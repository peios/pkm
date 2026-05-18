// `Ring` — a per-CPU KMES ring buffer consumer.
//
// Implements the PSD-003 v0.20 §5.1 read protocol over the mmap'd,
// double-mapped ring buffer: a lock-free, syscall-free drain loop with
// futex-based notification when the buffer is empty.
//
// All shared-memory access goes through `read_volatile` / `write_volatile`.
// peios-uapi is x86_64-only (see the `compile_error!` in `sys.rs`), and on
// x86_64 every aligned load is acquire-ordered and every store is
// release-ordered at the hardware level — the volatile qualifier is what
// stops the *compiler* from eliding or reordering these accesses. This
// matches PSD-003 §5.1's memory-ordering table, which notes the release
// barriers are no-ops on x86-64.

use alloc::vec;
use alloc::vec::Vec;
use core::time::Duration;

use peios_uapi::Errno;
use peios_uapi::errno;
use peios_uapi::kmes::{self, HDR_BASE};
use peios_uapi::sys;

use crate::Result;
use crate::error::Error;
use crate::event::{Event, OwnedEvent};
use crate::raw;

/// Ring buffer format version this crate understands (PSD-003 §8: v0.20
/// uses version 1).
const RING_VERSION: u32 = 1;

/// A consumer attached to one per-CPU KMES ring buffer.
///
/// Obtain a `Ring` per CPU from [`Ring::attach_all`]. Drain it with
/// [`next`](Ring::next) (non-blocking, zero-copy) or [`read`](Ring::read)
/// (blocking, owned). A `Ring` owns its file descriptor and mapping, both
/// released on drop.
pub struct Ring {
    fd: i32,
    base: *mut u8,
    map_len: usize,
    capacity: u64,
    cpu_id: u16,
    /// Generation observed when the ring was mapped. A mismatch means the
    /// buffer was resized and the caller must re-attach.
    generation: u64,
    /// Monotonic byte offset of the next event to read.
    read_pos: u64,
    /// `event_size` of the event last yielded by `next` but not yet
    /// stepped over; consumed at the start of the following `next`.
    pending_advance: u64,
    /// Sequence number of the last event yielded; 0 = none yet.
    last_sequence: u64,
    /// Running count of events lost to overwrite/drop, inferred from gaps
    /// in the per-CPU sequence number.
    lost_events: u64,
}

// A `Ring` is a plain owner of an fd + mapping. The mapping is process-
// global memory and KMES wakes consumers regardless of thread, so a `Ring`
// is safe to move between threads. It is not `Sync`: `next` mutates the
// read cursor through `&mut self`.
unsafe impl Send for Ring {}

impl Ring {
    /// Attach to every per-CPU KMES ring buffer.
    ///
    /// Returns one [`Ring`] per CPU, in CPU order (`rings[0]` is CPU 0).
    /// The caller's effective token must hold `SeSecurityPrivilege`.
    pub fn attach_all() -> Result<Vec<Ring>> {
        // Probe: a zero-slot call reports the CPU count via ERANGE.
        let mut probe_fd: i32 = 0;
        let mut count: i32 = 0;
        let mut capacity: u64 = 0;
        let rc = unsafe { raw::attach(&mut probe_fd, &mut count, &mut capacity) };
        if rc < 0 {
            let e = Errno::from_raw(rc);
            if e.raw() != errno::ERANGE {
                return Err(Error::Syscall(e));
            }
        }
        if count <= 0 {
            return Err(Error::Syscall(Errno::new(errno::EINVAL)));
        }
        let n = count as usize;

        // Real call: one fd per CPU.
        let mut fds: Vec<i32> = vec![0i32; n];
        let mut count: i32 = n as i32;
        let mut capacity: u64 = 0;
        let rc = unsafe { raw::attach(fds.as_mut_ptr(), &mut count, &mut capacity) };
        if rc < 0 {
            return Err(Error::Syscall(Errno::from_raw(rc)));
        }
        let actual = (count as usize).min(n);

        let mut rings: Vec<Ring> = Vec::with_capacity(actual);
        for i in 0..actual {
            let fd = fds[i];
            match Ring::map(fd, capacity) {
                Ok(ring) => rings.push(ring),
                Err(e) => {
                    // Already-mapped rings drop (unmap + close) themselves;
                    // close the descriptors we never mapped.
                    for &leftover in &fds[i..actual] {
                        unsafe { sys::close(leftover) };
                    }
                    return Err(e);
                }
            }
        }
        Ok(rings)
    }

    /// `mmap` one ring buffer fd and validate its producer metadata page.
    fn map(fd: i32, capacity: u64) -> Result<Ring> {
        let map_len = kmes::ring_mapping_size(capacity);
        let rc = unsafe {
            sys::mmap(
                core::ptr::null_mut(),
                map_len,
                sys::PROT_READ | sys::PROT_WRITE,
                sys::MAP_SHARED,
                fd,
                0,
            )
        };
        if rc < 0 {
            unsafe { sys::close(fd) };
            return Err(Error::Map(Errno::from_raw(rc)));
        }
        let base = rc as *mut u8;

        let mut magic = [0u8; 8];
        unsafe {
            core::ptr::copy_nonoverlapping(base.add(kmes::P_MAGIC), magic.as_mut_ptr(), 8);
        }
        if magic != kmes::RING_MAGIC {
            unsafe {
                sys::munmap(base, map_len);
                sys::close(fd);
            }
            return Err(Error::BadMagic);
        }

        let version = unsafe { (base.add(kmes::P_VERSION) as *const u32).read_volatile() };
        if version != RING_VERSION {
            unsafe {
                sys::munmap(base, map_len);
                sys::close(fd);
            }
            return Err(Error::Version {
                found: version,
                expected: RING_VERSION,
            });
        }

        let cpu_id = unsafe { (base.add(kmes::P_CPU_ID) as *const u16).read_volatile() };
        let generation = unsafe { (base.add(kmes::P_GENERATION) as *const u64).read_volatile() };
        let tail = unsafe { (base.add(kmes::P_TAIL_POS) as *const u64).read_volatile() };

        Ok(Ring {
            fd,
            base,
            map_len,
            capacity,
            cpu_id,
            generation,
            // Start at the oldest surviving event (PSD-003 §5.1).
            read_pos: tail,
            pending_advance: 0,
            last_sequence: 0,
            lost_events: 0,
        })
    }

    /// CPU this ring buffer belongs to.
    pub fn cpu_id(&self) -> u16 {
        self.cpu_id
    }

    /// Data-region capacity in bytes (a power of two).
    pub fn capacity(&self) -> u64 {
        self.capacity
    }

    /// Buffer generation observed when this ring was attached.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Sequence number of the most recent event yielded (0 = none yet).
    pub fn last_sequence(&self) -> u64 {
        self.last_sequence
    }

    /// Running count of events lost to ring-buffer overwrite or size-limit
    /// drops, inferred from gaps in the per-CPU sequence number.
    pub fn lost_events(&self) -> u64 {
        self.lost_events
    }

    // --- producer/consumer metadata access ---------------------------------

    #[inline]
    fn data(&self) -> *const u8 {
        unsafe { self.base.add(kmes::METADATA_TOTAL_SIZE) }
    }

    #[inline]
    fn write_pos(&self) -> u64 {
        unsafe { (self.base.add(kmes::P_WRITE_POS) as *const u64).read_volatile() }
    }

    #[inline]
    fn tail_pos(&self) -> u64 {
        unsafe { (self.base.add(kmes::P_TAIL_POS) as *const u64).read_volatile() }
    }

    #[inline]
    fn generation_now(&self) -> u64 {
        unsafe { (self.base.add(kmes::P_GENERATION) as *const u64).read_volatile() }
    }

    #[inline]
    fn futex_counter(&self) -> u32 {
        unsafe { (self.base.add(kmes::P_FUTEX_COUNTER) as *const u32).read_volatile() }
    }

    #[inline]
    fn set_need_wake(&self) {
        unsafe {
            self.base.add(kmes::METADATA_PAGE_SIZE).write_volatile(1u8);
        }
        // Keep the write_pos re-check below from being hoisted above the
        // need_wake store (PSD-003 §5.1 notification-wait step 2).
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }

    #[inline]
    fn clear_need_wake(&self) {
        unsafe {
            self.base.add(kmes::METADATA_PAGE_SIZE).write_volatile(0u8);
        }
    }

    /// Drain one event without blocking.
    ///
    /// Returns `Ok(Some(event))` for the next event, `Ok(None)` if the
    /// buffer is currently empty, or `Err(Error::GenerationChanged)` once a
    /// drained buffer has been resized.
    ///
    /// The returned [`Event`] borrows the ring's mapped memory; the borrow
    /// is tied to `&mut self`, so the read cursor cannot advance while it
    /// is held. To keep the event longer — in particular to move it to
    /// another thread — copy it with [`OwnedEvent::from`]. A consumer that
    /// processes the event in place for longer than it takes KMES to lap
    /// the buffer should likewise copy first.
    //
    // Not an `Iterator`: the yielded item borrows `&mut self` (a lending
    // iterator), which `Iterator`'s associated-type `Item` cannot express.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<Event<'_>>> {
        // Step over the event yielded by the previous call.
        if self.pending_advance != 0 {
            self.read_pos += self.pending_advance;
            self.pending_advance = 0;
        }

        let mask = self.capacity - 1;
        loop {
            let write_pos = self.write_pos();
            if self.read_pos >= write_pos {
                // Buffer drained — only now is it safe to act on a resize.
                if self.generation_now() != self.generation {
                    return Err(Error::GenerationChanged);
                }
                return Ok(None);
            }

            let saved_tail = self.tail_pos();
            if self.read_pos < saved_tail {
                // Lapped: events at the read cursor were overwritten.
                self.read_pos = saved_tail;
                continue;
            }

            let off = (self.read_pos & mask) as usize;
            // The double mapping guarantees `[off, off + capacity)` is a
            // contiguous, mapped byte range, so a capacity-sized window
            // always covers a whole event regardless of wrap.
            let window = self.capacity as usize;
            let parsed = {
                let bytes = unsafe { core::slice::from_raw_parts(self.data().add(off), window) };
                Event::parse(bytes)
            };

            // Torn-read check (PSD-003 §5.1 step 5): did the tail advance
            // past us while we were reading the event?
            let tail_after = self.tail_pos();
            if tail_after > saved_tail && self.read_pos < tail_after {
                continue;
            }

            // Lift every field into owned scalars so the parse borrow ends
            // here and `self` is free to mutate below.
            let (event_size, header_size, timestamp_ns, sequence, cpu_id, origin, type_len) =
                match parsed {
                    Ok(h) => (
                        h.event_size,
                        h.header_size,
                        h.timestamp_ns,
                        h.sequence,
                        h.cpu_id,
                        h.origin,
                        h.event_type.len(),
                    ),
                    Err(pe) => {
                        // Not torn (checked above) yet unparseable — the
                        // event is corrupt. Skip to the oldest surviving
                        // event; if the cursor cannot advance, surface it
                        // rather than spin.
                        let tail = self.tail_pos();
                        if tail > self.read_pos {
                            self.read_pos = tail;
                            continue;
                        }
                        return Err(Error::Parse(pe));
                    }
                };

            // Gap detection: a jump in the per-CPU sequence number counts
            // overwritten or dropped events.
            if self.last_sequence != 0 && sequence > self.last_sequence + 1 {
                self.lost_events += sequence - self.last_sequence - 1;
            }
            self.last_sequence = sequence;
            self.pending_advance = event_size as u64;

            // Reconstruct the event view over a slice bounded to exactly
            // this event, with the lifetime of the `&mut self` borrow.
            let bytes =
                unsafe { core::slice::from_raw_parts(self.data().add(off), event_size as usize) };
            return Ok(Some(Event {
                event_size,
                header_size,
                timestamp_ns,
                sequence,
                cpu_id,
                origin,
                event_type: &bytes[HDR_BASE..HDR_BASE + type_len],
                payload: &bytes[header_size as usize..event_size as usize],
            }));
        }
    }

    /// Block until an event is available, then return it copied out.
    ///
    /// Uses the PSD-003 §5.1 futex notification wait. A signal arriving
    /// during the wait is treated as cancellation — `read` does *not*
    /// retry `EINTR`, returning [`Error::Interrupted`] so the caller
    /// decides whether to resume.
    ///
    /// Returns an [`OwnedEvent`]: a blocking reader is no longer in a
    /// tight drain loop, and an owned copy frees it from the cursor
    /// borrow that [`next`](Ring::next) imposes.
    pub fn read(&mut self) -> Result<OwnedEvent> {
        loop {
            if let Some(event) = self.next()? {
                return Ok(OwnedEvent::from(&event));
            }
            self.wait(None)?;
        }
    }

    /// Block for up to `timeout` waiting for an event, then return it
    /// copied out, or `Ok(None)` if none arrived.
    ///
    /// May return `Ok(None)` before the full `timeout` elapses on a
    /// spurious futex wake; a caller that wants to keep waiting should
    /// call again. As with [`read`](Ring::read), a signal surfaces as
    /// [`Error::Interrupted`] rather than being retried.
    pub fn read_timeout(&mut self, timeout: Duration) -> Result<Option<OwnedEvent>> {
        if let Some(event) = self.next()? {
            return Ok(Some(OwnedEvent::from(&event)));
        }
        self.wait(Some(timeout))?;
        if let Some(event) = self.next()? {
            Ok(Some(OwnedEvent::from(&event)))
        } else {
            Ok(None)
        }
    }

    /// PSD-003 §5.1 notification wait: arm `need_wake`, re-check for a
    /// late write, then sleep on the futex counter.
    fn wait(&self, timeout: Option<Duration>) -> Result<()> {
        self.set_need_wake();
        // An event may have landed between the empty drain and the
        // need_wake store; if so, do not sleep.
        if self.write_pos() != self.read_pos {
            self.clear_need_wake();
            return Ok(());
        }
        let counter = self.futex_counter();
        let ts = timeout.map(duration_to_timespec);
        let ts_ptr = ts.as_ref().map_or(core::ptr::null(), core::ptr::from_ref);
        let rc = unsafe {
            sys::futex_wait(
                self.base.add(kmes::P_FUTEX_COUNTER) as *const u32,
                counter,
                ts_ptr,
            )
        };
        self.clear_need_wake();
        if rc == 0 {
            return Ok(());
        }
        let e = Errno::from_raw(rc);
        match e.raw() {
            // EAGAIN: the counter already moved (an event arrived).
            // ETIMEDOUT: the deadline elapsed. Both mean "go re-drain".
            errno::EAGAIN | errno::ETIMEDOUT => Ok(()),
            errno::EINTR => Err(Error::Interrupted),
            _ => Err(Error::Syscall(e)),
        }
    }
}

impl Drop for Ring {
    fn drop(&mut self) {
        unsafe {
            sys::munmap(self.base, self.map_len);
            sys::close(self.fd);
        }
    }
}

fn duration_to_timespec(d: Duration) -> sys::Timespec {
    sys::Timespec {
        tv_sec: d.as_secs() as i64,
        tv_nsec: d.subsec_nanos() as i64,
    }
}
