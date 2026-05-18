// `libp-test event <subcommand>` — KMES emit + ring-buffer consumer probes.

use std::thread;
use std::time::Duration;

use clap::Subcommand;
use libp_event::{EmitEntry, OwnedEvent, Ring};
use serde_json::json;

/// Event type tags. Each probe emits its own tag so a drain can pick its
/// events out of whatever else KMES is carrying.
const PROBE_TYPE: &str = "libp-test.probe";
const BATCH_TYPE: &str = "libp-test.batch";
const BLOCKING_TYPE: &str = "libp-test.blocking";

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Attach to every per-CPU ring buffer; report the CPU count and the
    /// shared per-buffer capacity.
    Attach,

    /// Emit one event carrying `nonce`, then drain every ring buffer and
    /// report whether the event was found again.
    EmitRead {
        #[arg(long)]
        nonce: u64,
    },

    /// Emit a batch of `count` events (all carrying `nonce`), then drain
    /// every ring buffer and count how many are visible.
    EmitBatch {
        #[arg(long)]
        nonce: u64,
        #[arg(long, default_value_t = 8)]
        count: u32,
    },

    /// Pin to CPU 0, drain its ring empty, then block in `read()` on the
    /// futex while a delayed background thread emits one event — exercises
    /// the notification-wait path.
    BlockingRead {
        #[arg(long)]
        nonce: u64,
    },
}

pub fn run(cmd: Cmd) {
    let out = match cmd {
        Cmd::Attach => attach(),
        Cmd::EmitRead { nonce } => emit_read(nonce),
        Cmd::EmitBatch { nonce, count } => emit_batch(nonce, count),
        Cmd::BlockingRead { nonce } => blocking_read(nonce),
    };
    println!("{}", serde_json::to_string(&out).unwrap());
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

/// Encode `n` as a msgpack `uint 64` (`0xcf` + 8 big-endian bytes). The
/// KMES syscall path rejects a payload that is not valid msgpack.
fn msgpack_u64(n: u64) -> [u8; 9] {
    let mut buf = [0u8; 9];
    buf[0] = 0xcf;
    buf[1..].copy_from_slice(&n.to_be_bytes());
    buf
}

/// Decode a payload produced by [`msgpack_u64`], if it has that shape.
fn decode_msgpack_u64(payload: &[u8]) -> Option<u64> {
    if payload.len() == 9 && payload[0] == 0xcf {
        Some(u64::from_be_bytes(payload[1..9].try_into().unwrap()))
    } else {
        None
    }
}

fn err(e: libp_event::Error) -> serde_json::Value {
    let errno = match &e {
        libp_event::Error::Syscall(n) | libp_event::Error::Map(n) => {
            Some(json!({ "name": n.name(), "raw": n.raw() }))
        }
        libp_event::Error::PartialBatch { errno, .. } => {
            Some(json!({ "name": errno.name(), "raw": errno.raw() }))
        }
        _ => None,
    };
    json!({ "ok": false, "error": e.to_string(), "errno": errno })
}

fn event_json(ev: &OwnedEvent) -> serde_json::Value {
    json!({
        "sequence": ev.sequence,
        "cpu_id": ev.cpu_id,
        "origin": peios_uapi::kmes::origin_name(ev.origin),
        "event_type": ev.event_type_str().unwrap_or("<non-utf8>"),
        "timestamp_ns": ev.timestamp_ns,
        "payload_nonce": decode_msgpack_u64(&ev.payload),
    })
}

/// Drain every ring buffer fully, returning every event as an owned copy.
fn drain_all(rings: &mut [Ring]) -> Result<Vec<OwnedEvent>, libp_event::Error> {
    let mut events = Vec::new();
    for ring in rings.iter_mut() {
        loop {
            match ring.next() {
                Ok(Some(ev)) => events.push(OwnedEvent::from(&ev)),
                Ok(None) => break,
                // A resize froze this buffer; stop draining it.
                Err(libp_event::Error::GenerationChanged) => break,
                Err(e) => return Err(e),
            }
        }
    }
    Ok(events)
}

/// Pin the calling thread (and threads it later spawns) to CPU 0, so that
/// `kmes_emit` and CPU 0's ring buffer agree.
fn pin_cpu0() {
    const SYS_SCHED_SETAFFINITY: i64 = 203;
    let mask: u64 = 1; // bit 0 → CPU 0
    unsafe {
        peios_uapi::sys::syscall3(
            SYS_SCHED_SETAFFINITY,
            0,
            core::mem::size_of::<u64>() as u64,
            &mask as *const u64 as u64,
        );
    }
}

// ---------------------------------------------------------------------------
// Subcommands.
// ---------------------------------------------------------------------------

fn attach() -> serde_json::Value {
    match Ring::attach_all() {
        Ok(rings) => json!({
            "ok": true,
            "cpu_count": rings.len(),
            "capacity": rings.first().map(Ring::capacity).unwrap_or(0),
        }),
        Err(e) => err(e),
    }
}

fn emit_read(nonce: u64) -> serde_json::Value {
    if let Err(e) = libp_event::emit(PROBE_TYPE, &msgpack_u64(nonce)) {
        return err(e);
    }
    let mut rings = match Ring::attach_all() {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    let events = match drain_all(&mut rings) {
        Ok(ev) => ev,
        Err(e) => return err(e),
    };
    match events.iter().find(|ev| {
        ev.event_type_str() == Some(PROBE_TYPE) && decode_msgpack_u64(&ev.payload) == Some(nonce)
    }) {
        Some(ev) => json!({ "ok": true, "found": true, "event": event_json(ev) }),
        None => json!({ "ok": true, "found": false, "drained": events.len() }),
    }
}

fn emit_batch(nonce: u64, count: u32) -> serde_json::Value {
    let payload = msgpack_u64(nonce);
    let entries: Vec<EmitEntry> = (0..count)
        .map(|_| EmitEntry::new(BATCH_TYPE, &payload))
        .collect();
    if let Err(e) = libp_event::emit_batch(&entries) {
        return err(e);
    }
    let mut rings = match Ring::attach_all() {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    let events = match drain_all(&mut rings) {
        Ok(ev) => ev,
        Err(e) => return err(e),
    };
    let found = events
        .iter()
        .filter(|ev| {
            ev.event_type_str() == Some(BATCH_TYPE)
                && decode_msgpack_u64(&ev.payload) == Some(nonce)
        })
        .count();
    json!({ "ok": true, "requested": count, "found": found })
}

fn blocking_read(nonce: u64) -> serde_json::Value {
    pin_cpu0();
    let mut rings = match Ring::attach_all() {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    if rings.is_empty() {
        return json!({ "ok": false, "error": "no ring buffers attached" });
    }
    // CPU 0's ring (attach returns fds in CPU order); drop the rest.
    let mut ring = rings.swap_remove(0);
    drop(rings);

    // Drain whatever is already buffered so the next read genuinely
    // blocks on the futex rather than returning a stale event.
    loop {
        match ring.next() {
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(e) => return err(e),
        }
    }

    // A background thread emits after a delay, while the main thread is
    // parked in the notification wait.
    let emitter = thread::spawn(move || {
        thread::sleep(Duration::from_millis(150));
        libp_event::emit(BLOCKING_TYPE, &msgpack_u64(nonce))
    });

    // Block for our event. Bounded so a test can never hang outright.
    let mut found: Option<OwnedEvent> = None;
    for _ in 0..40 {
        match ring.read_timeout(Duration::from_millis(500)) {
            Ok(Some(ev)) => {
                if ev.event_type_str() == Some(BLOCKING_TYPE)
                    && decode_msgpack_u64(&ev.payload) == Some(nonce)
                {
                    found = Some(ev);
                    break;
                }
            }
            Ok(None) => {}
            Err(e) => return err(e),
        }
    }

    if let Err(e) = emitter.join().unwrap() {
        return err(e);
    }
    match found {
        Some(ev) => json!({
            "ok": true,
            "found": true,
            "cpu_id": ring.cpu_id(),
            "event": event_json(&ev),
        }),
        None => json!({ "ok": true, "found": false }),
    }
}
