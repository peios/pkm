//! NTFE's device for userspace: `/dev/peios-ntfe`, ABI 5.
//!
//! The Network Traffic Filtering Engine judges every traversal against the
//! PNP packet layers. Its device is how a program sees what it is doing:
//!
//! - the engine's [`Status`]: the generation in force, whether a write has
//!   been walked yet ([`Status::in_force_after`]), and every confession
//!   counter;
//! - the verdict stream ([`Device::events`]): one [`Event`] per evaluation,
//!   with the rule that decided and who stood at each end. The stream has
//!   one reader at a time; another gets `EBUSY`;
//! - three dumps, each a best-effort snapshot of a table that changes
//!   under the walk: the counter cells ([`Device::counters`]), the live
//!   flows with their cached sentences ([`Device::flows`]), and the
//!   sockets prepared to receive ([`Device::listeners`]).
//!
//! The records are the generated ones in `peios-uapi`, laid out as
//! `uapi/pkm/ntfe.h` declares them; this crate checks the ABI word and
//! decodes them into owned values. The layouts are documented in the
//! kernel TRM's NTFE ABI appendix. The device is mode 0600: reading it
//! takes the authority to open it.

use std::fs::File;
use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::AsRawFd;

use peios_uapi as uapi;

/// Where the device is.
pub const DEVICE: &str = "/dev/peios-ntfe";
/// The ABI this crate decodes.
pub const ABI: u64 = uapi::PEIOS_NTFE_ABI_VERSION as u64;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    /// The engine speaks another ABI: nothing it says can be decoded.
    Abi {
        engine: u64,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "{DEVICE}: {e}"),
            Error::Abi { engine } => write!(
                f,
                "{DEVICE}: the engine speaks ABI {engine}, this reader {ABI}"
            ),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// The FNV-1a-64 hash NTFE identifies a rule path by in a flow's sentence:
/// the path relative to its layer key, `/`-separated (`ssh/too-fast`).
pub fn rule_hash(path: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in path.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// A rules layer the engine judges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    Packet,
    RawPacket,
    Flow,
}

impl Layer {
    fn from_raw(v: u8) -> Option<Layer> {
        match u32::from(v) {
            uapi::PEIOS_NTFE_EV_LAYER_PACKET => Some(Layer::Packet),
            uapi::PEIOS_NTFE_EV_LAYER_RAWPACKET => Some(Layer::RawPacket),
            uapi::PEIOS_NTFE_EV_LAYER_FLOW => Some(Layer::Flow),
            _ => None,
        }
    }
}

/// What a REJECT told the sender.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectKind {
    /// Nothing is listening: a reset, or port unreachable.
    Refused,
    /// Policy refused: administratively prohibited.
    Prohibited,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    Reject(RejectKind),
    Drop,
}

impl Verdict {
    fn from_raw(verdict: u8, kind: u8) -> Option<Verdict> {
        match u32::from(verdict) {
            uapi::PEIOS_NTFE_EV_VERDICT_PASS => Some(Verdict::Pass),
            uapi::PEIOS_NTFE_EV_VERDICT_DROP => Some(Verdict::Drop),
            uapi::PEIOS_NTFE_EV_VERDICT_REJECT => Some(Verdict::Reject(
                if u32::from(kind) == uapi::PEIOS_NTFE_EV_REJECT_PROHIBITED {
                    RejectKind::Prohibited
                } else {
                    RejectKind::Refused
                },
            )),
            _ => None,
        }
    }
}

/// Which way a traversal, or a flow's originator, went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    In,
    Out,
}

impl Direction {
    fn from_raw(v: u8) -> Direction {
        if u32::from(v) == uapi::PEIOS_NTFE_EV_DIR_OUT {
            Direction::Out
        } else {
            Direction::In
        }
    }
}

/// Which standing seat judged a traversal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Seat {
    Ingress,
    Egress,
    LocalIn,
    LocalOut,
    Other(u8),
}

impl Seat {
    fn from_raw(v: u8) -> Seat {
        match u32::from(v) {
            uapi::PEIOS_NTFE_EV_SEAT_INGRESS => Seat::Ingress,
            uapi::PEIOS_NTFE_EV_SEAT_EGRESS => Seat::Egress,
            uapi::PEIOS_NTFE_EV_SEAT_LOCAL_IN => Seat::LocalIn,
            uapi::PEIOS_NTFE_EV_SEAT_LOCAL_OUT => Seat::LocalOut,
            _ => Seat::Other(v),
        }
    }
}

/// Connection tracking's view of a packet, as its snapshot carried it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowState {
    New,
    Established,
    Related,
    Invalid,
    Untracked,
}

impl FlowState {
    fn from_raw(v: u8) -> Option<FlowState> {
        match u32::from(v) {
            uapi::PEIOS_NTFE_EV_FLOW_NEW => Some(FlowState::New),
            uapi::PEIOS_NTFE_EV_FLOW_ESTABLISHED => Some(FlowState::Established),
            uapi::PEIOS_NTFE_EV_FLOW_RELATED => Some(FlowState::Related),
            uapi::PEIOS_NTFE_EV_FLOW_INVALID => Some(FlowState::Invalid),
            uapi::PEIOS_NTFE_EV_FLOW_UNTRACKED => Some(FlowState::Untracked),
            _ => None,
        }
    }
}

/// What stood at one end of a flow: the `Local` and `Remote` facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointKind {
    /// Not known: not a Flow-layer record, or not yet resolved.
    Absent,
    /// A program's socket.
    Program,
    /// The stack itself.
    Kernel,
    /// Inbound multicast or broadcast, to every socket on the port.
    Shared,
    /// Nothing receives it.
    None,
}

impl EndpointKind {
    fn from_raw(v: u8) -> EndpointKind {
        match u32::from(v) {
            uapi::PEIOS_NTFE_EV_LOCAL_PROGRAM => EndpointKind::Program,
            uapi::PEIOS_NTFE_EV_LOCAL_KERNEL => EndpointKind::Kernel,
            uapi::PEIOS_NTFE_EV_LOCAL_SHARED => EndpointKind::Shared,
            uapi::PEIOS_NTFE_EV_LOCAL_NONE => EndpointKind::None,
            _ => EndpointKind::Absent,
        }
    }
}

/// Who stood at one end, for a program: the identity the kernel stamped on
/// its socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub kind: EndpointKind,
    /// The endpoint could not be attributed when it was resolved.
    pub unresolved: bool,
    pub pid: i32,
    /// The process GUID, as its 16 bytes.
    pub guid: [u8; 16],
    pub comm: String,
    /// The token's user SID, binary, when there is one.
    pub user: Option<Vec<u8>>,
    /// The per-service SID, binary, for a service.
    pub service: Option<Vec<u8>>,
}

/// A self-sized binary SID out of a fixed field: `None` when the field is
/// all zero (absent), else its 8 + 4 × count bytes.
fn sid(field: &[u8]) -> Option<Vec<u8>> {
    if field.first().copied().unwrap_or(0) == 0 {
        return None;
    }
    let len = (8 + 4 * usize::from(*field.get(1)?)).min(field.len());
    Some(field[..len].to_vec())
}

fn text(field: &[u8]) -> String {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).into_owned()
}

fn addr(family: u8, bytes: &[u8; 16]) -> Option<IpAddr> {
    match family {
        4 => Some(IpAddr::V4(Ipv4Addr::new(
            bytes[0], bytes[1], bytes[2], bytes[3],
        ))),
        6 => Some(IpAddr::V6(Ipv6Addr::from(*bytes))),
        _ => None,
    }
}

/// An address in a field that is all zero when it is "any".
fn bound(family: u8, bytes: &[u8; 16]) -> Option<IpAddr> {
    if bytes.iter().all(|&b| b == 0) {
        None
    } else {
        addr(family, bytes)
    }
}

fn guid(field: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(&field[..16]);
    out
}

/// The engine's status. Counters are cumulative since boot.
#[derive(Debug, Clone, Copy)]
pub struct Status(pub uapi::peios_ntfe_status);

impl Status {
    /// The policy generation in force; 0 when nothing was ever ingested.
    pub fn generation(&self) -> u64 {
        self.0.generation
    }

    /// Whether any layer has a published forest.
    pub fn enforcing(&self) -> bool {
        self.0.enforcing != 0
    }

    /// Why the last re-walk of the registry was refused, as an errno, while
    /// the previous generation stands; `None` when it was not.
    pub fn refusal(&self) -> Option<i32> {
        (self.0.last_ingest_error != 0).then_some(self.0.last_ingest_error as i32)
    }

    /// Whether every change noted when `noted` was read has been walked:
    /// read [`Status::changes_noted`] after a write, then wait for this.
    /// A walk that was refused counts as walked: see [`Status::refusal`].
    pub fn in_force_after(&self, noted: u64) -> bool {
        self.0.changes_walked >= noted
    }

    pub fn changes_noted(&self) -> u64 {
        self.0.changes_noted
    }

    /// Changes noted and not yet walked.
    pub fn pending(&self) -> u64 {
        self.0.changes_noted.saturating_sub(self.0.changes_walked)
    }

    /// The `CurrentReportingLevel` the engine applies.
    pub fn reporting_level(&self) -> u64 {
        self.0.reporting_level
    }
}

/// The side effects an evaluation yielded, counted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Effects {
    pub tags: u8,
    pub counts: u8,
    pub reports: u8,
    pub prompts: u8,
}

/// One evaluation, from the verdict stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// Monotonic; a gap is events the ring dropped, and confessed.
    pub seq: u64,
    /// When, as CLOCK_REALTIME nanoseconds.
    pub time_ns: u64,
    pub seat: Seat,
    pub layer: Option<Layer>,
    pub verdict: Option<Verdict>,
    pub direction: Direction,
    /// Nothing yielded: the layer's backstop dropped it.
    pub backstop: bool,
    /// Evaluation failed, and it was dropped.
    pub fail_closed: bool,
    /// A REJECT was sent as a DROP, having no way to say it.
    pub reject_degraded: bool,
    /// A stale sentence was judged again.
    pub rejudged: bool,
    pub protocol: u8,
    pub flow_state: Option<FlowState>,
    pub ifindex: u32,
    pub src: Option<IpAddr>,
    pub dst: Option<IpAddr>,
    /// 0 when the fact was absent.
    pub src_port: u16,
    pub dst_port: u16,
    pub ether_type: u16,
    pub length: u32,
    pub effects: Effects,
    /// The deciding rule's path in its layer, or `backstop`.
    pub attributed: String,
    pub local: Endpoint,
    pub remote: Endpoint,
}

impl Event {
    pub fn decode(e: &uapi::peios_ntfe_event) -> Event {
        let endpoint = |kind: u8,
                        unresolved: u8,
                        pid: i32,
                        g: &[u8],
                        comm: &[u8],
                        user: &[u8],
                        service: &[u8]| Endpoint {
            kind: EndpointKind::from_raw(kind),
            unresolved: unresolved != 0,
            pid,
            guid: guid(g),
            comm: text(comm),
            user: sid(user),
            service: sid(service),
        };
        Event {
            seq: e.seq,
            time_ns: e.t_ns,
            seat: Seat::from_raw(e.seat),
            layer: Layer::from_raw(e.layer),
            verdict: Verdict::from_raw(e.verdict, e.reject_kind),
            direction: Direction::from_raw(e.direction),
            backstop: u32::from(e.flags) & uapi::PEIOS_NTFE_EV_F_BACKSTOP != 0,
            fail_closed: u32::from(e.flags) & uapi::PEIOS_NTFE_EV_F_FAIL_CLOSED != 0,
            reject_degraded: u32::from(e.flags) & uapi::PEIOS_NTFE_EV_F_REJECT_DEGRADED != 0,
            rejudged: u32::from(e.flags) & uapi::PEIOS_NTFE_EV_F_REJUDGED != 0,
            protocol: e.protocol,
            flow_state: FlowState::from_raw(e.flow_state),
            ifindex: e.ifindex,
            src: addr(e.addr_family, &e.src_addr),
            dst: addr(e.addr_family, &e.dst_addr),
            src_port: e.src_port,
            dst_port: e.dst_port,
            ether_type: e.ether_type,
            length: e.length,
            effects: Effects {
                tags: e.effects as u8,
                counts: (e.effects >> 8) as u8,
                reports: (e.effects >> 16) as u8,
                prompts: (e.effects >> 24) as u8,
            },
            attributed: text(&e.attributed),
            local: endpoint(
                e.local_kind,
                e.local_unresolved,
                e.local_pid,
                &e.local_guid,
                &e.local_comm,
                &e.local_user,
                &e.local_service,
            ),
            remote: endpoint(
                e.remote_kind,
                e.remote_unresolved,
                e.remote_pid,
                &e.remote_guid,
                &e.remote_comm,
                &e.remote_user,
                &e.remote_service,
            ),
        }
    }
}

/// Which facts partition a counter table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KeySpec {
    pub src_addr: bool,
    pub dst_addr: bool,
    pub interface: bool,
}

/// One counter cell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Counter {
    /// The stream a `COUNT` writes.
    pub name: String,
    pub hash: u64,
    pub keyspec: KeySpec,
    /// The cell's key: only the facts the key-spec names are present.
    pub interface: Option<i32>,
    pub src: Option<IpAddr>,
    pub dst: Option<IpAddr>,
    /// Since the cell was made.
    pub total: u64,
    /// CLOCK_REALTIME seconds of the last write.
    pub last_secs: u64,
    /// Each window the table answers, as (seconds, value).
    pub windows: Vec<(u32, u64)>,
}

impl Counter {
    pub fn decode(c: &uapi::peios_ntfe_counter_rec) -> Counter {
        let spec = u32::from(c.keyspec);
        let keyspec = KeySpec {
            src_addr: spec & uapi::PEIOS_NTFE_KEY_SRC_ADDR != 0,
            dst_addr: spec & uapi::PEIOS_NTFE_KEY_DST_ADDR != 0,
            interface: spec & uapi::PEIOS_NTFE_KEY_INTERFACE != 0,
        };
        let n = (c.n_windows as usize).min(c.window_secs.len());
        Counter {
            name: text(&c.name),
            hash: c.hash,
            keyspec,
            interface: keyspec.interface.then_some(c.ifindex),
            src: if keyspec.src_addr {
                addr(c.family, &c.src_addr)
            } else {
                None
            },
            dst: if keyspec.dst_addr {
                addr(c.family, &c.dst_addr)
            } else {
                None
            },
            total: c.total,
            last_secs: c.last_secs,
            windows: (0..n)
                .map(|i| (c.window_secs[i], c.window_value[i]))
                .collect(),
        }
    }
}

/// One cached Flow-layer judgment of a flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sentence {
    /// The generation that judged it: a newer one makes it stale.
    pub generation: u64,
    /// When a time condition it consulted next flips, as epoch seconds.
    pub expires_at: Option<i64>,
    /// [`rule_hash`] of the deciding rule's path.
    pub rule_hash: u64,
    pub verdict: Option<Verdict>,
}

/// One live flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flow {
    /// Connection tracking's id for it.
    pub id: u32,
    pub protocol: u8,
    /// The originator's side, once the Flow layer has judged it.
    pub direction: Option<Direction>,
    /// Both ends on this machine: two sentences.
    pub loopback: bool,
    pub seen_reply: bool,
    pub assured: bool,
    /// Expected by another flow.
    pub related: bool,
    /// The interface at its first judgment.
    pub ifindex: i32,
    /// Connection tracking's remaining lifetime for it.
    pub timeout_secs: u32,
    /// The original direction's tuple.
    pub src: Option<IpAddr>,
    pub dst: Option<IpAddr>,
    /// ICMP: the echo id.
    pub src_port: u16,
    pub dst_port: u16,
    pub icmp_type: u8,
    pub icmp_code: u8,
    /// CLOCK_REALTIME seconds it was made.
    pub start_secs: u64,
    /// Original direction, then reply.
    pub packets: [u64; 2],
    pub bytes: [u64; 2],
    /// Its sentence; a loopback flow's inbound end's too.
    pub sentences: Vec<Sentence>,
    /// Who stood at the end each sentence is for.
    pub owners: Vec<Endpoint>,
    /// Up to eight of its tags, as (name hash, value).
    pub tags: Vec<(u64, u64)>,
}

impl Flow {
    pub fn decode(f: &uapi::peios_ntfe_flow_rec) -> Flow {
        let slots = uapi::PEIOS_NTFE_FLOW_SENTENCES as usize;
        let sentences = (0..slots)
            .filter(|&s| f.sentence_generation[s] != 0)
            .map(|s| Sentence {
                generation: f.sentence_generation[s],
                expires_at: (f.sentence_expires_at[s] != 0).then_some(f.sentence_expires_at[s]),
                rule_hash: f.sentence_rule_hash[s],
                verdict: Verdict::from_raw(f.sentence_verdict[s], f.sentence_reject_kind[s]),
            })
            .collect();
        let owners = (0..slots)
            .filter(|&s| f.owner_kind[s] != 0)
            .map(|s| Endpoint {
                kind: EndpointKind::from_raw(f.owner_kind[s]),
                unresolved: f.owner_unresolved[s] != 0,
                pid: f.owner_pid[s],
                guid: guid(&f.owner_guid[s * 16..]),
                comm: text(&f.owner_comm[s * 16..s * 16 + 16]),
                user: sid(&f.owner_user[s * 68..s * 68 + 68]),
                service: sid(&f.owner_service[s * 32..s * 32 + 32]),
            })
            .collect();
        let tags = (0..usize::from(f.n_tags).min(f.tag_hash.len()))
            .map(|i| (f.tag_hash[i], f.tag_value[i]))
            .collect();
        Flow {
            id: f.id,
            protocol: f.protocol,
            direction: (f.judged != 0).then(|| Direction::from_raw(f.direction)),
            loopback: f.loopback != 0,
            seen_reply: f.seen_reply != 0,
            assured: f.assured != 0,
            related: f.related != 0,
            ifindex: f.ifindex,
            timeout_secs: f.timeout_secs,
            src: addr(f.family, &f.src_addr),
            dst: addr(f.family, &f.dst_addr),
            src_port: f.src_port,
            dst_port: f.dst_port,
            icmp_type: f.icmp_type,
            icmp_code: f.icmp_code,
            start_secs: f.start_secs,
            packets: f.packets,
            bytes: f.bytes,
            sentences,
            owners,
            tags,
        }
    }
}

/// One socket prepared to receive: a listening TCP socket, or a bound UDP
/// one, with who it belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listener {
    pub protocol: u8,
    pub port: u16,
    /// The local address it is bound to; `None` for any.
    pub addr: Option<IpAddr>,
    /// The interface it is bound to; `None` for any.
    pub ifindex: Option<i32>,
    pub reuseport: bool,
    /// UDP: it receives from one peer only.
    pub connected: bool,
    pub v6only: bool,
    pub owner: Endpoint,
}

impl Listener {
    pub fn decode(l: &uapi::peios_ntfe_listener_rec) -> Listener {
        Listener {
            protocol: l.protocol,
            port: l.port,
            addr: bound(l.family, &l.addr),
            ifindex: (l.ifindex != 0).then_some(l.ifindex),
            reuseport: l.reuseport != 0,
            connected: l.connected != 0,
            v6only: l.v6only != 0,
            owner: Endpoint {
                kind: EndpointKind::from_raw(l.owner_kind),
                unresolved: l.owner_unresolved != 0,
                pid: l.owner_pid,
                guid: l.owner_guid,
                comm: text(&l.owner_comm),
                user: sid(&l.owner_user),
                service: sid(&l.owner_service),
            },
        }
    }
}

/// A dump: as many records as fitted, and how many there were.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dump<T> {
    pub records: Vec<T>,
    /// How many the walk saw; more than `records` holds when the buffer
    /// was too small.
    pub total: u32,
}

/// The device, open.
#[derive(Debug)]
pub struct Device(File);

/// The queries' common shape: a user buffer, its length, and two counts out.
#[repr(C)]
#[derive(Default)]
struct Query {
    buf: u64,
    buf_len: u32,
    count: u32,
    total: u32,
    _pad0: u32,
}

// Every dump query is this one shape.
const _: () =
    assert!(std::mem::size_of::<Query>() == std::mem::size_of::<uapi::peios_ntfe_flows_query>());
const _: () =
    assert!(std::mem::size_of::<Query>() == std::mem::size_of::<uapi::peios_ntfe_counters_query>());
const _: () = assert!(
    std::mem::size_of::<Query>() == std::mem::size_of::<uapi::peios_ntfe_listeners_query>()
);

impl Device {
    /// Opens the device. It is mode 0600.
    pub fn open() -> Result<Device> {
        Ok(Device(File::open(DEVICE)?))
    }

    fn ioctl<T>(&self, request: u64, arg: *mut T) -> io::Result<()> {
        // SAFETY: `request` is one of the device's ioctl numbers, each of
        // which reads or writes exactly the record `arg` points to (and, for
        // a dump, the buffer that record names), all alive for the call.
        let rc = unsafe { libc::ioctl(self.0.as_raw_fd(), request as libc::c_ulong, arg) };
        if rc != 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// The engine's status, refused when it speaks another ABI.
    pub fn status(&self) -> Result<Status> {
        // SAFETY: the record is plain integers; all zero is a valid value.
        let mut raw: uapi::peios_ntfe_status = unsafe { std::mem::zeroed() };
        self.ioctl(uapi::PEIOS_NTFE_IOC_STATUS, &mut raw)?;
        if raw.abi != ABI {
            return Err(Error::Abi { engine: raw.abi });
        }
        Ok(Status(raw))
    }

    fn dump<T: Copy, U>(
        &self,
        request: u64,
        capacity: usize,
        decode: impl Fn(&T) -> U,
    ) -> Result<Dump<U>> {
        self.status()?;
        // SAFETY: each record is plain integers and byte arrays; all zero
        // is a valid value.
        let mut buf: Vec<T> = vec![unsafe { std::mem::zeroed() }; capacity];
        let mut query = Query {
            buf: buf.as_mut_ptr() as u64,
            buf_len: (capacity * std::mem::size_of::<T>()) as u32,
            ..Query::default()
        };
        self.ioctl(request, &mut query)?;
        let count = (query.count as usize).min(capacity);
        Ok(Dump {
            records: buf[..count].iter().map(decode).collect(),
            total: query.total,
        })
    }

    /// The counter cells, at most `capacity` of them.
    pub fn counters(&self, capacity: usize) -> Result<Dump<Counter>> {
        self.dump(uapi::PEIOS_NTFE_IOC_COUNTERS, capacity, Counter::decode)
    }

    /// The live flows, at most `capacity` of them.
    pub fn flows(&self, capacity: usize) -> Result<Dump<Flow>> {
        self.dump(uapi::PEIOS_NTFE_IOC_FLOWS, capacity, Flow::decode)
    }

    /// The sockets prepared to receive, at most `capacity` of them.
    pub fn listeners(&self, capacity: usize) -> Result<Dump<Listener>> {
        self.dump(uapi::PEIOS_NTFE_IOC_LISTENERS, capacity, Listener::decode)
    }

    /// Reads up to `max` events from the stream, blocking until there is
    /// one. The stream has one reader at a time: another gets `EBUSY`.
    pub fn events(&mut self, max: usize) -> Result<Vec<Event>> {
        let size = std::mem::size_of::<uapi::peios_ntfe_event>();
        let mut bytes = vec![0u8; size * max.max(1)];
        let n = self.0.read(&mut bytes)?;
        Ok(bytes[..n - n % size]
            .chunks_exact(size)
            .map(|chunk| {
                // SAFETY: the chunk is exactly one record's bytes, as the
                // device wrote it; read_unaligned copes with the Vec<u8>'s
                // alignment.
                let raw: uapi::peios_ntfe_event =
                    unsafe { std::ptr::read_unaligned(chunk.as_ptr().cast()) };
                Event::decode(&raw)
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{offset_of, size_of};

    /// The offsets the integration tests' decoders read at
    /// (peios-integration-tests/tests/helpers/ntfe.lua): a second, byte-exact
    /// reading of the same header.
    #[test]
    fn records_lie_where_the_other_decoder_reads_them() {
        use uapi::{
            peios_ntfe_counter_rec as C, peios_ntfe_event as E, peios_ntfe_flow_rec as F,
            peios_ntfe_listener_rec as L,
        };
        assert_eq!(
            (
                size_of::<E>(),
                size_of::<C>(),
                size_of::<F>(),
                size_of::<L>()
            ),
            (456, 232, 568, 168)
        );
        assert_eq!(size_of::<uapi::peios_ntfe_status>(), 46 * 8);
        assert_eq!(
            (
                offset_of!(E, src_addr),
                offset_of!(E, dst_addr),
                offset_of!(E, length),
                offset_of!(E, attributed)
            ),
            (36, 52, 68, 76)
        );
        assert_eq!(
            (
                offset_of!(E, local_kind),
                offset_of!(E, local_pid),
                offset_of!(E, local_guid),
                offset_of!(E, local_comm)
            ),
            (176, 180, 188, 220)
        );
        assert_eq!(
            (
                offset_of!(E, local_user),
                offset_of!(E, remote_user),
                offset_of!(E, local_service),
                offset_of!(E, remote_service)
            ),
            (252, 320, 388, 420)
        );
        assert_eq!(
            (
                offset_of!(C, hash),
                offset_of!(C, ifindex),
                offset_of!(C, src_addr),
                offset_of!(C, total),
                offset_of!(C, window_secs),
                offset_of!(C, window_value)
            ),
            (64, 76, 80, 112, 136, 168)
        );
        assert_eq!(
            (
                offset_of!(F, ifindex),
                offset_of!(F, src_addr),
                offset_of!(F, src_port),
                offset_of!(F, start_secs),
                offset_of!(F, packets),
                offset_of!(F, bytes)
            ),
            (12, 20, 52, 64, 72, 88)
        );
        assert_eq!(
            (
                offset_of!(F, sentence_generation),
                offset_of!(F, sentence_expires_at),
                offset_of!(F, sentence_rule_hash),
                offset_of!(F, sentence_verdict),
                offset_of!(F, sentence_reject_kind)
            ),
            (104, 120, 136, 152, 154)
        );
        assert_eq!(
            (
                offset_of!(F, tag_hash),
                offset_of!(F, tag_value),
                offset_of!(F, owner_kind),
                offset_of!(F, owner_pid),
                offset_of!(F, owner_guid)
            ),
            (160, 224, 288, 296, 304)
        );
        assert_eq!(
            (
                offset_of!(F, owner_comm),
                offset_of!(F, owner_user),
                offset_of!(F, owner_service)
            ),
            (336, 368, 504)
        );
        assert_eq!(
            (
                offset_of!(L, port),
                offset_of!(L, ifindex),
                offset_of!(L, addr),
                offset_of!(L, owner_pid),
                offset_of!(L, owner_guid)
            ),
            (8, 12, 16, 32, 36)
        );
        assert_eq!(
            (
                offset_of!(L, owner_comm),
                offset_of!(L, owner_user),
                offset_of!(L, owner_service)
            ),
            (52, 68, 136)
        );
    }

    #[test]
    fn a_rule_path_hashes_as_the_engine_hashes_it() {
        assert_eq!(rule_hash(""), 0xcbf2_9ce4_8422_2325);
        assert_ne!(rule_hash("ssh"), rule_hash("ssh/too-fast"));
    }

    #[test]
    fn an_event_decodes_its_verdict_and_who_was_there() {
        // SAFETY: plain integers and bytes; all zero is valid.
        let mut raw: uapi::peios_ntfe_event = unsafe { std::mem::zeroed() };
        raw.seq = 7;
        raw.layer = uapi::PEIOS_NTFE_EV_LAYER_FLOW as u8;
        raw.verdict = uapi::PEIOS_NTFE_EV_VERDICT_REJECT as u8;
        raw.reject_kind = uapi::PEIOS_NTFE_EV_REJECT_PROHIBITED as u8;
        raw.addr_family = 4;
        raw.src_addr[..4].copy_from_slice(&[203, 0, 113, 50]);
        raw.dst_port = 22;
        raw.effects = 1 << 16;
        raw.attributed[..12].copy_from_slice(b"ssh/too-fast");
        raw.local_kind = uapi::PEIOS_NTFE_EV_LOCAL_PROGRAM as u8;
        raw.local_comm[..4].copy_from_slice(b"sshd");
        raw.local_service[..2].copy_from_slice(&[1, 6]);
        let e = Event::decode(&raw);
        assert_eq!(e.layer, Some(Layer::Flow));
        assert_eq!(e.verdict, Some(Verdict::Reject(RejectKind::Prohibited)));
        assert_eq!(e.src, Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50))));
        assert_eq!(e.effects.reports, 1);
        assert_eq!(e.attributed, "ssh/too-fast");
        assert_eq!(
            (e.local.kind, e.local.comm.as_str()),
            (EndpointKind::Program, "sshd")
        );
        assert_eq!(e.local.service.map(|s| s.len()), Some(32));
        assert_eq!(e.remote.kind, EndpointKind::Absent);
    }

    #[test]
    fn a_counter_keeps_only_its_key_facts() {
        // SAFETY: plain integers and bytes; all zero is valid.
        let mut raw: uapi::peios_ntfe_counter_rec = unsafe { std::mem::zeroed() };
        raw.name[..9].copy_from_slice(b"ssh-tries");
        raw.keyspec = uapi::PEIOS_NTFE_KEY_SRC_ADDR as u8;
        raw.family = 4;
        raw.src_addr[..4].copy_from_slice(&[203, 0, 113, 50]);
        raw.dst_addr[..4].copy_from_slice(&[10, 0, 0, 1]);
        raw.n_windows = 1;
        raw.window_secs[0] = 60;
        raw.window_value[0] = 14;
        let c = Counter::decode(&raw);
        assert_eq!(c.name, "ssh-tries");
        assert!(c.src.is_some() && c.dst.is_none() && c.interface.is_none());
        assert_eq!(c.windows, vec![(60, 14)]);
    }

    #[test]
    fn a_flow_lists_only_its_filled_sentences_and_tags() {
        // SAFETY: plain integers and bytes; all zero is valid.
        let mut raw: uapi::peios_ntfe_flow_rec = unsafe { std::mem::zeroed() };
        raw.family = 4;
        raw.judged = 1;
        raw.direction = uapi::PEIOS_NTFE_EV_DIR_OUT as u8;
        raw.sentence_generation[0] = 42;
        raw.sentence_rule_hash[0] = rule_hash("outbound-ok");
        raw.n_tags = 1;
        raw.tag_hash[0] = 9;
        raw.tag_value[0] = 2;
        raw.owner_kind[0] = uapi::PEIOS_NTFE_EV_LOCAL_PROGRAM as u8;
        raw.owner_comm[..6].copy_from_slice(b"peipkg");
        let f = Flow::decode(&raw);
        assert_eq!(f.direction, Some(Direction::Out));
        assert_eq!(f.sentences.len(), 1);
        assert_eq!(f.sentences[0].verdict, Some(Verdict::Pass));
        assert_eq!(f.sentences[0].rule_hash, rule_hash("outbound-ok"));
        assert_eq!(f.tags, vec![(9, 2)]);
        assert_eq!(f.owners[0].comm, "peipkg");
    }
}
