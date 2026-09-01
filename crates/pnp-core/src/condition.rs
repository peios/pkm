//! Match conditions: the fact vocabulary, operators, and evaluation.
//!
//! A rule's match is a conjunction of conditions. Every condition is
//! evaluated against the immutable snapshot under the absent-fact law: a
//! condition over a fact the packet does not have is false.

use core::net::IpAddr;

use crate::hash::name_hash;
use crate::pkm_alloc::{String as PkmString, Vec as PkmVec};
use crate::snapshot::Snapshot;
use crate::strutil::str_to_pkm;

/// The packet-layer fact vocabulary (ratified, complete).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactId {
    /// Traversal direction (`in` / `out`).
    Direction,
    /// Interface name at the standing seat.
    Interface,
    /// Ethertype.
    EtherType,
    /// Source MAC address.
    SrcMac,
    /// Destination MAC address.
    DstMac,
    /// VLAN id.
    Vlan,
    /// Source IP address.
    SrcAddr,
    /// Destination IP address.
    DstAddr,
    /// IP protocol number.
    Protocol,
    /// TTL / hop limit.
    Ttl,
    /// DSCP field.
    Dscp,
    /// Fragment status.
    Fragment,
    /// L4 source port.
    SrcPort,
    /// L4 destination port.
    DstPort,
    /// TCP flags (`Has` / `Hasnt`).
    TcpFlags,
    /// ICMP type.
    IcmpType,
    /// ICMP code.
    IcmpCode,
    /// Packet length (stack view).
    Length,
    /// Conntrack flow classification.
    FlowState,
    /// Wall-clock year.
    TimeYear,
    /// Wall-clock month.
    TimeMonth,
    /// Wall-clock day of month.
    TimeDayOfMonth,
    /// ISO day of week (1 = Monday .. 7 = Sunday).
    TimeDayOfWeek,
    /// Wall-clock hour.
    TimeHour,
    /// Wall-clock minute.
    TimeMinute,
    /// Wall-clock second.
    TimeSecond,
}

impl FactId {
    /// Parses a fact name as written in rule value keys.
    pub fn from_key(name: &str) -> Option<FactId> {
        Some(match name {
            "Direction" => FactId::Direction,
            "Interface" => FactId::Interface,
            "EtherType" => FactId::EtherType,
            "SrcMac" => FactId::SrcMac,
            "DstMac" => FactId::DstMac,
            "Vlan" => FactId::Vlan,
            "SrcAddr" => FactId::SrcAddr,
            "DstAddr" => FactId::DstAddr,
            "Protocol" => FactId::Protocol,
            "Ttl" => FactId::Ttl,
            "Dscp" => FactId::Dscp,
            "Fragment" => FactId::Fragment,
            "SrcPort" => FactId::SrcPort,
            "DstPort" => FactId::DstPort,
            "TcpFlags" => FactId::TcpFlags,
            "IcmpType" => FactId::IcmpType,
            "IcmpCode" => FactId::IcmpCode,
            "Length" => FactId::Length,
            "FlowState" => FactId::FlowState,
            "Time.Year" => FactId::TimeYear,
            "Time.Month" => FactId::TimeMonth,
            "Time.DayOfMonth" => FactId::TimeDayOfMonth,
            "Time.DayOfWeek" => FactId::TimeDayOfWeek,
            "Time.Hour" => FactId::TimeHour,
            "Time.Minute" => FactId::TimeMinute,
            "Time.Second" => FactId::TimeSecond,
            _ => return None,
        })
    }

    /// The value family this fact compares in.
    pub fn family(self) -> FactFamily {
        match self {
            FactId::Direction | FactId::Interface | FactId::FlowState => FactFamily::Str,
            FactId::SrcAddr | FactId::DstAddr => FactFamily::Addr,
            FactId::SrcMac | FactId::DstMac => FactFamily::Mac,
            FactId::TcpFlags => FactFamily::Flags,
            _ => FactFamily::Int,
        }
    }
}

/// Value families: which operators and pattern shapes a fact supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactFamily {
    /// Integer-valued: `Equal` (scalars/ranges), `GreaterThan`, `LessThan`.
    Int,
    /// String-valued: `Equal` only.
    Str,
    /// IP addresses: `Equal` with exacts, ranges, and CIDR prefixes.
    Addr,
    /// MAC addresses: `Equal` with exacts.
    Mac,
    /// Flag sets: `Has` / `Hasnt`.
    Flags,
}

/// Counter key-spec bits: which facts partition a counter view. A packet
/// lacking any keyed fact has no cell (absent-fact law, both sides).
pub mod keyspec {
    /// Keyed by source address.
    pub const SRC_ADDR: u8 = 1 << 0;
    /// Keyed by destination address.
    pub const DST_ADDR: u8 = 1 << 1;
    /// Keyed by interface.
    pub const INTERFACE: u8 = 1 << 2;

    /// Parses one key-spec fact name.
    pub fn from_name(name: &str) -> Option<u8> {
        match name {
            "SrcAddr" => Some(SRC_ADDR),
            "DstAddr" => Some(DST_ADDR),
            "Interface" => Some(INTERFACE),
            _ => None,
        }
    }
}

/// Longest window a view may ask for (one day): per-key memory scales with
/// the number of windows a stream is viewed through, so the horizon is
/// bounded.
pub const MAX_WINDOW_SECS: u32 = 86_400;

/// A `Counter.<n>(...)` spec that does not parse as a view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BadView;

/// A compiled counter view: one way of slicing a stream. Every view the
/// forest mentions is materialized by the store at publication — windows
/// and key-specs are compile-time constants, so the hot path never sees
/// an arbitrary query.
#[derive(Debug, PartialEq, Eq)]
pub struct CounterView {
    /// Stream name.
    pub name: PkmString,
    /// `name_hash(name)`: the store's identity for the stream.
    pub hash: u64,
    /// Sliding window in seconds; 0 = the cumulative total.
    pub window_secs: u32,
    /// `keyspec::*` bits; 0 = one global cell.
    pub keyspec: u8,
}

impl CounterView {
    /// Parses the text after `Counter.`: `Name`, `Name(args)` where args
    /// are at most one duration (`10s`/`5m`/`2h`/`1d`) and at most one
    /// key-spec (`SrcAddr`, `DstAddr`, `Interface`, `+`-compounded), in
    /// any order. `Err(BadView)` for anything else (including a window over
    /// the horizon).
    pub fn parse(spec: &str) -> Result<CounterView, BadView> {
        let (name, args) = match spec.find('(') {
            Some(i) => {
                let rest = &spec[i + 1..];
                let close = rest.rfind(')').ok_or(BadView)?;
                if !rest[close + 1..].is_empty() {
                    return Err(BadView);
                }
                (&spec[..i], Some(&rest[..close]))
            }
            None => (spec, None),
        };
        let name = name.trim();
        if name.is_empty() || name.contains([')', ',', '.']) {
            return Err(BadView);
        }
        let mut window: Option<u32> = None;
        let mut keyspec: Option<u8> = None;
        if let Some(args) = args {
            for arg in args.split(',') {
                let arg = arg.trim();
                if arg.is_empty() {
                    return Err(BadView);
                }
                if let Some(secs) = parse_duration(arg) {
                    if window.replace(secs).is_some() {
                        return Err(BadView);
                    }
                    continue;
                }
                let mut bits = 0u8;
                for part in arg.split('+') {
                    let bit = keyspec::from_name(part.trim()).ok_or(BadView)?;
                    if bits & bit != 0 {
                        return Err(BadView);
                    }
                    bits |= bit;
                }
                if keyspec.replace(bits).is_some() {
                    return Err(BadView);
                }
            }
        }
        Ok(CounterView {
            name: str_to_pkm(name).map_err(|_| BadView)?,
            hash: name_hash(name),
            window_secs: window.unwrap_or(0),
            keyspec: keyspec.unwrap_or(0),
        })
    }
}

/// `<digits><unit>` with unit s/m/h/d; must be > 0 and <= MAX_WINDOW_SECS.
fn parse_duration(s: &str) -> Option<u32> {
    let (num, unit) = s.split_at(s.len().checked_sub(1)?);
    if num.is_empty() || !num.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: u64 = num.parse().ok()?;
    let mult: u64 = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        _ => return None,
    };
    let secs = n.checked_mul(mult)?;
    if secs == 0 || secs > u64::from(MAX_WINDOW_SECS) {
        return None;
    }
    Some(secs as u32)
}

/// What a condition is keyed on.
#[derive(Debug)]
pub enum CondKey {
    /// A vocabulary fact.
    Fact(FactId),
    /// A flow tag, by name and its store hash.
    Tag {
        /// Tag name (attribution / diagnostics).
        name: PkmString,
        /// `name_hash(name)`.
        hash: u64,
    },
    /// A counter view, by index into the forest's view table.
    Counter(u32),
}

/// One element of an integer `Equal` list.
#[derive(Debug, Clone, Copy)]
pub enum IntPattern {
    /// Exactly this value.
    Exact(i64),
    /// Inclusive range `a-b`.
    Range(i64, i64),
}

impl IntPattern {
    fn matches(self, v: i64) -> bool {
        match self {
            IntPattern::Exact(x) => v == x,
            IntPattern::Range(a, b) => v >= a && v <= b,
        }
    }
}

/// One element of an address `Equal` list.
#[derive(Debug, Clone, Copy)]
pub enum AddrPattern {
    /// Exactly this address.
    Exact(IpAddr),
    /// Inclusive range `a-b` (same family).
    Range(IpAddr, IpAddr),
    /// CIDR prefix.
    Cidr {
        /// Network address.
        addr: IpAddr,
        /// Prefix length in bits.
        prefix: u8,
    },
}

impl AddrPattern {
    fn matches(&self, v: IpAddr) -> bool {
        match *self {
            AddrPattern::Exact(a) => a == v,
            AddrPattern::Range(a, b) => match (addr_bits(a), addr_bits(b), addr_bits(v)) {
                (Some((fa, a)), Some((fb, b)), Some((fv, v))) => {
                    fa == fb && fb == fv && v >= a && v <= b
                }
                _ => false,
            },
            AddrPattern::Cidr { addr, prefix } => match (addr_bits(addr), addr_bits(v)) {
                (Some((fa, a)), Some((fv, v))) if fa == fv => {
                    let width: u32 = if fa == 4 { 32 } else { 128 };
                    if prefix == 0 {
                        return true;
                    }
                    if u32::from(prefix) > width {
                        return false;
                    }
                    let shift = width - u32::from(prefix);
                    (a >> shift) == (v >> shift)
                }
                _ => false,
            },
        }
    }
}

/// Address as (family, 128-bit value) for uniform comparison. v4 stays in
/// its own family: a v4 range never matches a v6 address and vice versa.
fn addr_bits(a: IpAddr) -> Option<(u8, u128)> {
    match a {
        IpAddr::V4(v4) => Some((4, u128::from(u32::from(v4)))),
        IpAddr::V6(v6) => Some((6, u128::from(v6))),
    }
}

/// The operator half of a condition.
#[derive(Debug)]
pub enum CondOp {
    /// Integer membership (scalars and ranges; list = OR within the field).
    EqualInt(PkmVec<IntPattern>),
    /// String membership.
    EqualStr(PkmVec<PkmString>),
    /// Address membership (exacts, ranges, CIDRs).
    EqualAddr(PkmVec<AddrPattern>),
    /// MAC membership.
    EqualMac(PkmVec<[u8; 6]>),
    /// Strictly greater than.
    Gt(i64),
    /// Strictly less than.
    Lt(i64),
    /// All listed flag bits set.
    Has(u8),
    /// All listed flag bits clear.
    Hasnt(u8),
}

/// One condition: key + operator. A rule matches iff all its conditions do.
#[derive(Debug)]
pub struct Condition {
    /// What the condition looks at.
    pub key: CondKey,
    /// How it compares.
    pub op: CondOp,
}

impl Condition {
    /// Evaluates the condition against a snapshot (absent-fact law: an
    /// unresolvable key is false).
    pub fn matches(&self, snap: &Snapshot) -> bool {
        match &self.key {
            CondKey::Tag { hash, .. } => match snap.tag(*hash) {
                Some(v) => int_op_matches(&self.op, clamp_u64(v)),
                None => false,
            },
            CondKey::Counter(view) => match snap.counter_view(*view) {
                Some(v) => int_op_matches(&self.op, clamp_u64(v)),
                None => false,
            },
            CondKey::Fact(fact) => match fact.family() {
                FactFamily::Int => match int_fact(*fact, snap) {
                    Some(v) => int_op_matches(&self.op, v),
                    None => false,
                },
                FactFamily::Str => match str_fact(*fact, snap) {
                    Some(v) => match &self.op {
                        CondOp::EqualStr(list) => list.iter().any(|p| p.as_str() == v),
                        _ => false,
                    },
                    None => false,
                },
                FactFamily::Addr => {
                    let v = match fact {
                        FactId::SrcAddr => snap.src_addr,
                        FactId::DstAddr => snap.dst_addr,
                        _ => None,
                    };
                    match v {
                        Some(v) => match &self.op {
                            CondOp::EqualAddr(list) => list.iter().any(|p| p.matches(v)),
                            _ => false,
                        },
                        None => false,
                    }
                }
                FactFamily::Mac => {
                    let v = match fact {
                        FactId::SrcMac => snap.src_mac,
                        FactId::DstMac => snap.dst_mac,
                        _ => None,
                    };
                    match v {
                        Some(v) => match &self.op {
                            CondOp::EqualMac(list) => list.iter().any(|p| *p == v),
                            _ => false,
                        },
                        None => false,
                    }
                }
                FactFamily::Flags => match snap.tcp_flags {
                    Some(v) => match &self.op {
                        CondOp::Has(mask) => v & mask == *mask,
                        CondOp::Hasnt(mask) => v & mask == 0,
                        _ => false,
                    },
                    None => false,
                },
            },
        }
    }
}

fn int_op_matches(op: &CondOp, v: i64) -> bool {
    match op {
        CondOp::EqualInt(list) => list.iter().any(|p| p.matches(v)),
        CondOp::Gt(x) => v > *x,
        CondOp::Lt(x) => v < *x,
        _ => false,
    }
}

fn clamp_u64(v: u64) -> i64 {
    if v > i64::MAX as u64 {
        i64::MAX
    } else {
        v as i64
    }
}

fn int_fact(fact: FactId, snap: &Snapshot) -> Option<i64> {
    Some(match fact {
        FactId::EtherType => i64::from(snap.ether_type?),
        FactId::Vlan => i64::from(snap.vlan?),
        FactId::Protocol => i64::from(snap.protocol?),
        FactId::Ttl => i64::from(snap.ttl?),
        FactId::Dscp => i64::from(snap.dscp?),
        FactId::Fragment => i64::from(snap.fragment? as u8),
        FactId::SrcPort => i64::from(snap.src_port?),
        FactId::DstPort => i64::from(snap.dst_port?),
        FactId::IcmpType => i64::from(snap.icmp_type?),
        FactId::IcmpCode => i64::from(snap.icmp_code?),
        FactId::Length => i64::from(snap.length?),
        FactId::TimeYear => snap.time?.year,
        FactId::TimeMonth => snap.time?.month,
        FactId::TimeDayOfMonth => snap.time?.day_of_month,
        FactId::TimeDayOfWeek => snap.time?.day_of_week,
        FactId::TimeHour => snap.time?.hour,
        FactId::TimeMinute => snap.time?.minute,
        FactId::TimeSecond => snap.time?.second,
        _ => return None,
    })
}

fn str_fact(fact: FactId, snap: &Snapshot) -> Option<&str> {
    match fact {
        FactId::Direction => snap.direction.map(|d| d.as_str()),
        FactId::FlowState => snap.flow_state.map(|s| s.as_str()),
        FactId::Interface => snap.interface.as_ref().map(|s| s.as_str()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_view_grammar_is_typed_and_order_free() {
        let v = CounterView::parse("SynFlood").unwrap();
        assert_eq!((v.window_secs, v.keyspec), (0, 0));
        assert_eq!(v.hash, name_hash("SynFlood"));

        let v = CounterView::parse("SynFlood(100s, SrcAddr+DstAddr)").unwrap();
        assert_eq!(v.window_secs, 100);
        assert_eq!(v.keyspec, keyspec::SRC_ADDR | keyspec::DST_ADDR);

        let v = CounterView::parse("x( Interface , 5m )").unwrap();
        assert_eq!(v.window_secs, 300);
        assert_eq!(v.keyspec, keyspec::INTERFACE);

        assert_eq!(CounterView::parse("x(2h)").unwrap().window_secs, 7200);
        assert_eq!(CounterView::parse("x(1d)").unwrap().window_secs, 86_400);
        assert_eq!(CounterView::parse("x(SrcAddr)").unwrap().window_secs, 0);
    }

    #[test]
    fn counter_view_grammar_refuses_nonsense() {
        assert!(CounterView::parse("").is_err());
        assert!(CounterView::parse("x(").is_err());
        assert!(CounterView::parse("x()").is_err());
        assert!(CounterView::parse("x(10s, 20s)").is_err()); // two windows
        assert!(CounterView::parse("x(SrcAddr, DstAddr)").is_err()); // two keyspecs
        assert!(CounterView::parse("x(SrcAddr+SrcAddr)").is_err()); // duplicate key
        assert!(CounterView::parse("x(2d)").is_err()); // over the horizon
        assert!(CounterView::parse("x(0s)").is_err());
        assert!(CounterView::parse("x(10)").is_err()); // unitless
        assert!(CounterView::parse("x(Ttl)").is_err()); // not a key fact
        assert!(CounterView::parse("x(10s)y").is_err());
    }
}
