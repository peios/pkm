//! Match conditions: the fact vocabulary, operators, and evaluation.
//!
//! A rule's match is a conjunction of conditions. Every condition is
//! evaluated against the immutable snapshot under the absent-fact law: a
//! condition over a fact the packet does not have is false.

use core::net::IpAddr;

use crate::pkm_alloc::{String as PkmString, Vec as PkmVec};
use crate::snapshot::Snapshot;

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

/// What a condition is keyed on.
#[derive(Debug)]
pub enum CondKey {
    /// A vocabulary fact.
    Fact(FactId),
    /// A flow tag by name.
    Tag(PkmString),
    /// A counter cell by name.
    Counter(PkmString),
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
            CondKey::Tag(name) => match snap.tag(name.as_str()) {
                Some(v) => int_op_matches(&self.op, v),
                None => false,
            },
            CondKey::Counter(name) => match snap.counter(name.as_str()) {
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
