//! Port reservations: the KACS object that authorises `bind(2)`.
//!
//! Ports are a shared, unowned namespace. The one thing worth authorising is
//! the claim — binding a non-zero port — and this module holds the pure
//! semantics of that decision: parsing a reservation selector, validating a
//! table of reservations, and finding the most specific reservation for a
//! `(protocol, port)` pair. Evaluating the winning descriptor against a token
//! is ordinary `AccessCheck` with [`PORT_GENERIC_MAPPING`]; the kernel
//! ingress does that.
//!
//! The registry shape this mirrors (`<pkm/net.h>`):
//!
//! ```text
//! Machine\System\Network\TcpIp\PortReservations\
//!     @                 REG_BINARY  SD   default reservation
//!     tcp,udp:1-1023    REG_BINARY  SD
//!     tcp:80            REG_BINARY  SD
//! ```
//!
//! Every value under the key is one reservation; the unnamed default value is
//! the default reservation. A table is rebuilt whole from the key's values and
//! rejected whole if any value is malformed or two selectors of equal width
//! overlap — the kernel keeps the previous table rather than guessing.

use crate::access_mask::{GenericMapping, READ_CONTROL};
use crate::error::{KacsError, KacsResult};
use crate::pkm_alloc::Vec;
use crate::security_descriptor::SecurityDescriptor;

/// Port right permitting `bind(2)` to a port the selector contains.
pub const PORT_BIND: u32 = peios_uapi::KACS_PORT_BIND;

/// Every right a port descriptor can carry.
pub const PORT_ALL_ACCESS: u32 = peios_uapi::KACS_PORT_ALL_ACCESS;

/// Generic mapping for port reservation descriptors.
///
/// A port descriptor authorises one operation. Editing the reservation is a
/// registry write governed by the key's descriptor, so `WRITE_DAC` and
/// `WRITE_OWNER` map to nothing here.
pub const PORT_GENERIC_MAPPING: GenericMapping = GenericMapping {
    read: READ_CONTROL,
    write: 0,
    execute: PORT_BIND,
    all: PORT_ALL_ACCESS,
};

/// Selector protocol bit for TCP.
pub const PORT_PROTO_TCP: u8 = peios_uapi::KACS_PORT_PROTO_TCP as u8;
/// Selector protocol bit for UDP.
pub const PORT_PROTO_UDP: u8 = peios_uapi::KACS_PORT_PROTO_UDP as u8;
/// Selector protocol bits for every protocol.
pub const PORT_PROTO_ALL: u8 = peios_uapi::KACS_PORT_PROTO_ALL as u8;

/// Longest accepted selector, in bytes.
pub const PORT_SELECTOR_MAX_LEN: usize = peios_uapi::KACS_PORT_SELECTOR_MAX_LEN as usize;

/// Name of the registry value holding the default reservation, as spelled
/// in a serialised table. In the registry itself the default value has the
/// empty name; `@` is its conventional spelling and both are accepted.
pub const PORT_DEFAULT_SELECTOR: &[u8] = b"@";

/// Whether `name` names the default reservation.
pub fn is_default_selector(name: &[u8]) -> bool {
    name.is_empty() || name == PORT_DEFAULT_SELECTOR
}

/// A transport protocol as seen at `bind(2)`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PortProtocol {
    /// `IPPROTO_TCP` (and SCTP is *not* covered — no reservation applies).
    Tcp,
    /// `IPPROTO_UDP` and `IPPROTO_UDPLITE`.
    Udp,
}

impl PortProtocol {
    const fn bit(self) -> u8 {
        match self {
            PortProtocol::Tcp => PORT_PROTO_TCP,
            PortProtocol::Udp => PORT_PROTO_UDP,
        }
    }
}

/// A parsed reservation selector: a protocol set and an inclusive port range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortSelector {
    /// Bitwise OR of `PORT_PROTO_*`.
    pub protocols: u8,
    /// First port covered, inclusive.
    pub lo: u16,
    /// Last port covered, inclusive.
    pub hi: u16,
}

impl PortSelector {
    /// Parses a selector name.
    ///
    /// Grammar: `<proto>[,<proto>]:<lo>[-<hi>]`, with `proto` one of `tcp`,
    /// `udp`, `*` (case-insensitive ASCII). Ports are decimal, `1..=65535`,
    /// no leading zeros, `lo <= hi`. A repeated protocol is rejected so that
    /// every selector has exactly one spelling.
    pub fn parse(name: &[u8]) -> KacsResult<Self> {
        if name.is_empty() || name.len() > PORT_SELECTOR_MAX_LEN {
            return Err(KacsError::InvalidPortSelector("length"));
        }
        let colon = name
            .iter()
            .position(|&b| b == b':')
            .ok_or(KacsError::InvalidPortSelector("missing ':'"))?;
        let (proto_part, range_part) = (&name[..colon], &name[colon + 1..]);

        let mut protocols = 0u8;
        for proto in proto_part.split(|&b| b == b',') {
            let bit = match proto {
                b"*" => PORT_PROTO_ALL,
                _ if proto.eq_ignore_ascii_case(b"tcp") => PORT_PROTO_TCP,
                _ if proto.eq_ignore_ascii_case(b"udp") => PORT_PROTO_UDP,
                _ => return Err(KacsError::InvalidPortSelector("protocol")),
            };
            if protocols & bit != 0 {
                return Err(KacsError::InvalidPortSelector("repeated protocol"));
            }
            protocols |= bit;
        }
        if protocols == 0 {
            return Err(KacsError::InvalidPortSelector("no protocol"));
        }

        let (lo, hi) = match range_part.iter().position(|&b| b == b'-') {
            Some(dash) => (
                parse_port(&range_part[..dash])?,
                parse_port(&range_part[dash + 1..])?,
            ),
            None => {
                let port = parse_port(range_part)?;
                (port, port)
            }
        };
        if lo > hi {
            return Err(KacsError::InvalidPortSelector("range order"));
        }
        Ok(Self { protocols, lo, hi })
    }

    /// Whether this selector covers `(protocol, port)`.
    pub const fn contains(&self, protocol: PortProtocol, port: u16) -> bool {
        self.protocols & protocol.bit() != 0 && port >= self.lo && port <= self.hi
    }

    /// Number of ports covered. The tie-break for specificity: fewer is more
    /// specific, regardless of protocol count.
    pub const fn width(&self) -> u32 {
        (self.hi as u32) - (self.lo as u32) + 1
    }

    const fn overlaps(&self, other: &Self) -> bool {
        self.protocols & other.protocols != 0 && self.lo <= other.hi && other.lo <= self.hi
    }
}

fn parse_port(digits: &[u8]) -> KacsResult<u16> {
    if digits.is_empty() || digits.len() > 5 {
        return Err(KacsError::InvalidPortSelector("port digits"));
    }
    if digits[0] == b'0' {
        return Err(KacsError::InvalidPortSelector("port zero or leading zero"));
    }
    let mut value: u32 = 0;
    for &b in digits {
        if !b.is_ascii_digit() {
            return Err(KacsError::InvalidPortSelector("port digits"));
        }
        value = value * 10 + u32::from(b - b'0');
    }
    if value > u32::from(u16::MAX) {
        return Err(KacsError::InvalidPortSelector("port range"));
    }
    Ok(value as u16)
}

/// One reservation: a selector and the descriptor bytes it maps to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortReservation<'a> {
    /// Which ports the reservation covers.
    pub selector: PortSelector,
    /// Self-relative security descriptor, validated at table build.
    pub sd: &'a [u8],
}

/// A validated table of reservations plus the default reservation.
#[derive(Debug)]
pub struct PortReservationTable<'a> {
    default_sd: &'a [u8],
    reservations: Vec<PortReservation<'a>>,
}

impl<'a> PortReservationTable<'a> {
    /// Builds a table from registry values, `(name, data)` pairs.
    ///
    /// Exactly one value must be named `@` — the default reservation. Every
    /// descriptor must parse as self-relative. Two selectors that overlap
    /// with the same width are rejected: the most specific match would be
    /// ambiguous, and the table refuses to guess. Nested or differing-width
    /// overlap is fine and is how specificity works.
    pub fn from_values<I>(values: I) -> KacsResult<Self>
    where
        I: IntoIterator<Item = (&'a [u8], &'a [u8])>,
    {
        let mut default_sd: Option<&'a [u8]> = None;
        let mut reservations: Vec<PortReservation<'a>> = Vec::new();

        for (name, sd) in values {
            SecurityDescriptor::parse(sd).map_err(|_| KacsError::InvalidPortReservationSd)?;
            if is_default_selector(name) {
                if default_sd.is_some() {
                    return Err(KacsError::InvalidPortSelector("duplicate default"));
                }
                default_sd = Some(sd);
                continue;
            }
            let selector = PortSelector::parse(name)?;
            for existing in reservations.iter() {
                if existing.selector.overlaps(&selector)
                    && existing.selector.width() == selector.width()
                {
                    return Err(KacsError::AmbiguousPortReservation);
                }
            }
            reservations
                .push(PortReservation { selector, sd })
                .map_err(|_| KacsError::AllocationFailure)?;
        }

        let default_sd = default_sd.ok_or(KacsError::InvalidPortSelector("missing default"))?;
        Ok(Self {
            default_sd,
            reservations,
        })
    }

    /// The descriptor governing `(protocol, port)`: the narrowest selector
    /// containing it, else the default reservation.
    pub fn lookup(&self, protocol: PortProtocol, port: u16) -> &'a [u8] {
        let mut best: Option<&PortReservation<'a>> = None;
        for reservation in self.reservations.iter() {
            if !reservation.selector.contains(protocol, port) {
                continue;
            }
            match best {
                Some(current) if current.selector.width() <= reservation.selector.width() => {}
                _ => best = Some(reservation),
            }
        }
        best.map_or(self.default_sd, |reservation| reservation.sd)
    }

    /// The default reservation's descriptor.
    pub fn default_sd(&self) -> &'a [u8] {
        self.default_sd
    }

    /// Every explicit reservation, in table order.
    pub fn reservations(&self) -> &[PortReservation<'a>] {
        &self.reservations
    }
}

/// Allocation-free lookup over raw `(name, sd)` values.
///
/// The same rule as [`PortReservationTable::lookup`] — narrowest containing
/// selector, else the `@` default — but streamed over the values without
/// building a table, for callers that hold a lock under which they must not
/// allocate. Callers must have validated the values with
/// [`PortReservationTable::from_values`] when they were published; an
/// unparseable name is skipped here rather than reported, and a missing
/// default yields `None`.
pub fn lookup_values<'a, I>(values: I, protocol: PortProtocol, port: u16) -> Option<&'a [u8]>
where
    I: IntoIterator<Item = (&'a [u8], &'a [u8])>,
{
    let mut default_sd: Option<&'a [u8]> = None;
    let mut best: Option<(u32, &'a [u8])> = None;
    for (name, sd) in values {
        if is_default_selector(name) {
            default_sd = Some(sd);
            continue;
        }
        let Ok(selector) = PortSelector::parse(name) else {
            continue;
        };
        if !selector.contains(protocol, port) {
            continue;
        }
        let width = selector.width();
        match best {
            Some((current, _)) if current <= width => {}
            _ => best = Some((width, sd)),
        }
    }
    best.map(|(_, sd)| sd).or(default_sd)
}

/// The compiled-in default reservation, used until the registry table has
/// loaded once and whenever it is unavailable — never merged with it.
///
/// Owner and group SYSTEM; one DACL entry granting SYSTEM
/// `PORT_BIND | READ_CONTROL`. Nothing else may claim a port before the
/// registry says otherwise.
pub const PORT_FALLBACK_DEFAULT_SD: &[u8] = &[
    // SECURITY_DESCRIPTOR header: revision 1, sbz, control
    // (SELF_RELATIVE | DACL_PRESENT), owner @20, group @32, sacl 0, dacl @44.
    0x01, 0x00, 0x04, 0x80, //
    20, 0, 0, 0, //
    32, 0, 0, 0, //
    0, 0, 0, 0, //
    44, 0, 0, 0, //
    // owner: S-1-5-18
    1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0, //
    // group: S-1-5-18
    1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0, //
    // ACL header: revision 2, sbz, size 28, count 1, sbz2
    0x02, 0x00, 28, 0, 1, 0, 0, 0, //
    // ACCESS_ALLOWED ACE: type 0, flags 0, size 20, mask PORT_BIND|READ_CONTROL
    0x00, 0x00, 20, 0, 0x01, 0x00, 0x02, 0x00, //
    // trustee: S-1-5-18
    1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0, //
];

/// The compiled-in fallback table: the fallback default and nothing else.
pub fn port_fallback_table() -> KacsResult<PortReservationTable<'static>> {
    PortReservationTable::from_values([(PORT_DEFAULT_SELECTOR, PORT_FALLBACK_DEFAULT_SD)])
}
