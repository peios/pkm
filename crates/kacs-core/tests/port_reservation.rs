//! Port reservation semantics: selector grammar, table validation, lookup,
//! and the compiled-in fallback.
mod common;

use common::*;
use kacs_core::*;

const SYSTEM: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];

/// A minimal self-relative SD: owner/group SYSTEM, one allow ACE for `sid`.
fn port_sd(sid: &[u8], mask: u32) -> Vec<u8> {
    let acl = acl_bytes(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, mask, sid)]);
    let owner_off = 20u32;
    let group_off = owner_off + SYSTEM.len() as u32;
    let dacl_off = group_off + SYSTEM.len() as u32;
    let mut bytes = vec![1u8, 0];
    bytes.extend_from_slice(&(SE_SELF_RELATIVE | SE_DACL_PRESENT).to_le_bytes());
    bytes.extend_from_slice(&owner_off.to_le_bytes());
    bytes.extend_from_slice(&group_off.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&dacl_off.to_le_bytes());
    bytes.extend_from_slice(&SYSTEM);
    bytes.extend_from_slice(&SYSTEM);
    bytes.extend_from_slice(&acl);
    bytes
}

fn sel(name: &str) -> PortSelector {
    PortSelector::parse(name.as_bytes()).expect(name)
}

#[test]
fn selector_grammar_accepts_every_documented_form() {
    assert_eq!(
        sel("tcp:80"),
        PortSelector { protocols: PORT_PROTO_TCP, lo: 80, hi: 80 }
    );
    assert_eq!(
        sel("udp:53"),
        PortSelector { protocols: PORT_PROTO_UDP, lo: 53, hi: 53 }
    );
    assert_eq!(
        sel("tcp,udp:1-1023"),
        PortSelector { protocols: PORT_PROTO_ALL, lo: 1, hi: 1023 }
    );
    assert_eq!(sel("udp,tcp:1-1023"), sel("tcp,udp:1-1023"));
    assert_eq!(
        sel("*:8080"),
        PortSelector { protocols: PORT_PROTO_ALL, lo: 8080, hi: 8080 }
    );
    assert_eq!(sel("TCP:443"), sel("tcp:443"));
    assert_eq!(sel("tcp,udp:65535-65535").width(), 1);
    assert_eq!(sel("*:1-65535").width(), 65535);
}

#[test]
fn selector_grammar_rejects_malformed_names() {
    for bad in [
        "", "tcp", "tcp:", ":80", "tcp:0", "tcp:080", "tcp:65536", "tcp:80-", "tcp:-80",
        "tcp:443-80", "sctp:80", "tcp,tcp:80", "*,tcp:80", "tcp,:80", "tcp:8 0", "tcp:80:90",
        "tcp:1-2-3", "tcp,udp:65535-655350",
    ] {
        assert!(
            PortSelector::parse(bad.as_bytes()).is_err(),
            "{bad:?} should be rejected"
        );
    }
    assert!(matches!(
        PortSelector::parse(b"tcp:0"),
        Err(KacsError::InvalidPortSelector(_))
    ));
}

#[test]
fn selector_contains_respects_protocol_and_range() {
    let s = sel("tcp:1-1023");
    assert!(s.contains(PortProtocol::Tcp, 1));
    assert!(s.contains(PortProtocol::Tcp, 1023));
    assert!(!s.contains(PortProtocol::Tcp, 1024));
    assert!(!s.contains(PortProtocol::Udp, 80));
    assert!(sel("*:80").contains(PortProtocol::Udp, 80));
}

#[test]
fn table_requires_exactly_one_default_and_valid_descriptors() {
    let sd = port_sd(&SYSTEM, PORT_BIND);
    assert!(matches!(
        PortReservationTable::from_values([(b"tcp:80".as_slice(), sd.as_slice())]),
        Err(KacsError::InvalidPortSelector("missing default"))
    ));
    assert!(matches!(
        PortReservationTable::from_values([
            (PORT_DEFAULT_SELECTOR, sd.as_slice()),
            (PORT_DEFAULT_SELECTOR, sd.as_slice()),
        ]),
        Err(KacsError::InvalidPortSelector("duplicate default"))
    ));
    assert!(matches!(
        PortReservationTable::from_values([(PORT_DEFAULT_SELECTOR, &sd[..10])]),
        Err(KacsError::InvalidPortReservationSd)
    ));
    assert!(matches!(
        PortReservationTable::from_values([
            (PORT_DEFAULT_SELECTOR, sd.as_slice()),
            (b"tcp:nope".as_slice(), sd.as_slice()),
        ]),
        Err(KacsError::InvalidPortSelector(_))
    ));
}

#[test]
fn table_rejects_equal_width_overlap_but_allows_nesting() {
    let sd = port_sd(&SYSTEM, PORT_BIND);
    let dup = PortReservationTable::from_values([
        (PORT_DEFAULT_SELECTOR, sd.as_slice()),
        (b"tcp:80".as_slice(), sd.as_slice()),
        (b"*:80".as_slice(), sd.as_slice()),
    ]);
    assert!(matches!(dup, Err(KacsError::AmbiguousPortReservation)));

    let shifted = PortReservationTable::from_values([
        (PORT_DEFAULT_SELECTOR, sd.as_slice()),
        (b"tcp:100-199".as_slice(), sd.as_slice()),
        (b"tcp:150-249".as_slice(), sd.as_slice()),
    ]);
    assert!(matches!(shifted, Err(KacsError::AmbiguousPortReservation)));

    // Same ports, disjoint protocols: no overlap.
    PortReservationTable::from_values([
        (PORT_DEFAULT_SELECTOR, sd.as_slice()),
        (b"tcp:80".as_slice(), sd.as_slice()),
        (b"udp:80".as_slice(), sd.as_slice()),
    ])
    .expect("disjoint protocols may share a port");

    // Nesting is how specificity works.
    PortReservationTable::from_values([
        (PORT_DEFAULT_SELECTOR, sd.as_slice()),
        (b"tcp,udp:1-1023".as_slice(), sd.as_slice()),
        (b"tcp:80".as_slice(), sd.as_slice()),
        (b"tcp:443".as_slice(), sd.as_slice()),
    ])
    .expect("nested reservations are valid");
}

#[test]
fn lookup_returns_the_narrowest_containing_reservation_else_default() {
    let default = port_sd(&SYSTEM, PORT_BIND);
    let low = port_sd(&SYSTEM, PORT_BIND | READ_CONTROL);
    let web = port_sd(&sid_bytes([0, 0, 0, 0, 0, 5], &[80, 1]), PORT_BIND);
    let table = PortReservationTable::from_values([
        (PORT_DEFAULT_SELECTOR, default.as_slice()),
        (b"tcp:80".as_slice(), web.as_slice()),
        (b"tcp,udp:1-1023".as_slice(), low.as_slice()),
    ])
    .expect("table");

    assert_eq!(table.lookup(PortProtocol::Tcp, 80), web.as_slice());
    assert_eq!(table.lookup(PortProtocol::Udp, 80), low.as_slice());
    assert_eq!(table.lookup(PortProtocol::Tcp, 22), low.as_slice());
    assert_eq!(table.lookup(PortProtocol::Tcp, 1023), low.as_slice());
    assert_eq!(table.lookup(PortProtocol::Tcp, 1024), default.as_slice());
    assert_eq!(table.lookup(PortProtocol::Udp, 8080), default.as_slice());
    assert_eq!(table.default_sd(), default.as_slice());
    assert_eq!(table.reservations().len(), 2);
}

#[test]
fn lookup_order_independence() {
    let a = port_sd(&SYSTEM, PORT_BIND);
    let b = port_sd(&SYSTEM, READ_CONTROL);
    let c = port_sd(&SYSTEM, PORT_BIND | READ_CONTROL);
    let forward = PortReservationTable::from_values([
        (PORT_DEFAULT_SELECTOR, a.as_slice()),
        (b"tcp:1-1023".as_slice(), b.as_slice()),
        (b"tcp:80".as_slice(), c.as_slice()),
    ])
    .unwrap();
    let reverse = PortReservationTable::from_values([
        (b"tcp:80".as_slice(), c.as_slice()),
        (b"tcp:1-1023".as_slice(), b.as_slice()),
        (PORT_DEFAULT_SELECTOR, a.as_slice()),
    ])
    .unwrap();
    assert_eq!(
        forward.lookup(PortProtocol::Tcp, 80),
        reverse.lookup(PortProtocol::Tcp, 80)
    );
    assert_eq!(forward.lookup(PortProtocol::Tcp, 80), c.as_slice());
}

#[test]
fn fallback_descriptor_is_well_formed_and_matches_the_test_encoder() {
    let parsed = SecurityDescriptor::parse(PORT_FALLBACK_DEFAULT_SD).expect("fallback parses");
    assert_eq!(parsed.owner().map(|s| s.as_bytes()), Some(SYSTEM.as_slice()));
    assert_eq!(parsed.group().map(|s| s.as_bytes()), Some(SYSTEM.as_slice()));
    assert!(parsed.dacl().is_some());
    // The shared encoder emits ACL_REVISION_DS; the fallback uses the plain
    // ACL_REVISION that a basic-ACE ACL should carry. Everything else must be
    // byte-identical.
    let mut expected = port_sd(&SYSTEM, PORT_BIND | READ_CONTROL);
    expected[44] = ACL_REVISION;
    assert_eq!(PORT_FALLBACK_DEFAULT_SD, expected.as_slice());

    let table = port_fallback_table().expect("fallback table");
    assert_eq!(table.reservations().len(), 0);
    assert_eq!(table.lookup(PortProtocol::Tcp, 80), PORT_FALLBACK_DEFAULT_SD);
    assert_eq!(table.lookup(PortProtocol::Udp, 60000), PORT_FALLBACK_DEFAULT_SD);
}

#[test]
fn port_rights_and_mapping_match_the_uapi() {
    assert_eq!(PORT_BIND, 0x0000_0001);
    assert_eq!(PORT_ALL_ACCESS, PORT_BIND | READ_CONTROL);
    assert_eq!(PORT_GENERIC_MAPPING.map_mask(GENERIC_EXECUTE).unwrap(), PORT_BIND);
    assert_eq!(PORT_GENERIC_MAPPING.map_mask(GENERIC_READ).unwrap(), READ_CONTROL);
    assert_eq!(PORT_GENERIC_MAPPING.map_mask(GENERIC_WRITE).unwrap(), 0);
    assert_eq!(PORT_GENERIC_MAPPING.map_mask(GENERIC_ALL).unwrap(), PORT_ALL_ACCESS);
    assert_eq!(PORT_SELECTOR_MAX_LEN, "tcp,udp:65535-65535".len());
}

#[test]
fn streaming_lookup_agrees_with_the_table() {
    let default = port_sd(&SYSTEM, PORT_BIND);
    let low = port_sd(&SYSTEM, PORT_BIND | READ_CONTROL);
    let web = port_sd(&sid_bytes([0, 0, 0, 0, 0, 5], &[80, 1]), PORT_BIND);
    let values: Vec<(&[u8], &[u8])> = vec![
        (b"tcp:80", web.as_slice()),
        (PORT_DEFAULT_SELECTOR, default.as_slice()),
        (b"tcp,udp:1-1023", low.as_slice()),
    ];
    let table = PortReservationTable::from_values(values.iter().copied()).unwrap();
    for (proto, port) in [
        (PortProtocol::Tcp, 80),
        (PortProtocol::Udp, 80),
        (PortProtocol::Tcp, 22),
        (PortProtocol::Tcp, 1024),
        (PortProtocol::Udp, 65535),
    ] {
        assert_eq!(
            lookup_values(values.iter().copied(), proto, port),
            Some(table.lookup(proto, port)),
            "{proto:?}:{port}"
        );
    }
    // No default at all: nothing to fall back on.
    assert_eq!(
        lookup_values([(b"tcp:80".as_slice(), web.as_slice())], PortProtocol::Udp, 9),
        None
    );
    // A malformed name is skipped, not fatal, once past validation.
    assert_eq!(
        lookup_values(
            [(b"bogus".as_slice(), web.as_slice()), (PORT_DEFAULT_SELECTOR, default.as_slice())],
            PortProtocol::Tcp,
            80
        ),
        Some(default.as_slice())
    );
}

#[test]
fn the_empty_name_is_the_default_reservation() {
    let sd = port_sd(&SYSTEM, PORT_BIND);
    assert!(is_default_selector(b""));
    assert!(is_default_selector(b"@"));
    assert!(!is_default_selector(b"tcp:80"));
    let table = PortReservationTable::from_values([(b"".as_slice(), sd.as_slice())]).unwrap();
    assert_eq!(table.default_sd(), sd.as_slice());
    assert!(matches!(
        PortReservationTable::from_values([
            (b"".as_slice(), sd.as_slice()),
            (PORT_DEFAULT_SELECTOR, sd.as_slice()),
        ]),
        Err(KacsError::InvalidPortSelector("duplicate default"))
    ));
    assert_eq!(
        lookup_values([(b"".as_slice(), sd.as_slice())], PortProtocol::Tcp, 1),
        Some(sd.as_slice())
    );
}
