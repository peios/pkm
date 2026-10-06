//! The registry write records: the exact key sets and byte layout of
//! `lcs.audit.value.set`, `.value.deleted`, `.key.tombstoned`,
//! `.key.deleted`, `.key.hidden`, `.key.created`,
//! `.key.descriptor.changed` and `.transaction.committed`.

use crate::common::sid;
use kacs_core::TokenType;
use lcs_core::{
    LcsCallerTokenSummary, LcsError, LcsKeyAuditAccess, LcsKeyAuditDetail, LcsKeyAuditRecord,
    LcsSdAuditSummary, LcsTransactionAuditReason, LcsTransactionAuditState,
    LcsTransactionCommittedAuditRecord, LcsValueAuditSummary, key_audit_payload_len,
    transaction_committed_audit_payload_len, write_key_audit_payload,
    write_transaction_committed_audit_payload,
};

const KEY_SET_VALUE: u32 = 0x0002;
const DELETE: u32 = 0x0001_0000;
const WRITE_DAC: u32 = 0x0004_0000;
const KEY_CREATE_SUB_KEY: u32 = 0x0004;
const KEY_ALL_ACCESS: u32 = 0x000f_003f;
const PATH: &str = "Machine\\Software\\Test";

fn caller(user_sid: &[u8]) -> LcsCallerTokenSummary<'_> {
    LcsCallerTokenSummary {
        user_sid,
        integrity_level: 512,
        token_id: 99,
        authentication_id: 42,
        token_type: TokenType::Primary,
        impersonation_level: 0,
    }
}

/// A msgpack builder for the expected bytes, written independently of the
/// serializer under test.
#[derive(Default)]
struct Mp(Vec<u8>);

impl Mp {
    fn map(&mut self, n: usize) -> &mut Self {
        assert!(n <= 15);
        self.0.push(0x80 | n as u8);
        self
    }

    fn str(&mut self, s: &str) -> &mut Self {
        assert!(s.len() <= 31);
        self.0.push(0xa0 | s.len() as u8);
        self.0.extend_from_slice(s.as_bytes());
        self
    }

    fn bin(&mut self, b: &[u8]) -> &mut Self {
        self.0.push(0xc4);
        self.0.push(b.len() as u8);
        self.0.extend_from_slice(b);
        self
    }

    fn uint(&mut self, v: u64) -> &mut Self {
        if v <= 0x7f {
            self.0.push(v as u8);
        } else if v <= 0xff {
            self.0.extend_from_slice(&[0xcc, v as u8]);
        } else if v <= 0xffff {
            self.0.push(0xcd);
            self.0.extend_from_slice(&(v as u16).to_be_bytes());
        } else if v <= 0xffff_ffff {
            self.0.push(0xce);
            self.0.extend_from_slice(&(v as u32).to_be_bytes());
        } else {
            self.0.push(0xcf);
            self.0.extend_from_slice(&v.to_be_bytes());
        }
        self
    }

    fn int32(&mut self, v: i32) -> &mut Self {
        self.0.push(0xd2);
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }

    fn bool(&mut self, v: bool) -> &mut Self {
        self.0.push(if v { 0xc3 } else { 0xc2 });
        self
    }

    fn caller(&mut self, user_sid: &[u8]) -> &mut Self {
        self.str("subject").map(1).str("token").map(6);
        self.str("sid").bin(user_sid);
        self.str("integrity").uint(512);
        self.str("id").uint(99);
        self.str("auth-id").uint(42);
        self.str("type").str("primary");
        self.str("impersonation").uint(0)
    }

    fn outcome(&mut self, errno: Option<i32>) -> &mut Self {
        self.str("outcome");
        match errno {
            None => self.map(1).str("success").bool(true),
            Some(errno) => self
                .map(2)
                .str("success")
                .bool(false)
                .str("errno")
                .int32(errno),
        }
    }
}

fn write(record: &LcsKeyAuditRecord<'_>) -> Vec<u8> {
    let len = key_audit_payload_len(record).expect("payload length");
    let mut out = vec![0xee; len + 3];
    let plan = write_key_audit_payload(record, &mut out).expect("payload");
    assert_eq!(plan.bytes, len);
    assert_eq!(
        &out[len..],
        &[0xee; 3],
        "the writer stays inside its length"
    );
    out.truncate(len);
    out
}

fn handle_access(requested: u32, mask: u32) -> LcsKeyAuditAccess {
    LcsKeyAuditAccess {
        requested,
        granted: KEY_ALL_ACCESS,
        audit_mask: Some(mask),
    }
}

fn record<'a>(
    user: &'a [u8],
    access: LcsKeyAuditAccess,
    detail: LcsKeyAuditDetail<'a>,
) -> LcsKeyAuditRecord<'a> {
    LcsKeyAuditRecord {
        caller: caller(user),
        key_guid: [7; 16],
        key_path: PATH,
        key_layer_name: Some("base"),
        access,
        transaction_id: None,
        result_errno: 0,
        timed_out: false,
        detail,
    }
}

/// `object: {kind, key: {guid, path, layer: {name}, ...}}` with `extra`
/// further entries in `key`.
fn object_key_head(mp: &mut Mp, object_len: usize, key_len: usize) {
    mp.str("object").map(object_len);
    mp.str("kind").str("key");
    mp.str("key").map(key_len);
    mp.str("guid").bin(&[7; 16]);
    mp.str("path").str(PATH);
    mp.str("layer").map(1).str("name").str("base");
}

fn access_map(mp: &mut Mp, requested: u32, matched: u32, mask: u32) {
    mp.str("access").map(4);
    mp.str("requested").uint(requested as u64);
    mp.str("granted").uint(KEY_ALL_ACCESS as u64);
    mp.str("matched").uint(matched as u64);
    mp.str("audit-mask").uint(mask as u64);
}

fn value(value_type: u32, length: u32, fill: u8) -> LcsValueAuditSummary {
    LcsValueAuditSummary {
        value_type,
        length,
        digest: [fill; 32],
    }
}

#[test]
fn value_set_carries_the_new_and_previous_value_and_the_sequence() {
    let user = sid(5, &[18]);
    let mask = KEY_SET_VALUE | DELETE;
    let rec = record(
        &user,
        handle_access(KEY_SET_VALUE, mask),
        LcsKeyAuditDetail::ValueSet {
            value_name: Some("Enabled"),
            value: Some(value(4, 4, 0xa1)),
            previous: Some(value(1, 10, 0xb2)),
            sequence: Some(300),
            expected_sequence: Some(299),
        },
    );

    let mut mp = Mp::default();
    // subject, object, access, mutation, outcome
    mp.map(5).caller(&user);
    object_key_head(&mut mp, 2, 4);
    mp.str("value").map(7);
    mp.str("name").str("Enabled");
    mp.str("type")
        .uint(4)
        .str("length")
        .uint(4)
        .str("digest")
        .bin(&[0xa1; 32]);
    mp.str("type-previous").uint(1);
    mp.str("length-previous").uint(10);
    mp.str("digest-previous").bin(&[0xb2; 32]);
    access_map(&mut mp, KEY_SET_VALUE, KEY_SET_VALUE, mask);
    mp.str("mutation").map(2);
    mp.str("sequence")
        .uint(300)
        .str("sequence-expected")
        .uint(299);
    mp.outcome(None);

    assert_eq!(write(&rec), mp.0);
}

#[test]
fn value_set_staged_in_a_transaction_carries_its_id_and_no_previous_value() {
    let user = sid(5, &[18]);
    let mut rec = record(
        &user,
        handle_access(KEY_SET_VALUE, KEY_SET_VALUE),
        LcsKeyAuditDetail::ValueSet {
            value_name: Some(""),
            value: Some(value(1, 2, 0x11)),
            previous: None,
            sequence: Some(5),
            expected_sequence: None,
        },
    );
    rec.transaction_id = Some(1234);

    let mut mp = Mp::default();
    // subject, object, access, mutation, transaction, outcome
    mp.map(6).caller(&user);
    object_key_head(&mut mp, 2, 4);
    mp.str("value").map(4);
    mp.str("name").str("");
    mp.str("type")
        .uint(1)
        .str("length")
        .uint(2)
        .str("digest")
        .bin(&[0x11; 32]);
    access_map(&mut mp, KEY_SET_VALUE, KEY_SET_VALUE, KEY_SET_VALUE);
    mp.str("mutation").map(1).str("sequence").uint(5);
    mp.str("transaction").map(1).str("id").uint(1234);
    mp.outcome(None);

    assert_eq!(write(&rec), mp.0);
}

/// A write whose source wait ran out is recorded as failed, with
/// `request.timed-out` true: it may still be applied later.
#[test]
fn value_set_timeout_is_a_failure_with_request_timed_out() {
    let user = sid(5, &[18]);
    let mut rec = record(
        &user,
        handle_access(KEY_SET_VALUE, KEY_SET_VALUE),
        LcsKeyAuditDetail::ValueSet {
            value_name: Some("V"),
            value: Some(value(4, 4, 0x33)),
            previous: None,
            sequence: Some(8),
            expected_sequence: None,
        },
    );
    rec.result_errno = 110;
    rec.timed_out = true;

    let mut mp = Mp::default();
    // subject, object, access, mutation, request, outcome
    mp.map(6).caller(&user);
    object_key_head(&mut mp, 2, 4);
    mp.str("value").map(4);
    mp.str("name").str("V");
    mp.str("type")
        .uint(4)
        .str("length")
        .uint(4)
        .str("digest")
        .bin(&[0x33; 32]);
    access_map(&mut mp, KEY_SET_VALUE, KEY_SET_VALUE, KEY_SET_VALUE);
    mp.str("mutation").map(1).str("sequence").uint(8);
    mp.str("request").map(1).str("timed-out").bool(true);
    mp.outcome(Some(-110));

    assert_eq!(write(&rec), mp.0);
}

/// A failure that is not a timeout still says so, and a request refused
/// before the name was read carries no value map at all.
#[test]
fn value_set_early_failure_has_no_value_map() {
    let user = sid(5, &[18]);
    let mut rec = record(
        &user,
        handle_access(KEY_SET_VALUE, KEY_SET_VALUE),
        LcsKeyAuditDetail::ValueSet {
            value_name: None,
            value: None,
            previous: None,
            sequence: None,
            expected_sequence: None,
        },
    );
    rec.key_layer_name = None;
    rec.result_errno = 13;

    let mut mp = Mp::default();
    // subject, object, access, request, outcome
    mp.map(5).caller(&user);
    mp.str("object").map(2).str("kind").str("key");
    mp.str("key")
        .map(2)
        .str("guid")
        .bin(&[7; 16])
        .str("path")
        .str(PATH);
    access_map(&mut mp, KEY_SET_VALUE, KEY_SET_VALUE, KEY_SET_VALUE);
    mp.str("request").map(1).str("timed-out").bool(false);
    mp.outcome(Some(-13));

    assert_eq!(write(&rec), mp.0);
}

#[test]
fn value_deleted_carries_the_name_and_the_value_it_removed() {
    let user = sid(5, &[18]);
    let rec = record(
        &user,
        handle_access(KEY_SET_VALUE, KEY_SET_VALUE),
        LcsKeyAuditDetail::ValueDeleted {
            value_name: Some("Old"),
            previous: Some(value(3, 16, 0x44)),
        },
    );

    let mut mp = Mp::default();
    mp.map(4).caller(&user);
    object_key_head(&mut mp, 2, 4);
    mp.str("value").map(4);
    mp.str("name").str("Old");
    mp.str("type-previous").uint(3);
    mp.str("length-previous").uint(16);
    mp.str("digest-previous").bin(&[0x44; 32]);
    access_map(&mut mp, KEY_SET_VALUE, KEY_SET_VALUE, KEY_SET_VALUE);
    mp.outcome(None);

    assert_eq!(write(&rec), mp.0);
}

#[test]
fn key_tombstoned_names_set_or_clear() {
    let user = sid(5, &[18]);
    for (set, name, sequence) in [(true, "set", Some(41)), (false, "clear", None)] {
        let rec = record(
            &user,
            handle_access(KEY_SET_VALUE, KEY_SET_VALUE),
            LcsKeyAuditDetail::KeyTombstoned {
                set: Some(set),
                sequence,
            },
        );

        let mut mp = Mp::default();
        // subject, object, access, operation, [mutation], outcome
        mp.map(5 + usize::from(sequence.is_some())).caller(&user);
        object_key_head(&mut mp, 2, 3);
        access_map(&mut mp, KEY_SET_VALUE, KEY_SET_VALUE, KEY_SET_VALUE);
        mp.str("operation").map(1).str("name").str(name);
        if let Some(sequence) = sequence {
            mp.str("mutation").map(1).str("sequence").uint(sequence);
        }
        mp.outcome(None);

        assert_eq!(write(&rec), mp.0, "{name}");
    }
}

#[test]
fn key_deleted_of_a_layer_metadata_key_names_the_layer() {
    let user = sid(5, &[18]);
    let rec = record(
        &user,
        handle_access(DELETE, DELETE | KEY_SET_VALUE),
        LcsKeyAuditDetail::KeyDeleted {
            layer_name: Some("Vendor"),
        },
    );

    let mut mp = Mp::default();
    mp.map(4).caller(&user);
    object_key_head(&mut mp, 3, 3);
    mp.str("layer").map(1).str("name").str("Vendor");
    access_map(&mut mp, DELETE, DELETE, DELETE | KEY_SET_VALUE);
    mp.outcome(None);

    assert_eq!(write(&rec), mp.0);
}

#[test]
fn key_hidden_carries_its_sequence() {
    let user = sid(5, &[18]);
    let rec = record(
        &user,
        handle_access(DELETE, DELETE),
        LcsKeyAuditDetail::KeyHidden { sequence: Some(77) },
    );

    let mut mp = Mp::default();
    mp.map(5).caller(&user);
    object_key_head(&mut mp, 2, 3);
    access_map(&mut mp, DELETE, DELETE, DELETE);
    mp.str("mutation").map(1).str("sequence").uint(77);
    mp.outcome(None);

    assert_eq!(write(&rec), mp.0);
}

#[test]
fn key_created_carries_the_new_key_and_its_descriptor() {
    let user = sid(5, &[18]);
    let owner = sid(5, &[32, 544]);
    let mut rec = record(
        &user,
        LcsKeyAuditAccess {
            requested: KEY_CREATE_SUB_KEY,
            granted: KEY_CREATE_SUB_KEY,
            audit_mask: None,
        },
        LcsKeyAuditDetail::KeyCreated {
            volatile: true,
            volatile_requested: true,
            symlink: false,
            sd_owner: Some(&owner),
            sd_length: 120,
        },
    );
    rec.transaction_id = Some(9);

    let mut mp = Mp::default();
    // subject, object, access, transaction, outcome
    mp.map(5).caller(&user);
    object_key_head(&mut mp, 3, 7);
    mp.str("created").bool(true);
    mp.str("volatile").bool(true);
    mp.str("volatile-requested").bool(true);
    mp.str("symlink").bool(false);
    mp.str("sd")
        .map(2)
        .str("length")
        .uint(120)
        .str("owner")
        .bin(&owner);
    mp.str("access").map(2);
    mp.str("requested").uint(KEY_CREATE_SUB_KEY as u64);
    mp.str("granted").uint(KEY_CREATE_SUB_KEY as u64);
    mp.str("transaction").map(1).str("id").uint(9);
    mp.outcome(None);

    assert_eq!(write(&rec), mp.0);
}

#[test]
fn key_created_is_never_a_failure() {
    let user = sid(5, &[18]);
    let mut rec = record(
        &user,
        LcsKeyAuditAccess {
            requested: KEY_CREATE_SUB_KEY,
            granted: KEY_CREATE_SUB_KEY,
            audit_mask: None,
        },
        LcsKeyAuditDetail::KeyCreated {
            volatile: false,
            volatile_requested: false,
            symlink: false,
            sd_owner: None,
            sd_length: 20,
        },
    );
    rec.result_errno = 5;
    assert!(matches!(
        key_audit_payload_len(&rec),
        Err(LcsError::MalformedKeyAuditRecord { .. })
    ));
}

#[test]
fn descriptor_changed_carries_both_descriptors() {
    let user = sid(5, &[18]);
    let owner = sid(5, &[32, 544]);
    let old_owner = sid(5, &[18]);
    let mut rec = record(
        &user,
        handle_access(WRITE_DAC, WRITE_DAC),
        LcsKeyAuditDetail::KeyDescriptorChanged {
            components: 0x5,
            sd: Some(LcsSdAuditSummary {
                length: 100,
                digest: [0x55; 32],
                owner: Some(&owner),
            }),
            previous: Some(LcsSdAuditSummary {
                length: 90,
                digest: [0x66; 32],
                owner: Some(&old_owner),
            }),
        },
    );
    rec.key_layer_name = None;

    let mut mp = Mp::default();
    mp.map(4).caller(&user);
    mp.str("object").map(3).str("kind").str("key");
    mp.str("key")
        .map(2)
        .str("guid")
        .bin(&[7; 16])
        .str("path")
        .str(PATH);
    mp.str("sd").map(7);
    mp.str("components").uint(5);
    mp.str("length").uint(100);
    mp.str("length-previous").uint(90);
    mp.str("digest").bin(&[0x55; 32]);
    mp.str("digest-previous").bin(&[0x66; 32]);
    mp.str("owner").bin(&owner);
    mp.str("owner-previous").bin(&old_owner);
    access_map(&mut mp, WRITE_DAC, WRITE_DAC, WRITE_DAC);
    mp.outcome(None);

    assert_eq!(write(&rec), mp.0);
}

/// A SACL change is recorded whatever the handle's mask: `access.matched`
/// is then zero. Any other change must overlap the mask.
#[test]
fn descriptor_changed_sacl_change_needs_no_mask_overlap() {
    const ACCESS_SYSTEM_SECURITY: u32 = 0x0100_0000;
    let user = sid(5, &[18]);
    let mut rec = record(
        &user,
        handle_access(ACCESS_SYSTEM_SECURITY, 0),
        LcsKeyAuditDetail::KeyDescriptorChanged {
            components: 0x8,
            sd: None,
            previous: None,
        },
    );
    rec.key_layer_name = None;
    rec.result_errno = 22;

    let mut mp = Mp::default();
    // subject, object, access, request, outcome
    mp.map(5).caller(&user);
    mp.str("object").map(3).str("kind").str("key");
    mp.str("key")
        .map(2)
        .str("guid")
        .bin(&[7; 16])
        .str("path")
        .str(PATH);
    mp.str("sd").map(1).str("components").uint(8);
    access_map(&mut mp, ACCESS_SYSTEM_SECURITY, 0, 0);
    mp.str("request").map(1).str("timed-out").bool(false);
    mp.outcome(Some(-22));
    assert_eq!(write(&rec), mp.0);

    rec.detail = LcsKeyAuditDetail::KeyDescriptorChanged {
        components: 0x4,
        sd: None,
        previous: None,
    };
    rec.access = handle_access(WRITE_DAC, DELETE);
    assert!(matches!(
        key_audit_payload_len(&rec),
        Err(LcsError::MalformedKeyAuditRecord {
            field: "access.matched"
        })
    ));
}

#[test]
fn key_audit_records_refuse_inconsistent_state() {
    let user = sid(5, &[18]);
    let bad_sid = [1u8, 1];
    let base = record(
        &user,
        handle_access(KEY_SET_VALUE, KEY_SET_VALUE),
        LcsKeyAuditDetail::ValueDeleted {
            value_name: Some("x"),
            previous: None,
        },
    );

    let mut timed_out_success = base;
    timed_out_success.timed_out = true;
    assert!(key_audit_payload_len(&timed_out_success).is_err());

    let mut no_mask = base;
    no_mask.access.audit_mask = None;
    assert!(key_audit_payload_len(&no_mask).is_err());

    let mut no_overlap = base;
    no_overlap.access.audit_mask = Some(DELETE);
    assert!(key_audit_payload_len(&no_overlap).is_err());

    let mut empty_path = base;
    empty_path.key_path = "";
    assert!(key_audit_payload_len(&empty_path).is_err());

    let mut bad_caller = base;
    bad_caller.caller.user_sid = &bad_sid;
    assert!(key_audit_payload_len(&bad_caller).is_err());

    let mut buffer = [0u8; 8];
    assert!(matches!(
        write_key_audit_payload(&base, &mut buffer),
        Err(LcsError::AuditPayloadOutputBufferTooSmall { .. })
    ));
}

fn write_txn(record: &LcsTransactionCommittedAuditRecord<'_>) -> Vec<u8> {
    let len = transaction_committed_audit_payload_len(record).expect("payload length");
    let mut out = vec![0u8; len];
    let plan = write_transaction_committed_audit_payload(record, &mut out).expect("payload");
    assert_eq!(plan.bytes, len);
    out
}

#[test]
fn transaction_committed_success_is_three_maps() {
    let user = sid(5, &[18]);
    let rec = LcsTransactionCommittedAuditRecord {
        caller: caller(&user),
        transaction_id: 4096,
        state: LcsTransactionAuditState::Committed,
        errno: None,
        reason: None,
        commit_outstanding: None,
    };

    let mut mp = Mp::default();
    mp.map(3).caller(&user);
    mp.str("transaction").map(2);
    mp.str("id").uint(4096).str("state").str("committed");
    mp.outcome(None);

    assert_eq!(write_txn(&rec), mp.0);
}

#[test]
fn transaction_committed_failures_carry_a_reason() {
    let user = sid(5, &[18]);
    // A commit whose wait ran out with the commit unanswered.
    let timed_out = LcsTransactionCommittedAuditRecord {
        caller: caller(&user),
        transaction_id: 7,
        state: LcsTransactionAuditState::TimedOut,
        errno: Some(110),
        reason: Some(LcsTransactionAuditReason::TimedOut),
        commit_outstanding: Some(true),
    };
    let mut mp = Mp::default();
    mp.map(3).caller(&user);
    mp.str("transaction").map(3);
    mp.str("id").uint(7).str("state").str("timed-out");
    mp.str("commit-outstanding").bool(true);
    mp.str("outcome").map(3);
    mp.str("success").bool(false);
    mp.str("errno").int32(-110);
    mp.str("reason").str("timed-out");
    assert_eq!(write_txn(&timed_out), mp.0);

    // Closed without a commit: no errno, since no call failed.
    let aborted = LcsTransactionCommittedAuditRecord {
        caller: caller(&user),
        transaction_id: 8,
        state: LcsTransactionAuditState::Aborted,
        errno: None,
        reason: Some(LcsTransactionAuditReason::Aborted),
        commit_outstanding: Some(false),
    };
    let mut mp = Mp::default();
    mp.map(3).caller(&user);
    mp.str("transaction").map(3);
    mp.str("id").uint(8).str("state").str("aborted");
    mp.str("commit-outstanding").bool(false);
    mp.str("outcome").map(2);
    mp.str("success").bool(false);
    mp.str("reason").str("aborted");
    assert_eq!(write_txn(&aborted), mp.0);
}

#[test]
fn transaction_committed_refuses_inconsistent_state() {
    let user = sid(5, &[18]);
    let ok = LcsTransactionCommittedAuditRecord {
        caller: caller(&user),
        transaction_id: 1,
        state: LcsTransactionAuditState::Committed,
        errno: None,
        reason: None,
        commit_outstanding: None,
    };
    let mut reason_on_success = ok;
    reason_on_success.reason = Some(LcsTransactionAuditReason::Aborted);
    assert!(transaction_committed_audit_payload_len(&reason_on_success).is_err());

    let mut failure_without_reason = ok;
    failure_without_reason.state = LcsTransactionAuditState::SourceDown;
    assert!(transaction_committed_audit_payload_len(&failure_without_reason).is_err());

    assert_eq!(
        LcsTransactionAuditState::from_raw(5),
        Some(LcsTransactionAuditState::SourceDown)
    );
    assert_eq!(LcsTransactionAuditState::from_raw(6), None);
    assert_eq!(
        LcsTransactionAuditReason::from_raw(3),
        Some(LcsTransactionAuditReason::SourceError)
    );
    assert_eq!(LcsTransactionAuditReason::from_raw(0), None);
}
