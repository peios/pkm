use crate::common::{context};
use lcs_core::{
    BlanketTombstoneEntry, LayerView, LcsError, LcsLimits, NamedValueEntry,
    REG_SZ, RsiMalformedSourceDataPlan, RsiMappedErrno, RsiSourceDataValidationFailure, ValueEntry,
    for_each_effective_value, plan_rsi_malformed_source_data, resolve_value,
};


fn duplicate_winning_tie_failure() -> RsiSourceDataValidationFailure {
    let limits = LcsLimits::default();
    let layers = [LayerView {
        name: "base",
        precedence: 0,
        enabled: true,
    }];
    let context = context(&layers, &limits);
    let entries = [
        ValueEntry {
            layer: "base",
            sequence: 5,
            value_type: REG_SZ,
            data: b"first",
        },
        ValueEntry {
            layer: "base",
            sequence: 5,
            value_type: REG_SZ,
            data: b"second",
        },
    ];

    let err = resolve_value(&context, &entries, &[]).unwrap_err();
    assert_eq!(
        err,
        LcsError::DuplicateWinningSequenceTie {
            precedence: 0,
            sequence: 5,
        }
    );

    match err {
        LcsError::DuplicateWinningSequenceTie { .. } => {
            RsiSourceDataValidationFailure::DuplicateWinningSequenceTie
        }
        other => panic!("unexpected duplicate sequence validation result: {other:?}"),
    }
}

#[test]
fn duplicate_winning_sequence_tie_maps_to_malformed_data_eio_and_audit_policy() {
    let failure = duplicate_winning_tie_failure();

    assert_eq!(
        plan_rsi_malformed_source_data(failure),
        RsiMalformedSourceDataPlan {
            failure: RsiSourceDataValidationFailure::DuplicateWinningSequenceTie,
            caller_errno: RsiMappedErrno::Eio,
            emit_audit: true,
            keep_source_alive: true,
            retain_previous_layer_metadata_sd: false,
        }
    );
}

#[test]
fn duplicate_sequences_in_unrelated_candidate_sets_are_not_compared() {
    let limits = LcsLimits::default();
    let layers = [LayerView {
        name: "base",
        precedence: 0,
        enabled: true,
    }];
    let context = context(&layers, &limits);
    let entries = [
        NamedValueEntry {
            name: "alpha",
            entry: ValueEntry {
                layer: "base",
                sequence: 5,
                value_type: REG_SZ,
                data: b"alpha",
            },
        },
        NamedValueEntry {
            name: "beta",
            entry: ValueEntry {
                layer: "base",
                sequence: 5,
                value_type: REG_SZ,
                data: b"beta",
            },
        },
    ];
    let blankets: [BlanketTombstoneEntry<'_>; 0] = [];
    let mut emitted = 0usize;

    assert_eq!(
        for_each_effective_value(&context, &entries, &blankets, |_| {
            emitted += 1;
            Ok(())
        }),
        Ok(2)
    );
    assert_eq!(emitted, 2);
}
