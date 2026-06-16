use crate::common::{context, limits};
use lcs_core::{
    BASE_LAYER_VIEW, BlanketTombstoneEntry, LayerView,
    QueryValueOutcome, REG_BINARY, REG_TOMBSTONE, RsiMappedErrno, ValueEntry, ValueResolution,
    query_value_not_found_errno, query_value_result_from_resolution, resolve_value,
};



#[test]
fn effective_per_value_tombstone_reads_as_enoent_without_exposing_type() {
    let limits = limits();
    let layers = [
        BASE_LAYER_VIEW,
        LayerView {
            name: "policy",
            precedence: 10,
            enabled: true,
        },
    ];
    let context = context(&layers, &limits);
    let resolution = resolve_value(
        &context,
        &[
            ValueEntry {
                layer: "base",
                sequence: 1,
                value_type: REG_BINARY,
                data: b"lower",
            },
            ValueEntry {
                layer: "policy",
                sequence: 2,
                value_type: REG_TOMBSTONE,
                data: &[],
            },
        ],
        &[],
    )
    .expect("tombstone resolution should succeed");

    assert_eq!(resolution, ValueResolution::NotFound);
    let outcome = query_value_result_from_resolution(resolution);
    assert_eq!(outcome, QueryValueOutcome::NotFound);
    assert_eq!(
        query_value_not_found_errno(&outcome),
        Some(RsiMappedErrno::Enoent)
    );
}

#[test]
fn non_winning_tombstone_does_not_hide_newer_same_precedence_value() {
    let limits = limits();
    let layers = [BASE_LAYER_VIEW];
    let context = context(&layers, &limits);
    let resolution = resolve_value(
        &context,
        &[
            ValueEntry {
                layer: "base",
                sequence: 1,
                value_type: REG_TOMBSTONE,
                data: &[],
            },
            ValueEntry {
                layer: "base",
                sequence: 2,
                value_type: REG_BINARY,
                data: b"newer",
            },
        ],
        &[],
    )
    .expect("newer value should resolve");
    let outcome = query_value_result_from_resolution(resolution);

    let QueryValueOutcome::Found(found) = outcome else {
        panic!("expected newer normal value to remain visible");
    };
    assert_eq!(found.data, b"newer");
    assert_eq!(query_value_not_found_errno(&outcome), None);
}

#[test]
fn blanket_tombstone_query_absence_uses_the_same_enoent_projection() {
    let limits = limits();
    let layers = [
        BASE_LAYER_VIEW,
        LayerView {
            name: "policy",
            precedence: 10,
            enabled: true,
        },
    ];
    let context = context(&layers, &limits);
    let resolution = resolve_value(
        &context,
        &[ValueEntry {
            layer: "base",
            sequence: 1,
            value_type: REG_BINARY,
            data: b"lower",
        }],
        &[BlanketTombstoneEntry {
            layer: "policy",
            sequence: 2,
        }],
    )
    .expect("blanket tombstone resolution should succeed");
    let outcome = query_value_result_from_resolution(resolution);

    assert_eq!(
        query_value_not_found_errno(&outcome),
        Some(RsiMappedErrno::Enoent)
    );
}
