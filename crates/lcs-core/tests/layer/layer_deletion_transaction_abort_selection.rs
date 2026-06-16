use lcs_core::{
    LayerDeletionAffectedTransactionsPlan, LayerDeletionTransactionView, LcsError, LcsLimits,
    TransactionTerminalErrno, plan_layer_deletion, plan_layer_deletion_affected_transactions,
};

#[test]
fn layer_deletion_aborts_only_bound_transactions_written_to_deleted_layer() {
    let limits = LcsLimits::default();
    let tx10_layers = ["policy"];
    let tx11_layers = ["other"];
    let tx12_layers = ["policy"];
    let tx13_layers = ["POLICY", "policy"];
    let transactions = [
        LayerDeletionTransactionView {
            transaction_id: 10,
            active_bound: true,
            written_layers: &tx10_layers,
        },
        LayerDeletionTransactionView {
            transaction_id: 11,
            active_bound: true,
            written_layers: &tx11_layers,
        },
        LayerDeletionTransactionView {
            transaction_id: 12,
            active_bound: false,
            written_layers: &tx12_layers,
        },
        LayerDeletionTransactionView {
            transaction_id: 13,
            active_bound: true,
            written_layers: &tx13_layers,
        },
    ];
    let mut emitted = Vec::new();

    let affected = plan_layer_deletion_affected_transactions(
        &limits,
        "Policy",
        &transactions,
        |transaction_id| {
            emitted.push(transaction_id);
            Ok(())
        },
    )
    .expect("affected transaction scan should succeed");

    assert_eq!(emitted, vec![10, 13]);
    assert_eq!(
        affected,
        LayerDeletionAffectedTransactionsPlan {
            inspected_transaction_count: 4,
            affected_bound_transaction_count: 2,
            abort_before_delete_layer_dispatch: true,
            affected_terminal_errno: TransactionTerminalErrno::Invalid,
        }
    );
    assert_eq!(
        plan_layer_deletion(&limits, "Policy", affected.affected_bound_transaction_count,)
            .unwrap()
            .abort_affected_bound_transactions,
        true
    );
}

#[test]
fn unaffected_layer_deletion_does_not_emit_abort_ids() {
    let limits = LcsLimits::default();
    let tx_layers = ["other"];
    let transactions = [LayerDeletionTransactionView {
        transaction_id: 20,
        active_bound: true,
        written_layers: &tx_layers,
    }];
    let mut emitted = Vec::new();

    let affected = plan_layer_deletion_affected_transactions(
        &limits,
        "policy",
        &transactions,
        |transaction_id| {
            emitted.push(transaction_id);
            Ok(())
        },
    )
    .expect("unaffected transaction scan should succeed");

    assert!(emitted.is_empty());
    assert_eq!(affected.affected_bound_transaction_count, 0);
    assert!(!affected.abort_before_delete_layer_dispatch);
}

#[test]
fn malformed_transaction_layer_log_fails_before_abort_emission() {
    let limits = LcsLimits::default();
    let bad_layers = ["bad/layer"];
    let transactions = [LayerDeletionTransactionView {
        transaction_id: 30,
        active_bound: true,
        written_layers: &bad_layers,
    }];
    let mut emitted = Vec::new();

    assert_eq!(
        plan_layer_deletion_affected_transactions(
            &limits,
            "policy",
            &transactions,
            |transaction_id| {
                emitted.push(transaction_id);
                Ok(())
            },
        ),
        Err(LcsError::NameContainsSeparator {
            field: "layer_name"
        })
    );
    assert!(emitted.is_empty());
}
