use lcs_core::{
    LayerMetadataCacheUpdatePlan, LayerMetadataMutationTiming, TransactionalLayerReadPlan,
    TransactionalLayerReadSubject, plan_layer_metadata_cache_update, plan_transactional_layer_read,
};

#[test]
fn transactional_layer_reads_distinguish_metadata_from_registry_resolution() {
    assert_eq!(
        plan_transactional_layer_read(TransactionalLayerReadSubject::LayerMetadataValue),
        TransactionalLayerReadPlan::UseTransactionalSourceRead
    );
    assert_eq!(
        plan_transactional_layer_read(TransactionalLayerReadSubject::RegistryResolution),
        TransactionalLayerReadPlan::UsePublishedLayerCache
    );
}

#[test]
fn layer_metadata_mutations_refresh_only_after_commit_boundary() {
    assert_eq!(
        plan_layer_metadata_cache_update(
            true,
            LayerMetadataMutationTiming::NonTransactionalCommitted,
        ),
        LayerMetadataCacheUpdatePlan::RefreshBeforeReturn
    );
    assert_eq!(
        plan_layer_metadata_cache_update(true, LayerMetadataMutationTiming::TransactionPending),
        LayerMetadataCacheUpdatePlan::DeferUntilTransactionCommit
    );
    assert_eq!(
        plan_layer_metadata_cache_update(
            true,
            LayerMetadataMutationTiming::TransactionCommitSucceeded,
        ),
        LayerMetadataCacheUpdatePlan::RefreshBeforeReturn
    );
}

#[test]
fn aborted_or_failed_layer_metadata_transactions_do_not_refresh_cache() {
    assert_eq!(
        plan_layer_metadata_cache_update(true, LayerMetadataMutationTiming::TransactionDiscarded),
        LayerMetadataCacheUpdatePlan::NoRefresh
    );
}

#[test]
fn unrelated_mutations_do_not_refresh_layer_cache() {
    for timing in [
        LayerMetadataMutationTiming::NonTransactionalCommitted,
        LayerMetadataMutationTiming::TransactionPending,
        LayerMetadataMutationTiming::TransactionCommitSucceeded,
        LayerMetadataMutationTiming::TransactionDiscarded,
    ] {
        assert_eq!(
            plan_layer_metadata_cache_update(false, timing),
            LayerMetadataCacheUpdatePlan::NoRefresh
        );
    }
}
