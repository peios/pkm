use crate::casefold::casefold_eq;
use crate::config::LcsLimits;
use crate::constants::BASE_LAYER_NAME;
use crate::error::{LcsError, LcsResult};
use crate::path::{is_base_layer_name, validate_layer_name_bytes};
use crate::resolution::{LayerResolutionContext, LayerView};

/// Canonical hardcoded base layer view.
pub const BASE_LAYER_VIEW: LayerView<'static> = LayerView {
    name: BASE_LAYER_NAME,
    precedence: 0,
    enabled: true,
};

/// Source/cache layer metadata before PSD-005 defaults are applied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LayerMetadataEntry<'a> {
    pub name: &'a str,
    pub precedence: Option<u32>,
    pub enabled: Option<bool>,
}

/// Transactional read target affected by layer-precedence coherency.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionalLayerReadSubject {
    LayerMetadataValue,
    RegistryResolution,
}

/// Read source selected for a transactional layer-precedence-sensitive read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionalLayerReadPlan {
    UseTransactionalSourceRead,
    UsePublishedLayerCache,
}

/// Commit timing for a mutation under the layer metadata subtree.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LayerMetadataMutationTiming {
    NonTransactionalCommitted,
    TransactionPending,
    TransactionCommitSucceeded,
    TransactionDiscarded,
}

/// Layer metadata cache update selected for a layer metadata mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LayerMetadataCacheUpdatePlan {
    RefreshBeforeReturn,
    DeferUntilTransactionCommit,
    NoRefresh,
}

/// Normalizes an optional caller-supplied layer target.
pub fn normalize_layer_target<'a>(
    layer: Option<&'a str>,
    limits: &LcsLimits,
) -> LcsResult<&'a str> {
    let Some(layer) = layer else {
        return Ok(BASE_LAYER_NAME);
    };
    validate_layer_name_bytes(layer.as_bytes(), limits)
}

/// Emits the effective layer table from cached/source metadata.
///
/// The canonical base layer is always emitted first. Non-base metadata follows
/// first-seen input order after validation and PSD-005 defaulting.
pub fn for_each_effective_layer<'a, F>(
    limits: &LcsLimits,
    metadata: &'a [LayerMetadataEntry<'a>],
    mut emit: F,
) -> LcsResult<usize>
where
    F: FnMut(LayerView<'a>) -> LcsResult<()>,
{
    let count = validate_layer_metadata_snapshot(limits, metadata)?;

    emit(BASE_LAYER_VIEW)?;
    for entry in metadata {
        let name = validate_layer_name_bytes(entry.name.as_bytes(), limits)?;
        if is_base_layer_name(name) {
            continue;
        }
        emit(LayerView {
            name,
            precedence: entry.precedence.unwrap_or(0),
            enabled: entry.enabled.unwrap_or(true),
        })?;
    }

    Ok(count)
}

/// Validates a layer-resolution context before it is used for lookup.
pub fn validate_layer_resolution_context(context: &LayerResolutionContext<'_>) -> LcsResult<()> {
    validate_layer_views(context.limits, context.layers)?;
    validate_private_layer_set(context.limits, context.private_layers)
}

/// Validates an already-published layer view snapshot.
pub fn validate_layer_views(limits: &LcsLimits, layers: &[LayerView<'_>]) -> LcsResult<()> {
    if layers.len() > limits.max_total_layers {
        return Err(LcsError::TooManyLayers {
            count: layers.len(),
            max: limits.max_total_layers,
        });
    }

    let mut found_base = false;
    for (index, layer) in layers.iter().enumerate() {
        let name = validate_layer_name_bytes(layer.name.as_bytes(), limits)?;
        if layer_name_seen_before(limits, layers, index, name)? {
            return Err(LcsError::DuplicateLayerIdentity);
        }

        if is_base_layer_name(name) {
            found_base = true;
            if layer.precedence != 0 || !layer.enabled {
                return Err(LcsError::InvalidBaseLayerProperties {
                    precedence: layer.precedence,
                    enabled: layer.enabled,
                });
            }
        }
    }

    if !found_base {
        return Err(LcsError::MissingBaseLayer);
    }

    Ok(())
}

/// Validates private layer names carried by credentials.
pub fn validate_private_layer_set(limits: &LcsLimits, private_layers: &[&str]) -> LcsResult<()> {
    if private_layers.len() > limits.max_private_layers_per_token {
        return Err(LcsError::TooManyPrivateLayers {
            count: private_layers.len(),
            max: limits.max_private_layers_per_token,
        });
    }

    for (index, private_layer) in private_layers.iter().enumerate() {
        let name = validate_layer_name_bytes(private_layer.as_bytes(), limits)?;
        if private_layer_seen_before(limits, private_layers, index, name)? {
            return Err(LcsError::DuplicatePrivateLayerIdentity);
        }
    }

    Ok(())
}

/// Selects the read source for transactional layer-precedence-sensitive logic.
pub fn plan_transactional_layer_read(
    subject: TransactionalLayerReadSubject,
) -> TransactionalLayerReadPlan {
    match subject {
        TransactionalLayerReadSubject::LayerMetadataValue => {
            TransactionalLayerReadPlan::UseTransactionalSourceRead
        }
        TransactionalLayerReadSubject::RegistryResolution => {
            TransactionalLayerReadPlan::UsePublishedLayerCache
        }
    }
}

/// Plans cache refresh timing for a mutation under `Machine\System\Registry\Layers\`.
pub fn plan_layer_metadata_cache_update(
    affects_layer_metadata_subtree: bool,
    timing: LayerMetadataMutationTiming,
) -> LayerMetadataCacheUpdatePlan {
    if !affects_layer_metadata_subtree {
        return LayerMetadataCacheUpdatePlan::NoRefresh;
    }

    match timing {
        LayerMetadataMutationTiming::NonTransactionalCommitted
        | LayerMetadataMutationTiming::TransactionCommitSucceeded => {
            LayerMetadataCacheUpdatePlan::RefreshBeforeReturn
        }
        LayerMetadataMutationTiming::TransactionPending => {
            LayerMetadataCacheUpdatePlan::DeferUntilTransactionCommit
        }
        LayerMetadataMutationTiming::TransactionDiscarded => {
            LayerMetadataCacheUpdatePlan::NoRefresh
        }
    }
}

fn validate_layer_metadata_snapshot(
    limits: &LcsLimits,
    metadata: &[LayerMetadataEntry<'_>],
) -> LcsResult<usize> {
    let mut non_base_count = 0usize;

    for (index, entry) in metadata.iter().enumerate() {
        let name = validate_layer_name_bytes(entry.name.as_bytes(), limits)?;
        if metadata_name_seen_before(limits, metadata, index, name)? {
            return Err(LcsError::DuplicateLayerIdentity);
        }
        if !is_base_layer_name(name) {
            non_base_count += 1;
        }
    }

    let count = non_base_count + 1;
    if count > limits.max_total_layers {
        return Err(LcsError::TooManyLayers {
            count,
            max: limits.max_total_layers,
        });
    }

    Ok(count)
}

fn metadata_name_seen_before(
    limits: &LcsLimits,
    metadata: &[LayerMetadataEntry<'_>],
    index: usize,
    current_name: &str,
) -> LcsResult<bool> {
    for previous in &metadata[..index] {
        let previous_name = validate_layer_name_bytes(previous.name.as_bytes(), limits)?;
        if casefold_eq(previous_name, current_name) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn layer_name_seen_before(
    limits: &LcsLimits,
    layers: &[LayerView<'_>],
    index: usize,
    current_name: &str,
) -> LcsResult<bool> {
    for previous in &layers[..index] {
        let previous_name = validate_layer_name_bytes(previous.name.as_bytes(), limits)?;
        if casefold_eq(previous_name, current_name) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn private_layer_seen_before(
    limits: &LcsLimits,
    private_layers: &[&str],
    index: usize,
    current_name: &str,
) -> LcsResult<bool> {
    for previous in &private_layers[..index] {
        let previous_name = validate_layer_name_bytes(previous.as_bytes(), limits)?;
        if casefold_eq(previous_name, current_name) {
            return Ok(true);
        }
    }
    Ok(false)
}
