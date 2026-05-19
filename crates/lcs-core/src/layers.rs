use crate::access::{registry_fd_has_right, validate_registry_granted_access};
use crate::casefold::casefold_eq;
use crate::config::LcsLimits;
use crate::constants::{BASE_LAYER_NAME, KEY_SET_VALUE};
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

/// Inputs needed for layer-targeted write authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LayerWriteAuthorizationInput {
    pub target_fd_granted_access: u32,
    pub target_required_access: u32,
    pub layer_metadata_granted_access: u32,
    pub establishes_or_elevates_precedence_above_zero: bool,
    pub caller_has_tcb: bool,
}

/// Successful layer-targeted write authorization plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LayerWriteAuthorizationPlan {
    pub target_required_access: u32,
    pub layer_metadata_required_access: u32,
    pub tcb_required_for_precedence: bool,
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

/// Enforces the two-key authorization rule for writes targeting a layer.
pub fn plan_layer_write_authorization(
    input: LayerWriteAuthorizationInput,
) -> LcsResult<LayerWriteAuthorizationPlan> {
    validate_registry_granted_access(input.target_fd_granted_access)?;
    validate_registry_granted_access(input.target_required_access)?;
    validate_registry_granted_access(input.layer_metadata_granted_access)?;

    if !registry_fd_has_right(input.target_fd_granted_access, input.target_required_access) {
        return Err(LcsError::MissingTargetKeyFdAccess {
            required: input.target_required_access,
        });
    }
    if !registry_fd_has_right(input.layer_metadata_granted_access, KEY_SET_VALUE) {
        return Err(LcsError::MissingLayerMetadataSetValue);
    }
    if input.establishes_or_elevates_precedence_above_zero && !input.caller_has_tcb {
        return Err(LcsError::MissingLayerPrecedenceTcb);
    }

    Ok(LayerWriteAuthorizationPlan {
        target_required_access: input.target_required_access,
        layer_metadata_required_access: KEY_SET_VALUE,
        tcb_required_for_precedence: input.establishes_or_elevates_precedence_above_zero,
    })
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

/// Validates a layer metadata key SD before publishing it into the layer cache.
pub fn validate_layer_metadata_security_descriptor(bytes: &[u8]) -> LcsResult<()> {
    validate_source_security_descriptor(bytes, "layer_metadata.sd")
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

fn validate_source_security_descriptor(bytes: &[u8], field: &'static str) -> LcsResult<()> {
    let sd = kacs_core::SecurityDescriptor::parse(bytes)
        .map_err(|_| LcsError::MalformedSecurityDescriptor { field })?;
    if sd.owner().is_none() {
        return Err(LcsError::MalformedSecurityDescriptor { field });
    }
    Ok(())
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
