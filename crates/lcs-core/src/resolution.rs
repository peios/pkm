use crate::casefold::casefold_eq;
use crate::config::LcsLimits;
use crate::constants::REG_TOMBSTONE;
use crate::error::{LcsError, LcsResult};
use crate::layers::validate_layer_resolution_context;
use crate::path::{
    validate_key_component_bytes, validate_layer_name_bytes, validate_value_name_bytes,
};
use crate::source::NIL_GUID;
use crate::value::{RegistryValueType, ValidatedValueType, validate_value_write_type};

/// LCS GUID bytes in canonical on-wire order.
pub type Guid = [u8; 16];

/// One published layer-table entry visible to the resolver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LayerView<'a> {
    pub name: &'a str,
    pub precedence: u32,
    pub enabled: bool,
}

/// Per-operation resolution context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LayerResolutionContext<'a> {
    pub layers: &'a [LayerView<'a>],
    pub private_layers: &'a [&'a str],
    pub limits: &'a LcsLimits,
    pub next_sequence: u64,
}

/// Source-returned path-entry target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathTarget {
    Guid(Guid),
    Hidden,
}

/// One source-returned path entry for a single `(parent GUID, child name)`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PathEntry<'a> {
    pub layer: &'a str,
    pub sequence: u64,
    pub target: PathTarget,
}

/// LCS-produced path-entry write before source dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PathEntryWriteRequest<'a> {
    pub parent_guid: Guid,
    pub child_name: &'a str,
    pub layer: &'a str,
    pub sequence: u64,
    pub target: PathTarget,
}

/// Validated LCS path-entry write fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedPathEntryWrite<'a> {
    pub parent_guid: Guid,
    pub child_name: &'a str,
    pub layer: &'a str,
    pub sequence: u64,
    pub target: PathTarget,
}

/// Effective visible path entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolvedPathEntry<'a> {
    pub guid: Guid,
    pub layer: &'a str,
    pub precedence: u32,
    pub sequence: u64,
}

/// Result of resolving one path-entry candidate set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathResolution<'a> {
    Found(ResolvedPathEntry<'a>),
    NotFound,
}

/// One source-returned value entry for a single `(key GUID, value name)`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValueEntry<'a> {
    pub layer: &'a str,
    pub sequence: u64,
    pub value_type: u32,
    pub data: &'a [u8],
}

/// One source-returned blanket tombstone candidate for a key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlanketTombstoneEntry<'a> {
    pub layer: &'a str,
    pub sequence: u64,
}

/// Effective visible value entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolvedValueEntry<'a> {
    pub value_type: RegistryValueType,
    pub data: &'a [u8],
    pub layer: &'a str,
    pub precedence: u32,
    pub sequence: u64,
}

/// Result of resolving one value candidate set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValueResolution<'a> {
    Found(ResolvedValueEntry<'a>),
    NotFound,
}

/// One source-returned value entry with its source-visible value name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NamedValueEntry<'a> {
    pub name: &'a str,
    pub entry: ValueEntry<'a>,
}

/// One source-returned child path entry with its source-visible child name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NamedPathEntry<'a> {
    pub child_name: &'a str,
    pub entry: PathEntry<'a>,
}

/// One effective value emitted by enumeration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnumeratedValue<'a> {
    pub name: &'a str,
    pub value: ResolvedValueEntry<'a>,
}

/// One effective visible child emitted by subkey enumeration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnumeratedSubkey<'a> {
    pub child_name: &'a str,
    pub path: ResolvedPathEntry<'a>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ActiveLayer<'a> {
    name: &'a str,
    precedence: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PathCandidate<'a> {
    layer: ActiveLayer<'a>,
    sequence: u64,
    target: PathTarget,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ValueCandidatePayload<'a> {
    Value {
        value_type: RegistryValueType,
        data: &'a [u8],
    },
    Tombstone,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ValueCandidate<'a> {
    layer: ActiveLayer<'a>,
    sequence: u64,
    payload: ValueCandidatePayload<'a>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NamedPathCandidate<'a> {
    name: &'a str,
    layer: ActiveLayer<'a>,
    sequence: u64,
    target: PathTarget,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NamedValueCandidate<'a> {
    name: Option<&'a str>,
    layer: ActiveLayer<'a>,
    sequence: u64,
    payload: ValueCandidatePayload<'a>,
}

/// Resolves one source-returned path-entry candidate set.
pub fn resolve_path_entry<'a>(
    context: &LayerResolutionContext<'a>,
    entries: &'a [PathEntry<'a>],
) -> LcsResult<PathResolution<'a>> {
    validate_layer_resolution_context(context)?;

    let mut best: Option<PathCandidate<'a>> = None;
    let mut duplicate_best = false;

    for entry in entries {
        let Some(layer) = active_layer_for_source_entry(context, entry.layer)? else {
            continue;
        };
        validate_sequence(context, entry.sequence)?;
        let target = validate_path_target(entry.target)?;

        let candidate = PathCandidate {
            layer,
            sequence: entry.sequence,
            target,
        };
        update_best_path(&mut best, &mut duplicate_best, candidate);
    }

    let Some(best) = best else {
        return Ok(PathResolution::NotFound);
    };
    reject_duplicate_winning_tie(duplicate_best, best.layer.precedence, best.sequence)?;

    match best.target {
        PathTarget::Guid(guid) => Ok(PathResolution::Found(ResolvedPathEntry {
            guid,
            layer: best.layer.name,
            precedence: best.layer.precedence,
            sequence: best.sequence,
        })),
        PathTarget::Hidden => Ok(PathResolution::NotFound),
    }
}

/// Validates one LCS-produced path-entry write before source dispatch.
pub fn validate_path_entry_write_request<'a>(
    limits: &LcsLimits,
    request: &PathEntryWriteRequest<'a>,
) -> LcsResult<ValidatedPathEntryWrite<'a>> {
    if request.parent_guid == NIL_GUID {
        return Err(LcsError::NilParentGuid);
    }
    let child_name = validate_key_component_bytes(request.child_name.as_bytes(), limits)?;
    let layer = validate_layer_name_bytes(request.layer.as_bytes(), limits)?;
    let target = validate_path_target(request.target)?;

    Ok(ValidatedPathEntryWrite {
        parent_guid: request.parent_guid,
        child_name,
        layer,
        sequence: request.sequence,
        target,
    })
}

/// Validates a path-entry target value.
pub fn validate_path_target(target: PathTarget) -> LcsResult<PathTarget> {
    if let PathTarget::Guid(guid) = target {
        if guid == NIL_GUID {
            return Err(LcsError::NilKeyGuid);
        }
    }
    Ok(target)
}

/// Resolves one source-returned value candidate set.
pub fn resolve_value<'a>(
    context: &LayerResolutionContext<'a>,
    entries: &'a [ValueEntry<'a>],
    blankets: &'a [BlanketTombstoneEntry<'a>],
) -> LcsResult<ValueResolution<'a>> {
    validate_layer_resolution_context(context)?;

    let mut best: Option<ValueCandidate<'a>> = None;
    let mut duplicate_best = false;

    for entry in entries {
        let Some(layer) = active_layer_for_source_entry(context, entry.layer)? else {
            continue;
        };
        validate_sequence(context, entry.sequence)?;
        let payload = validate_source_value_payload(entry)?;

        let candidate = ValueCandidate {
            layer,
            sequence: entry.sequence,
            payload,
        };
        update_best_value(&mut best, &mut duplicate_best, candidate);
    }

    for blanket in blankets {
        let Some(layer) = active_layer_for_source_entry(context, blanket.layer)? else {
            continue;
        };
        validate_sequence(context, blanket.sequence)?;

        let candidate = ValueCandidate {
            layer,
            sequence: blanket.sequence,
            payload: ValueCandidatePayload::Tombstone,
        };
        update_best_value(&mut best, &mut duplicate_best, candidate);
    }

    let Some(best) = best else {
        return Ok(ValueResolution::NotFound);
    };
    reject_duplicate_winning_tie(duplicate_best, best.layer.precedence, best.sequence)?;

    match best.payload {
        ValueCandidatePayload::Value { value_type, data } => {
            Ok(ValueResolution::Found(ResolvedValueEntry {
                value_type,
                data,
                layer: best.layer.name,
                precedence: best.layer.precedence,
                sequence: best.sequence,
            }))
        }
        ValueCandidatePayload::Tombstone => Ok(ValueResolution::NotFound),
    }
}

/// Enumerates effective values from source-returned raw value entries.
///
/// This groups folded-equivalent names, resolves each group with blanket
/// tombstones, and emits only visible effective values. Output order is the
/// first-seen folded group order and is not an ABI guarantee.
pub fn for_each_effective_value<'a, F>(
    context: &LayerResolutionContext<'a>,
    entries: &'a [NamedValueEntry<'a>],
    blankets: &'a [BlanketTombstoneEntry<'a>],
    mut emit: F,
) -> LcsResult<usize>
where
    F: FnMut(EnumeratedValue<'a>) -> LcsResult<()>,
{
    validate_layer_resolution_context(context)?;
    prevalidate_value_enumeration_source(context, entries, blankets)?;

    let mut emitted = 0usize;

    for (index, entry) in entries.iter().enumerate() {
        let current_name = validate_value_name_bytes(entry.name.as_bytes(), context.limits)?;
        if value_name_seen_before(context, entries, index, current_name)? {
            continue;
        }

        let mut best: Option<NamedValueCandidate<'a>> = None;
        let mut duplicate_best = false;

        for candidate_entry in entries {
            let candidate_name =
                validate_value_name_bytes(candidate_entry.name.as_bytes(), context.limits)?;
            if !casefold_eq(candidate_name, current_name) {
                continue;
            }

            let Some(layer) = active_layer_for_source_entry(context, candidate_entry.entry.layer)?
            else {
                continue;
            };
            validate_sequence(context, candidate_entry.entry.sequence)?;
            let payload = validate_source_value_payload(&candidate_entry.entry)?;

            let candidate = NamedValueCandidate {
                name: Some(candidate_name),
                layer,
                sequence: candidate_entry.entry.sequence,
                payload,
            };
            update_best_named_value(&mut best, &mut duplicate_best, candidate);
        }

        for blanket in blankets {
            let Some(layer) = active_layer_for_source_entry(context, blanket.layer)? else {
                continue;
            };
            validate_sequence(context, blanket.sequence)?;

            let candidate = NamedValueCandidate {
                name: None,
                layer,
                sequence: blanket.sequence,
                payload: ValueCandidatePayload::Tombstone,
            };
            update_best_named_value(&mut best, &mut duplicate_best, candidate);
        }

        let Some(best) = best else {
            continue;
        };
        reject_duplicate_winning_tie(duplicate_best, best.layer.precedence, best.sequence)?;

        if let ValueCandidatePayload::Value { value_type, data } = best.payload {
            let name = best
                .name
                .expect("visible enumerated value candidate carries its source name");
            emit(EnumeratedValue {
                name,
                value: ResolvedValueEntry {
                    value_type,
                    data,
                    layer: best.layer.name,
                    precedence: best.layer.precedence,
                    sequence: best.sequence,
                },
            })?;
            emitted += 1;
        }
    }

    Ok(emitted)
}

/// Enumerates visible subkeys from source-returned raw child path entries.
///
/// This groups folded-equivalent child names, resolves each group, and emits
/// only effective GUID targets. Output order is the first-seen folded group
/// order and is not an ABI guarantee.
pub fn for_each_visible_subkey<'a, F>(
    context: &LayerResolutionContext<'a>,
    entries: &'a [NamedPathEntry<'a>],
    mut emit: F,
) -> LcsResult<usize>
where
    F: FnMut(EnumeratedSubkey<'a>) -> LcsResult<()>,
{
    validate_layer_resolution_context(context)?;
    prevalidate_subkey_enumeration_source(context, entries)?;

    let mut emitted = 0usize;

    for (index, entry) in entries.iter().enumerate() {
        let current_name =
            validate_key_component_bytes(entry.child_name.as_bytes(), context.limits)?;
        if child_name_seen_before(context, entries, index, current_name)? {
            continue;
        }

        let mut best: Option<NamedPathCandidate<'a>> = None;
        let mut duplicate_best = false;

        for candidate_entry in entries {
            let candidate_name = validate_key_component_bytes(
                candidate_entry.child_name.as_bytes(),
                context.limits,
            )?;
            if !casefold_eq(candidate_name, current_name) {
                continue;
            }

            let Some(layer) = active_layer_for_source_entry(context, candidate_entry.entry.layer)?
            else {
                continue;
            };
            validate_sequence(context, candidate_entry.entry.sequence)?;
            let target = validate_path_target(candidate_entry.entry.target)?;

            let candidate = NamedPathCandidate {
                name: candidate_name,
                layer,
                sequence: candidate_entry.entry.sequence,
                target,
            };
            update_best_named_path(&mut best, &mut duplicate_best, candidate);
        }

        let Some(best) = best else {
            continue;
        };
        reject_duplicate_winning_tie(duplicate_best, best.layer.precedence, best.sequence)?;

        if let PathTarget::Guid(guid) = best.target {
            emit(EnumeratedSubkey {
                child_name: best.name,
                path: ResolvedPathEntry {
                    guid,
                    layer: best.layer.name,
                    precedence: best.layer.precedence,
                    sequence: best.sequence,
                },
            })?;
            emitted += 1;
        }
    }

    Ok(emitted)
}

fn active_layer_for_source_entry<'a>(
    context: &LayerResolutionContext<'a>,
    source_layer: &'a str,
) -> LcsResult<Option<ActiveLayer<'a>>> {
    validate_layer_name_bytes(source_layer.as_bytes(), context.limits)?;

    let mut matched = None;
    for layer in context.layers {
        validate_layer_name_bytes(layer.name.as_bytes(), context.limits)?;
        if casefold_eq(layer.name, source_layer) {
            if matched.is_some() {
                return Err(LcsError::DuplicateLayerIdentity);
            }
            matched = Some(*layer);
        }
    }

    let Some(layer) = matched else {
        return Ok(None);
    };
    if !layer.enabled && !private_layer_attached(context, layer.name)? {
        return Ok(None);
    }

    Ok(Some(ActiveLayer {
        name: layer.name,
        precedence: layer.precedence,
    }))
}

fn private_layer_attached(
    context: &LayerResolutionContext<'_>,
    layer_name: &str,
) -> LcsResult<bool> {
    for private_layer in context.private_layers {
        validate_layer_name_bytes(private_layer.as_bytes(), context.limits)?;
        if casefold_eq(private_layer, layer_name) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn prevalidate_value_enumeration_source<'a>(
    context: &LayerResolutionContext<'a>,
    entries: &'a [NamedValueEntry<'a>],
    blankets: &'a [BlanketTombstoneEntry<'a>],
) -> LcsResult<()> {
    for entry in entries {
        validate_value_name_bytes(entry.name.as_bytes(), context.limits)?;
        let Some(_) = active_layer_for_source_entry(context, entry.entry.layer)? else {
            continue;
        };
        validate_sequence(context, entry.entry.sequence)?;
        validate_source_value_payload(&entry.entry)?;
    }

    for blanket in blankets {
        let Some(_) = active_layer_for_source_entry(context, blanket.layer)? else {
            continue;
        };
        validate_sequence(context, blanket.sequence)?;
    }

    Ok(())
}

fn prevalidate_subkey_enumeration_source<'a>(
    context: &LayerResolutionContext<'a>,
    entries: &'a [NamedPathEntry<'a>],
) -> LcsResult<()> {
    for entry in entries {
        validate_key_component_bytes(entry.child_name.as_bytes(), context.limits)?;
        let Some(_) = active_layer_for_source_entry(context, entry.entry.layer)? else {
            continue;
        };
        validate_sequence(context, entry.entry.sequence)?;
        validate_path_target(entry.entry.target)?;
    }

    Ok(())
}

fn value_name_seen_before<'a>(
    context: &LayerResolutionContext<'_>,
    entries: &'a [NamedValueEntry<'a>],
    index: usize,
    current_name: &str,
) -> LcsResult<bool> {
    for previous in &entries[..index] {
        let previous_name = validate_value_name_bytes(previous.name.as_bytes(), context.limits)?;
        if casefold_eq(previous_name, current_name) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn child_name_seen_before<'a>(
    context: &LayerResolutionContext<'_>,
    entries: &'a [NamedPathEntry<'a>],
    index: usize,
    current_name: &str,
) -> LcsResult<bool> {
    for previous in &entries[..index] {
        let previous_name =
            validate_key_component_bytes(previous.child_name.as_bytes(), context.limits)?;
        if casefold_eq(previous_name, current_name) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn validate_sequence(context: &LayerResolutionContext<'_>, sequence: u64) -> LcsResult<()> {
    if sequence >= context.next_sequence {
        return Err(LcsError::FutureSequence {
            sequence,
            next_sequence: context.next_sequence,
        });
    }
    Ok(())
}

fn validate_source_value_payload<'a>(
    entry: &'a ValueEntry<'a>,
) -> LcsResult<ValueCandidatePayload<'a>> {
    match validate_value_write_type(
        entry.value_type,
        entry.data.len(),
        entry.value_type == REG_TOMBSTONE,
    )? {
        ValidatedValueType::Normal(value_type) => Ok(ValueCandidatePayload::Value {
            value_type,
            data: entry.data,
        }),
        ValidatedValueType::Tombstone => Ok(ValueCandidatePayload::Tombstone),
    }
}

fn update_best_path<'a>(
    best: &mut Option<PathCandidate<'a>>,
    duplicate_best: &mut bool,
    candidate: PathCandidate<'a>,
) {
    match compare_candidate_tuple(
        best.map(|item| (item.layer.precedence, item.sequence)),
        candidate.layer.precedence,
        candidate.sequence,
    ) {
        CandidateOrdering::First => {}
        CandidateOrdering::Second => {
            *best = Some(candidate);
            *duplicate_best = false;
        }
        CandidateOrdering::Tie => {
            *duplicate_best = true;
        }
    }
}

fn update_best_value<'a>(
    best: &mut Option<ValueCandidate<'a>>,
    duplicate_best: &mut bool,
    candidate: ValueCandidate<'a>,
) {
    match compare_candidate_tuple(
        best.map(|item| (item.layer.precedence, item.sequence)),
        candidate.layer.precedence,
        candidate.sequence,
    ) {
        CandidateOrdering::First => {}
        CandidateOrdering::Second => {
            *best = Some(candidate);
            *duplicate_best = false;
        }
        CandidateOrdering::Tie => {
            *duplicate_best = true;
        }
    }
}

fn update_best_named_path<'a>(
    best: &mut Option<NamedPathCandidate<'a>>,
    duplicate_best: &mut bool,
    candidate: NamedPathCandidate<'a>,
) {
    match compare_candidate_tuple(
        best.map(|item| (item.layer.precedence, item.sequence)),
        candidate.layer.precedence,
        candidate.sequence,
    ) {
        CandidateOrdering::First => {}
        CandidateOrdering::Second => {
            *best = Some(candidate);
            *duplicate_best = false;
        }
        CandidateOrdering::Tie => {
            *duplicate_best = true;
        }
    }
}

fn update_best_named_value<'a>(
    best: &mut Option<NamedValueCandidate<'a>>,
    duplicate_best: &mut bool,
    candidate: NamedValueCandidate<'a>,
) {
    match compare_candidate_tuple(
        best.map(|item| (item.layer.precedence, item.sequence)),
        candidate.layer.precedence,
        candidate.sequence,
    ) {
        CandidateOrdering::First => {}
        CandidateOrdering::Second => {
            *best = Some(candidate);
            *duplicate_best = false;
        }
        CandidateOrdering::Tie => {
            *duplicate_best = true;
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CandidateOrdering {
    First,
    Second,
    Tie,
}

fn compare_candidate_tuple(
    current: Option<(u32, u64)>,
    precedence: u32,
    sequence: u64,
) -> CandidateOrdering {
    let Some((current_precedence, current_sequence)) = current else {
        return CandidateOrdering::Second;
    };

    match precedence.cmp(&current_precedence) {
        core::cmp::Ordering::Greater => CandidateOrdering::Second,
        core::cmp::Ordering::Less => CandidateOrdering::First,
        core::cmp::Ordering::Equal => match sequence.cmp(&current_sequence) {
            core::cmp::Ordering::Greater => CandidateOrdering::Second,
            core::cmp::Ordering::Less => CandidateOrdering::First,
            core::cmp::Ordering::Equal => CandidateOrdering::Tie,
        },
    }
}

fn reject_duplicate_winning_tie(
    duplicate_best: bool,
    precedence: u32,
    sequence: u64,
) -> LcsResult<()> {
    if duplicate_best {
        return Err(LcsError::DuplicateWinningSequenceTie {
            precedence,
            sequence,
        });
    }
    Ok(())
}
