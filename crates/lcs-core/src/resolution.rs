use crate::casefold::casefold_eq;
use crate::config::LcsLimits;
use crate::constants::REG_TOMBSTONE;
use crate::error::{LcsError, LcsResult};
use crate::path::validate_layer_name_bytes;
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

/// Resolves one source-returned path-entry candidate set.
pub fn resolve_path_entry<'a>(
    context: &LayerResolutionContext<'a>,
    entries: &'a [PathEntry<'a>],
) -> LcsResult<PathResolution<'a>> {
    let mut best: Option<PathCandidate<'a>> = None;
    let mut duplicate_best = false;

    for entry in entries {
        let Some(layer) = active_layer_for_source_entry(context, entry.layer)? else {
            continue;
        };
        validate_sequence(context, entry.sequence)?;

        let candidate = PathCandidate {
            layer,
            sequence: entry.sequence,
            target: entry.target,
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

/// Resolves one source-returned value candidate set.
pub fn resolve_value<'a>(
    context: &LayerResolutionContext<'a>,
    entries: &'a [ValueEntry<'a>],
    blankets: &'a [BlanketTombstoneEntry<'a>],
) -> LcsResult<ValueResolution<'a>> {
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
