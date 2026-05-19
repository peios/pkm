use crate::casefold::casefold_eq;
use crate::config::LcsLimits;
use crate::constants::RSI_HIVE_PRIVATE;
use crate::error::{LcsError, LcsResult};
use crate::hives::{HiveScope, HiveStatus, HiveView, SourceId};
use crate::path::validate_hive_name_bytes;
use crate::resolution::Guid;
use crate::sequence::SequenceCounter;

pub const NIL_GUID: Guid = [0; 16];

/// Source connection state relevant to hive identity reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceSlotStatus {
    Active,
    Down,
}

/// One hive supplied by a source registration request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceRegistrationHive<'a> {
    pub name: &'a str,
    pub root_guid: Guid,
    pub flags: u32,
    pub scope_guid: Guid,
}

/// Complete source registration request after userspace ABI copy-in.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceRegistrationRequest<'a> {
    pub hives: &'a [SourceRegistrationHive<'a>],
    pub max_sequence: u64,
    pub caller_has_tcb: bool,
}

/// One hive identity already reserved by an Active or Down source slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegisteredHiveIdentity<'a> {
    pub name: &'a str,
    pub root_guid: Guid,
    pub scope: HiveScope,
}

/// Existing source slot snapshot used for pure registration validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceSlotView<'a> {
    pub source_id: SourceId,
    pub status: SourceSlotStatus,
    pub hives: &'a [RegisteredHiveIdentity<'a>],
}

/// Registration action selected by the validator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceRegistrationDecision {
    NewSlot,
    ResumeDownSlot(SourceId),
}

/// Validated registration plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceRegistrationPlan {
    pub decision: SourceRegistrationDecision,
    pub hive_count: usize,
    pub source_next_sequence: u64,
}

/// Validated source-device open plan before any registration ioctl is accepted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceDeviceOpenPlan {
    pub grants_source_fd: bool,
}

/// Validates `/dev/pkm_registry` open admission.
pub fn plan_source_device_open(caller_has_tcb: bool) -> LcsResult<SourceDeviceOpenPlan> {
    if !caller_has_tcb {
        return Err(LcsError::MissingTcbPrivilege);
    }
    Ok(SourceDeviceOpenPlan {
        grants_source_fd: true,
    })
}

/// Validates a REG_SRC_REGISTER request against existing source slots.
pub fn validate_source_registration(
    limits: &LcsLimits,
    existing_slots: &[SourceSlotView<'_>],
    request: &SourceRegistrationRequest<'_>,
) -> LcsResult<SourceRegistrationPlan> {
    if !request.caller_has_tcb {
        return Err(LcsError::MissingTcbPrivilege);
    }
    validate_source_registration_hives(limits, request.hives)?;
    validate_source_slots(limits, existing_slots)?;

    let source_next_sequence =
        SequenceCounter::from_highest_persisted(request.max_sequence)?.next_sequence();

    if let Some(source_id) = exact_down_slot_match(limits, existing_slots, request.hives)? {
        return Ok(SourceRegistrationPlan {
            decision: SourceRegistrationDecision::ResumeDownSlot(source_id),
            hive_count: request.hives.len(),
            source_next_sequence,
        });
    }

    reject_active_collisions(limits, existing_slots, request.hives)?;
    reject_inexact_down_slot_resume(limits, existing_slots, request.hives)?;

    if existing_slots.len() >= limits.max_registered_sources {
        return Err(LcsError::TooManyRegisteredSources {
            count: existing_slots.len() + 1,
            max: limits.max_registered_sources,
        });
    }

    Ok(SourceRegistrationPlan {
        decision: SourceRegistrationDecision::NewSlot,
        hive_count: request.hives.len(),
        source_next_sequence,
    })
}

/// Validates the kernel-owned source slot table shape before publication.
pub fn validate_source_slots(
    limits: &LcsLimits,
    existing_slots: &[SourceSlotView<'_>],
) -> LcsResult<()> {
    validate_existing_source_slots(limits, existing_slots)
}

/// Emits routeable hive views from Active and Down source slot snapshots.
pub fn for_each_source_slot_hive<'a, F>(
    limits: &LcsLimits,
    source_slots: &'a [SourceSlotView<'a>],
    mut emit: F,
) -> LcsResult<usize>
where
    F: FnMut(HiveView<'a>) -> LcsResult<()>,
{
    validate_source_slots(limits, source_slots)?;

    let mut emitted = 0usize;
    for slot in source_slots {
        let status = source_slot_hive_status(slot.status);
        for hive in slot.hives {
            emit(HiveView {
                name: hive.name,
                root_guid: hive.root_guid,
                source_id: slot.source_id,
                status,
                scope: hive.scope,
            })?;
            emitted += 1;
        }
    }
    Ok(emitted)
}

/// Maps source slot lifecycle state to published hive route status.
pub fn source_slot_hive_status(status: SourceSlotStatus) -> HiveStatus {
    match status {
        SourceSlotStatus::Active => HiveStatus::Active,
        SourceSlotStatus::Down => HiveStatus::Unavailable,
    }
}

/// Validates source-provided hive entries independent of existing slots.
pub fn validate_source_registration_hives(
    limits: &LcsLimits,
    hives: &[SourceRegistrationHive<'_>],
) -> LcsResult<()> {
    if hives.is_empty() {
        return Err(LcsError::ZeroHiveCount);
    }
    if hives.len() > limits.max_hives_per_source {
        return Err(LcsError::TooManyHives {
            count: hives.len(),
            max: limits.max_hives_per_source,
        });
    }

    for (index, hive) in hives.iter().enumerate() {
        validate_registration_hive(limits, hive)?;
        if registration_hive_seen_before(limits, hives, index, hive)? {
            return Err(LcsError::DuplicateHiveIdentity);
        }
        if root_guid_seen_before(hives, index, hive.root_guid) {
            return Err(LcsError::DuplicateHiveRootGuid);
        }
    }

    Ok(())
}

/// Converts registration flags and scope field into the effective hive scope.
pub fn source_registration_hive_scope(hive: &SourceRegistrationHive<'_>) -> LcsResult<HiveScope> {
    let unknown = hive.flags & !RSI_HIVE_PRIVATE;
    if unknown != 0 {
        return Err(LcsError::UnknownHiveFlags {
            flags: hive.flags,
            unknown,
        });
    }

    if (hive.flags & RSI_HIVE_PRIVATE) != 0 {
        return Ok(HiveScope::Private(hive.scope_guid));
    }

    if hive.scope_guid != NIL_GUID {
        return Err(LcsError::GlobalHiveHasScopeGuid);
    }
    Ok(HiveScope::Global)
}

fn validate_registration_hive(
    limits: &LcsLimits,
    hive: &SourceRegistrationHive<'_>,
) -> LcsResult<()> {
    validate_hive_name_bytes(hive.name.as_bytes(), limits)?;
    source_registration_hive_scope(hive)?;
    if hive.root_guid == NIL_GUID {
        return Err(LcsError::NilHiveRootGuid);
    }
    Ok(())
}

fn validate_existing_source_slots(
    limits: &LcsLimits,
    existing_slots: &[SourceSlotView<'_>],
) -> LcsResult<()> {
    for (slot_index, slot) in existing_slots.iter().enumerate() {
        if slot.hives.is_empty() {
            return Err(LcsError::ZeroHiveCount);
        }
        for (index, hive) in slot.hives.iter().enumerate() {
            validate_hive_name_bytes(hive.name.as_bytes(), limits)?;
            if hive.root_guid == NIL_GUID {
                return Err(LcsError::NilHiveRootGuid);
            }
            if existing_hive_seen_before(limits, slot.hives, index, hive)? {
                return Err(LcsError::DuplicateHiveIdentity);
            }
            if existing_root_guid_seen_before(slot.hives, index, hive.root_guid) {
                return Err(LcsError::DuplicateHiveRootGuid);
            }
            if existing_hive_seen_in_prior_slot(limits, existing_slots, slot_index, hive)? {
                return Err(LcsError::DuplicateHiveIdentity);
            }
            if existing_root_guid_seen_in_prior_slot(existing_slots, slot_index, hive.root_guid) {
                return Err(LcsError::DuplicateHiveRootGuid);
            }
        }
    }
    Ok(())
}

fn registration_hive_seen_before(
    limits: &LcsLimits,
    hives: &[SourceRegistrationHive<'_>],
    index: usize,
    current: &SourceRegistrationHive<'_>,
) -> LcsResult<bool> {
    let current_name = validate_hive_name_bytes(current.name.as_bytes(), limits)?;
    let current_scope = source_registration_hive_scope(current)?;
    for previous in &hives[..index] {
        let previous_name = validate_hive_name_bytes(previous.name.as_bytes(), limits)?;
        let previous_scope = source_registration_hive_scope(previous)?;
        if same_hive_namespace(previous_name, previous_scope, current_name, current_scope) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn existing_hive_seen_before(
    limits: &LcsLimits,
    hives: &[RegisteredHiveIdentity<'_>],
    index: usize,
    current: &RegisteredHiveIdentity<'_>,
) -> LcsResult<bool> {
    let current_name = validate_hive_name_bytes(current.name.as_bytes(), limits)?;
    for previous in &hives[..index] {
        let previous_name = validate_hive_name_bytes(previous.name.as_bytes(), limits)?;
        if same_hive_namespace(previous_name, previous.scope, current_name, current.scope) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn existing_hive_seen_in_prior_slot(
    limits: &LcsLimits,
    existing_slots: &[SourceSlotView<'_>],
    slot_index: usize,
    current: &RegisteredHiveIdentity<'_>,
) -> LcsResult<bool> {
    let current_name = validate_hive_name_bytes(current.name.as_bytes(), limits)?;
    for slot in &existing_slots[..slot_index] {
        for previous in slot.hives {
            let previous_name = validate_hive_name_bytes(previous.name.as_bytes(), limits)?;
            if same_hive_namespace(previous_name, previous.scope, current_name, current.scope) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn existing_root_guid_seen_in_prior_slot(
    existing_slots: &[SourceSlotView<'_>],
    slot_index: usize,
    root_guid: Guid,
) -> bool {
    existing_slots[..slot_index]
        .iter()
        .flat_map(|slot| slot.hives.iter())
        .any(|previous| previous.root_guid == root_guid)
}

fn root_guid_seen_before(
    hives: &[SourceRegistrationHive<'_>],
    index: usize,
    root_guid: Guid,
) -> bool {
    hives[..index]
        .iter()
        .any(|previous| previous.root_guid == root_guid)
}

fn existing_root_guid_seen_before(
    hives: &[RegisteredHiveIdentity<'_>],
    index: usize,
    root_guid: Guid,
) -> bool {
    hives[..index]
        .iter()
        .any(|previous| previous.root_guid == root_guid)
}

fn exact_down_slot_match(
    limits: &LcsLimits,
    existing_slots: &[SourceSlotView<'_>],
    request_hives: &[SourceRegistrationHive<'_>],
) -> LcsResult<Option<SourceId>> {
    for slot in existing_slots {
        if slot.status != SourceSlotStatus::Down || slot.hives.len() != request_hives.len() {
            continue;
        }

        let mut all_match = true;
        for existing in slot.hives {
            if !request_contains_exact_hive(limits, request_hives, existing)? {
                all_match = false;
                break;
            }
        }

        if all_match {
            return Ok(Some(slot.source_id));
        }
    }
    Ok(None)
}

fn reject_active_collisions(
    limits: &LcsLimits,
    existing_slots: &[SourceSlotView<'_>],
    request_hives: &[SourceRegistrationHive<'_>],
) -> LcsResult<()> {
    for slot in existing_slots {
        if slot.status != SourceSlotStatus::Active {
            continue;
        }
        for existing in slot.hives {
            for requested in request_hives {
                if same_requested_and_existing_namespace(limits, requested, existing)? {
                    return Err(LcsError::HiveIdentityCollision);
                }
            }
        }
    }
    Ok(())
}

fn reject_inexact_down_slot_resume(
    limits: &LcsLimits,
    existing_slots: &[SourceSlotView<'_>],
    request_hives: &[SourceRegistrationHive<'_>],
) -> LcsResult<()> {
    for slot in existing_slots {
        if slot.status != SourceSlotStatus::Down {
            continue;
        }
        for existing in slot.hives {
            for requested in request_hives {
                if !same_requested_and_existing_namespace(limits, requested, existing)? {
                    continue;
                }
                if requested.root_guid != existing.root_guid {
                    return Err(LcsError::StaleSourceHiveIdentity);
                }
                return Err(LcsError::PartialSourceResume);
            }
        }
    }
    Ok(())
}

fn request_contains_exact_hive(
    limits: &LcsLimits,
    request_hives: &[SourceRegistrationHive<'_>],
    existing: &RegisteredHiveIdentity<'_>,
) -> LcsResult<bool> {
    for requested in request_hives {
        if same_requested_and_existing_namespace(limits, requested, existing)?
            && requested.root_guid == existing.root_guid
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn same_requested_and_existing_namespace(
    limits: &LcsLimits,
    requested: &SourceRegistrationHive<'_>,
    existing: &RegisteredHiveIdentity<'_>,
) -> LcsResult<bool> {
    let requested_name = validate_hive_name_bytes(requested.name.as_bytes(), limits)?;
    let requested_scope = source_registration_hive_scope(requested)?;
    let existing_name = validate_hive_name_bytes(existing.name.as_bytes(), limits)?;
    Ok(same_hive_namespace(
        requested_name,
        requested_scope,
        existing_name,
        existing.scope,
    ))
}

fn same_hive_namespace(
    left_name: &str,
    left_scope: HiveScope,
    right_name: &str,
    right_scope: HiveScope,
) -> bool {
    left_scope == right_scope && casefold_eq(left_name, right_name)
}
