use crate::access::{
    parse_registry_source_security_descriptor, validate_registry_acl_access_masks,
};
use crate::constants::{
    DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    REG_WATCH_SD_CHANGED, SACL_SECURITY_INFORMATION,
};
use crate::error::{LcsError, LcsResult};
use crate::ioctl::validate_registry_security_info;
use crate::output_buffer::{
    OutputBufferAggregate, OutputBufferCopyPlan, OutputBufferDecision, OutputBufferRequest,
    plan_output_buffer_copy, validate_output_buffer_required_size,
};
use crate::resolution::Guid;
use crate::watch::{WatchMutationContext, validate_watch_mutation_context};
use kacs_core::{
    Acl, MAX_SECURITY_DESCRIPTOR_BYTES, PkmVec, SE_DACL_AUTO_INHERIT_REQ, SE_DACL_AUTO_INHERITED,
    SE_DACL_DEFAULTED, SE_DACL_PRESENT, SE_DACL_PROTECTED, SE_DACL_TRUSTED, SE_GROUP_DEFAULTED,
    SE_OWNER_DEFAULTED, SE_RM_CONTROL_VALID, SE_SACL_AUTO_INHERIT_REQ, SE_SACL_AUTO_INHERITED,
    SE_SACL_DEFAULTED, SE_SACL_PRESENT, SE_SACL_PROTECTED, SE_SELF_RELATIVE, SE_SERVER_SECURITY,
    SecurityDescriptor, Sid,
};

const OWNER_CONTROL_MASK: u16 = SE_OWNER_DEFAULTED;
const GROUP_CONTROL_MASK: u16 = SE_GROUP_DEFAULTED;
const DACL_CONTROL_MASK: u16 = SE_DACL_PRESENT
    | SE_DACL_DEFAULTED
    | SE_DACL_AUTO_INHERIT_REQ
    | SE_DACL_AUTO_INHERITED
    | SE_DACL_PROTECTED
    | SE_DACL_TRUSTED
    | SE_SERVER_SECURITY;
const SACL_CONTROL_MASK: u16 = SE_SACL_PRESENT
    | SE_SACL_DEFAULTED
    | SE_SACL_AUTO_INHERIT_REQ
    | SE_SACL_AUTO_INHERITED
    | SE_SACL_PROTECTED;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SecurityDescriptorComponent<'a> {
    bytes: &'a [u8],
    control: u16,
}

/// Pure `REG_IOC_GET_SECURITY` payload plan.
#[derive(Debug, Eq, PartialEq)]
pub struct RegistryGetSecurityPlan {
    /// Self-relative KACS SD subset containing exactly the requested components.
    pub output_sd: PkmVec<u8>,
    /// Required output bytes for ERANGE/copyout plumbing.
    pub required_len: usize,
}

/// Required-size decision for the `REG_IOC_GET_SECURITY` SD output buffer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistryGetSecurityOutputBufferDecision {
    pub sd: OutputBufferDecision,
    pub aggregate: OutputBufferAggregate,
    pub copy_plan: OutputBufferCopyPlan,
}

/// Pure `REG_IOC_SET_SECURITY` payload plan.
#[derive(Debug, Eq, PartialEq)]
pub struct RegistrySetSecurityPlan {
    /// Self-relative KACS SD after applying the selected input components.
    pub merged_sd: PkmVec<u8>,
    /// SD writes mutate the key object directly, not a path layer.
    pub direct_key_mutation: bool,
    /// SD writes are never layer-qualified.
    pub layer_qualified: bool,
    /// SD writes update the key's last-write timestamp.
    pub updates_last_write_time: bool,
    /// Existing fds keep their cached granted masks.
    pub affects_existing_fd_grants: bool,
    /// Future opens evaluate the newly persisted SD.
    pub affects_future_opens: bool,
}

/// Visibility phase for `REG_IOC_SET_SECURITY` kernel-side effects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrySetSecurityEffectTiming {
    /// A non-transactional source write has committed.
    NonTransactionalCommitted,
    /// A transaction-enlisted source write has succeeded but the transaction has not committed.
    TransactionPending,
    /// A transaction containing this SD write has committed.
    TransactionCommitSucceeded,
    /// The transaction or source write failed or aborted before committed visibility.
    AbortedOrFailed,
}

/// Pure post-success effects for a validated `REG_IOC_SET_SECURITY` mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistrySetSecurityCommitEffects<'a> {
    pub update_hive_generation: bool,
    pub dispatch_watch_events: bool,
    pub record_transaction_mutation_log: bool,
    pub commit_visible_last_write_time_update: bool,
    pub retain_existing_fd_grants: bool,
    pub watch_mutation: Option<WatchMutationContext<'a>>,
}

/// Builds the binary KACS SD subset returned by `REG_IOC_GET_SECURITY`.
pub fn plan_registry_get_security(
    existing_sd: &[u8],
    security_info: u32,
) -> LcsResult<RegistryGetSecurityPlan> {
    validate_registry_security_info(security_info)?;
    let existing =
        parse_registry_source_security_descriptor(existing_sd, "reg_get_security.existing_sd")?;

    let output_sd = build_security_descriptor(
        "reg_get_security.output_sd",
        existing.resource_manager_control(),
        retained_rm_control(existing.control()),
        selected_sid_component(
            existing.owner(),
            existing.control(),
            OWNER_CONTROL_MASK,
            security_info,
            OWNER_SECURITY_INFORMATION,
        ),
        selected_sid_component(
            existing.group(),
            existing.control(),
            GROUP_CONTROL_MASK,
            security_info,
            GROUP_SECURITY_INFORMATION,
        ),
        selected_acl_component(
            existing.sacl(),
            existing.control(),
            SACL_CONTROL_MASK,
            security_info,
            SACL_SECURITY_INFORMATION,
        ),
        selected_acl_component(
            existing.dacl(),
            existing.control(),
            DACL_CONTROL_MASK,
            security_info,
            DACL_SECURITY_INFORMATION,
        ),
    )?;

    let required_len = output_sd.len();
    Ok(RegistryGetSecurityPlan {
        output_sd,
        required_len,
    })
}

/// Computes the GET_SECURITY SD output-buffer decision before copyout.
pub fn validate_registry_get_security_output_buffer(
    plan: &RegistryGetSecurityPlan,
    sd: OutputBufferRequest,
) -> LcsResult<RegistryGetSecurityOutputBufferDecision> {
    let sd = validate_output_buffer_required_size(sd, plan.required_len)?;
    let decisions = [sd];
    let copy_plan = plan_output_buffer_copy(&decisions);

    Ok(RegistryGetSecurityOutputBufferDecision {
        sd,
        aggregate: copy_plan.aggregate,
        copy_plan,
    })
}

/// Merges a `REG_IOC_SET_SECURITY` SD subset into an existing key SD.
pub fn plan_registry_set_security(
    existing_sd: &[u8],
    input_sd: &[u8],
    security_info: u32,
) -> LcsResult<RegistrySetSecurityPlan> {
    validate_registry_security_info(security_info)?;
    let existing =
        parse_registry_source_security_descriptor(existing_sd, "reg_set_security.existing_sd")?;
    let input =
        SecurityDescriptor::parse(input_sd).map_err(|_| LcsError::MalformedSecurityDescriptor {
            field: "reg_set_security.input_sd",
        })?;
    validate_indicated_input_acls(&input, security_info)?;

    let owner = if (security_info & OWNER_SECURITY_INFORMATION) != 0 {
        selected_required_owner_component(&input)?
    } else {
        sid_component(existing.owner(), existing.control(), OWNER_CONTROL_MASK)
    };
    let Some(owner) = owner else {
        return Err(LcsError::SecurityDescriptorMergeMissingOwner {
            field: "reg_set_security.security_info",
        });
    };

    let group = if (security_info & GROUP_SECURITY_INFORMATION) != 0 {
        sid_component(input.group(), input.control(), GROUP_CONTROL_MASK)
    } else {
        sid_component(existing.group(), existing.control(), GROUP_CONTROL_MASK)
    };
    let sacl = if (security_info & SACL_SECURITY_INFORMATION) != 0 {
        acl_component(input.sacl(), input.control(), SACL_CONTROL_MASK)
    } else {
        acl_component(existing.sacl(), existing.control(), SACL_CONTROL_MASK)
    };
    let dacl = if (security_info & DACL_SECURITY_INFORMATION) != 0 {
        acl_component(input.dacl(), input.control(), DACL_CONTROL_MASK)
    } else {
        acl_component(existing.dacl(), existing.control(), DACL_CONTROL_MASK)
    };

    let merged_sd = build_security_descriptor(
        "reg_set_security.merged_sd",
        existing.resource_manager_control(),
        retained_rm_control(existing.control()),
        Some(owner),
        group,
        sacl,
        dacl,
    )?;
    parse_registry_source_security_descriptor(merged_sd.as_slice(), "reg_set_security.merged_sd")?;

    Ok(RegistrySetSecurityPlan {
        merged_sd,
        direct_key_mutation: true,
        layer_qualified: false,
        updates_last_write_time: true,
        affects_existing_fd_grants: false,
        affects_future_opens: true,
    })
}

/// Plans generation and watch effects for a completed or transaction-staged SD write.
pub fn plan_registry_set_security_commit_effects<'a>(
    plan: &RegistrySetSecurityPlan,
    timing: RegistrySetSecurityEffectTiming,
    changed_key_guid: Guid,
    ancestor_guids: &'a [Guid],
    path_components: &'a [&'a str],
) -> LcsResult<RegistrySetSecurityCommitEffects<'a>> {
    validate_registry_set_security_plan(plan)?;

    let has_committed_visibility = matches!(
        timing,
        RegistrySetSecurityEffectTiming::NonTransactionalCommitted
            | RegistrySetSecurityEffectTiming::TransactionCommitSucceeded
    );
    let record_transaction_mutation_log =
        matches!(timing, RegistrySetSecurityEffectTiming::TransactionPending);
    let needs_watch_mutation = has_committed_visibility || record_transaction_mutation_log;

    let watch_mutation = if needs_watch_mutation {
        let mutation = WatchMutationContext {
            changed_key_guid,
            ancestor_guids,
            path_components,
            event_type: REG_WATCH_SD_CHANGED,
        };
        validate_watch_mutation_context(&mutation)?;
        Some(mutation)
    } else {
        None
    };

    Ok(RegistrySetSecurityCommitEffects {
        update_hive_generation: has_committed_visibility,
        dispatch_watch_events: has_committed_visibility,
        record_transaction_mutation_log,
        commit_visible_last_write_time_update: has_committed_visibility,
        retain_existing_fd_grants: !plan.affects_existing_fd_grants,
        watch_mutation,
    })
}

fn validate_registry_set_security_plan(plan: &RegistrySetSecurityPlan) -> LcsResult<()> {
    parse_registry_source_security_descriptor(
        plan.merged_sd.as_slice(),
        "reg_set_security.merged_sd",
    )?;
    if !plan.direct_key_mutation {
        return Err(LcsError::InvalidRegistrySetSecurityPlan {
            field: "direct_key_mutation",
        });
    }
    if plan.layer_qualified {
        return Err(LcsError::InvalidRegistrySetSecurityPlan {
            field: "layer_qualified",
        });
    }
    if !plan.updates_last_write_time {
        return Err(LcsError::InvalidRegistrySetSecurityPlan {
            field: "updates_last_write_time",
        });
    }
    if plan.affects_existing_fd_grants {
        return Err(LcsError::InvalidRegistrySetSecurityPlan {
            field: "affects_existing_fd_grants",
        });
    }
    if !plan.affects_future_opens {
        return Err(LcsError::InvalidRegistrySetSecurityPlan {
            field: "affects_future_opens",
        });
    }
    Ok(())
}

fn selected_required_owner_component<'a>(
    input: &SecurityDescriptor<'a>,
) -> LcsResult<Option<SecurityDescriptorComponent<'a>>> {
    let owner = sid_component(input.owner(), input.control(), OWNER_CONTROL_MASK);
    if owner.is_none() {
        return Err(LcsError::SecurityDescriptorMergeMissingOwner {
            field: "reg_set_security.input_sd",
        });
    }
    Ok(owner)
}

fn validate_indicated_input_acls(
    input: &SecurityDescriptor<'_>,
    security_info: u32,
) -> LcsResult<()> {
    if (security_info & DACL_SECURITY_INFORMATION) != 0 {
        if let Some(dacl) = input.dacl() {
            validate_registry_acl_access_masks(dacl, "reg_set_security.input_sd")?;
        }
    }
    if (security_info & SACL_SECURITY_INFORMATION) != 0 {
        if let Some(sacl) = input.sacl() {
            validate_registry_acl_access_masks(sacl, "reg_set_security.input_sd")?;
        }
    }

    Ok(())
}

fn selected_sid_component<'a>(
    sid: Option<Sid<'a>>,
    control: u16,
    control_mask: u16,
    security_info: u32,
    flag: u32,
) -> Option<SecurityDescriptorComponent<'a>> {
    if (security_info & flag) == 0 {
        return None;
    }
    sid_component(sid, control, control_mask)
}

fn selected_acl_component<'a>(
    acl: Option<Acl<'a>>,
    control: u16,
    control_mask: u16,
    security_info: u32,
    flag: u32,
) -> Option<SecurityDescriptorComponent<'a>> {
    if (security_info & flag) == 0 {
        return None;
    }
    acl_component(acl, control, control_mask)
}

fn sid_component<'a>(
    sid: Option<Sid<'a>>,
    control: u16,
    control_mask: u16,
) -> Option<SecurityDescriptorComponent<'a>> {
    sid.map(|sid| SecurityDescriptorComponent {
        bytes: sid.as_bytes(),
        control: control & control_mask,
    })
}

fn acl_component<'a>(
    acl: Option<Acl<'a>>,
    control: u16,
    control_mask: u16,
) -> Option<SecurityDescriptorComponent<'a>> {
    acl.map(|acl| SecurityDescriptorComponent {
        bytes: acl.bytes(),
        control: control & control_mask,
    })
}

fn retained_rm_control(control: u16) -> u16 {
    control & SE_RM_CONTROL_VALID
}

fn build_security_descriptor(
    field: &'static str,
    resource_manager_control: u8,
    base_control: u16,
    owner: Option<SecurityDescriptorComponent<'_>>,
    group: Option<SecurityDescriptorComponent<'_>>,
    sacl: Option<SecurityDescriptorComponent<'_>>,
    dacl: Option<SecurityDescriptorComponent<'_>>,
) -> LcsResult<PkmVec<u8>> {
    let mut bytes = PkmVec::with_capacity(SecurityDescriptor::HEADER_SIZE)
        .map_err(|_| LcsError::SecurityDescriptorConstructionFailed { field })?;
    for _ in 0..SecurityDescriptor::HEADER_SIZE {
        bytes
            .push(0)
            .map_err(|_| LcsError::SecurityDescriptorConstructionFailed { field })?;
    }

    let owner_offset = append_component(&mut bytes, owner, field)?;
    let group_offset = append_component(&mut bytes, group, field)?;
    let sacl_offset = append_component(&mut bytes, sacl, field)?;
    let dacl_offset = append_component(&mut bytes, dacl, field)?;

    if bytes.len() > MAX_SECURITY_DESCRIPTOR_BYTES {
        return Err(LcsError::SecurityDescriptorConstructionFailed { field });
    }

    let mut control = SE_SELF_RELATIVE | base_control;
    if let Some(owner) = owner {
        control |= owner.control;
    }
    if let Some(group) = group {
        control |= group.control;
    }
    if let Some(sacl) = sacl {
        control |= sacl.control | SE_SACL_PRESENT;
    }
    if let Some(dacl) = dacl {
        control |= dacl.control | SE_DACL_PRESENT;
    }

    bytes[0] = 1;
    bytes[1] = if (base_control & SE_RM_CONTROL_VALID) != 0 {
        resource_manager_control
    } else {
        0
    };
    write_u16_at(&mut bytes, 2, control);
    write_u32_at(&mut bytes, 4, owner_offset);
    write_u32_at(&mut bytes, 8, group_offset);
    write_u32_at(&mut bytes, 12, sacl_offset);
    write_u32_at(&mut bytes, 16, dacl_offset);

    SecurityDescriptor::parse(bytes.as_slice())
        .map_err(|_| LcsError::SecurityDescriptorConstructionFailed { field })?;
    Ok(bytes)
}

fn append_component(
    dst: &mut PkmVec<u8>,
    component: Option<SecurityDescriptorComponent<'_>>,
    field: &'static str,
) -> LcsResult<u32> {
    let Some(component) = component else {
        return Ok(0);
    };

    let offset = u32::try_from(dst.len())
        .map_err(|_| LcsError::SecurityDescriptorConstructionFailed { field })?;
    dst.extend_from_slice(component.bytes)
        .map_err(|_| LcsError::SecurityDescriptorConstructionFailed { field })?;
    Ok(offset)
}

fn write_u16_at(bytes: &mut PkmVec<u8>, offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32_at(bytes: &mut PkmVec<u8>, offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
