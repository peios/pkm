use crate::config::LcsLimits;
use crate::error::{LcsError, LcsResult};

/// External kernel resource limits relevant to PSD-005 registry memory bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistryMemoryBoundInputs {
    pub rlimit_nofile: usize,
    pub blocked_registry_threads: usize,
}

/// Explicit decomposition of the PSD-005 registry memory-bounding model.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistryMemoryBoundPlan {
    pub watch_queue_event_bound: usize,
    pub key_fd_state_bound: usize,
    pub key_fd_ancestor_entry_bound: usize,
    pub layer_table_entry_bound: usize,
    pub per_value_resolution_layer_bound: usize,
    pub pending_rsi_request_thread_bound: usize,
    pub per_source_in_flight_request_gate: usize,
    pub registry_specific_global_cap_required: bool,
}

/// Plans the configured and Linux-resource bounds that constrain registry memory.
pub fn plan_registry_memory_bounds(
    limits: &LcsLimits,
    inputs: RegistryMemoryBoundInputs,
) -> LcsResult<RegistryMemoryBoundPlan> {
    Ok(RegistryMemoryBoundPlan {
        watch_queue_event_bound: checked_mul_bound(
            "watch_queue_event_bound",
            limits.notification_queue_size,
            inputs.rlimit_nofile,
        )?,
        key_fd_state_bound: inputs.rlimit_nofile,
        key_fd_ancestor_entry_bound: checked_mul_bound(
            "key_fd_ancestor_entry_bound",
            inputs.rlimit_nofile,
            limits.max_key_depth,
        )?,
        layer_table_entry_bound: limits.max_total_layers,
        per_value_resolution_layer_bound: limits.max_layers_per_value,
        pending_rsi_request_thread_bound: inputs.blocked_registry_threads,
        per_source_in_flight_request_gate: limits.max_concurrent_rsi_requests,
        registry_specific_global_cap_required: false,
    })
}

fn checked_mul_bound(field: &'static str, lhs: usize, rhs: usize) -> LcsResult<usize> {
    lhs.checked_mul(rhs)
        .ok_or(LcsError::MemoryBoundOverflow { field })
}
