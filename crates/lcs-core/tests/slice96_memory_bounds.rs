use lcs_core::{
    LcsError, LcsLimits, RegistryMemoryBoundInputs, RegistryMemoryBoundPlan,
    plan_registry_memory_bounds,
};

#[test]
fn memory_bounds_follow_psd_005_resource_model() {
    assert_eq!(
        plan_registry_memory_bounds(
            &LcsLimits::default(),
            RegistryMemoryBoundInputs {
                rlimit_nofile: 1024,
                blocked_registry_threads: 33,
            },
        ),
        Ok(RegistryMemoryBoundPlan {
            watch_queue_event_bound: 262_144,
            key_fd_state_bound: 1024,
            key_fd_ancestor_entry_bound: 524_288,
            layer_table_entry_bound: 1024,
            per_value_resolution_layer_bound: 128,
            pending_rsi_request_thread_bound: 33,
            per_source_in_flight_request_gate: 256,
            registry_specific_global_cap_required: false,
        })
    );
}

#[test]
fn memory_bounds_track_active_runtime_limits() {
    let mut limits = LcsLimits::default();
    limits.notification_queue_size = 3;
    limits.max_key_depth = 4;
    limits.max_total_layers = 5;
    limits.max_layers_per_value = 6;
    limits.max_concurrent_rsi_requests = 2;

    assert_eq!(
        plan_registry_memory_bounds(
            &limits,
            RegistryMemoryBoundInputs {
                rlimit_nofile: 7,
                blocked_registry_threads: 11,
            },
        ),
        Ok(RegistryMemoryBoundPlan {
            watch_queue_event_bound: 21,
            key_fd_state_bound: 7,
            key_fd_ancestor_entry_bound: 28,
            layer_table_entry_bound: 5,
            per_value_resolution_layer_bound: 6,
            pending_rsi_request_thread_bound: 11,
            per_source_in_flight_request_gate: 2,
            registry_specific_global_cap_required: false,
        })
    );
}

#[test]
fn memory_bounds_fail_closed_on_arithmetic_overflow() {
    let mut limits = LcsLimits::default();
    limits.notification_queue_size = 2;

    assert_eq!(
        plan_registry_memory_bounds(
            &limits,
            RegistryMemoryBoundInputs {
                rlimit_nofile: usize::MAX,
                blocked_registry_threads: 0,
            },
        ),
        Err(LcsError::MemoryBoundOverflow {
            field: "watch_queue_event_bound",
        })
    );

    limits.notification_queue_size = 1;
    limits.max_key_depth = 2;

    assert_eq!(
        plan_registry_memory_bounds(
            &limits,
            RegistryMemoryBoundInputs {
                rlimit_nofile: usize::MAX,
                blocked_registry_threads: 0,
            },
        ),
        Err(LcsError::MemoryBoundOverflow {
            field: "key_fd_ancestor_entry_bound",
        })
    );
}
