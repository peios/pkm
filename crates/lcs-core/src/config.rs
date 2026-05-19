use crate::casefold::casefold_eq;
use crate::error::{LcsError, LcsResult};

/// Ratified range for one `Machine\System\Registry\*` configuration value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigRange {
    pub name: &'static str,
    pub default: u32,
    pub min: u32,
    pub max: u32,
}

pub const REQUEST_TIMEOUT_MS: ConfigRange = ConfigRange {
    name: "RequestTimeoutMs",
    default: 30_000,
    min: 1_000,
    max: 600_000,
};
pub const TRANSACTION_TIMEOUT_MS: ConfigRange = ConfigRange {
    name: "TransactionTimeoutMs",
    default: 30_000,
    min: 1_000,
    max: 600_000,
};
pub const MAX_KEY_DEPTH: ConfigRange = ConfigRange {
    name: "MaxKeyDepth",
    default: 512,
    min: 32,
    max: 4096,
};
pub const MAX_PATH_COMPONENT_LENGTH: ConfigRange = ConfigRange {
    name: "MaxPathComponentLength",
    default: 255,
    min: 64,
    max: 1024,
};
pub const MAX_TOTAL_PATH_LENGTH: ConfigRange = ConfigRange {
    name: "MaxTotalPathLength",
    default: 16_383,
    min: 1024,
    max: 65_535,
};
pub const SYMLINK_DEPTH_LIMIT: ConfigRange = ConfigRange {
    name: "SymlinkDepthLimit",
    default: 16,
    min: 1,
    max: 64,
};
pub const MAX_VALUE_SIZE: ConfigRange = ConfigRange {
    name: "MaxValueSize",
    default: 1_048_576,
    min: 4096,
    max: 67_108_864,
};
pub const MAX_LAYERS_PER_VALUE: ConfigRange = ConfigRange {
    name: "MaxLayersPerValue",
    default: 128,
    min: 1,
    max: 1024,
};
pub const MAX_TOTAL_LAYERS: ConfigRange = ConfigRange {
    name: "MaxTotalLayers",
    default: 1024,
    min: 16,
    max: 65_536,
};
pub const MAX_BOUND_TRANSACTIONS_PER_SOURCE: ConfigRange = ConfigRange {
    name: "MaxBoundTransactionsPerSource",
    default: 16,
    min: 1,
    max: 256,
};
pub const MAX_READ_ONLY_TRANSACTIONS_PER_SOURCE: ConfigRange = ConfigRange {
    name: "MaxReadOnlyTransactionsPerSource",
    default: 16,
    min: 1,
    max: 256,
};
pub const MAX_REGISTERED_SOURCES: ConfigRange = ConfigRange {
    name: "MaxRegisteredSources",
    default: 32,
    min: 1,
    max: 256,
};
pub const MAX_HIVES_PER_SOURCE: ConfigRange = ConfigRange {
    name: "MaxHivesPerSource",
    default: 64,
    min: 1,
    max: 1024,
};
pub const MAX_CONCURRENT_RSI_REQUESTS: ConfigRange = ConfigRange {
    name: "MaxConcurrentRSIRequests",
    default: 256,
    min: 8,
    max: 4096,
};
pub const NOTIFICATION_QUEUE_SIZE: ConfigRange = ConfigRange {
    name: "NotificationQueueSize",
    default: 256,
    min: 16,
    max: 65_536,
};
pub const MAX_SUBTREE_WATCH_DEPTH: ConfigRange = ConfigRange {
    name: "MaxSubtreeWatchDepth",
    default: 0,
    min: 0,
    max: 4096,
};
pub const MAX_TRANSACTION_WATCH_EVENT_BURST: ConfigRange = ConfigRange {
    name: "MaxTransactionWatchEventBurst",
    default: 4096,
    min: 256,
    max: 65_536,
};
pub const MAX_SCOPE_GUIDS_PER_TOKEN: ConfigRange = ConfigRange {
    name: "MaxScopeGUIDsPerToken",
    default: 8,
    min: 1,
    max: 256,
};
pub const MAX_PRIVATE_LAYERS_PER_TOKEN: ConfigRange = ConfigRange {
    name: "MaxPrivateLayersPerToken",
    default: 16,
    min: 1,
    max: 256,
};

pub const LCS_CONFIG_RANGES: [ConfigRange; 19] = [
    REQUEST_TIMEOUT_MS,
    TRANSACTION_TIMEOUT_MS,
    MAX_KEY_DEPTH,
    MAX_PATH_COMPONENT_LENGTH,
    MAX_TOTAL_PATH_LENGTH,
    SYMLINK_DEPTH_LIMIT,
    MAX_VALUE_SIZE,
    MAX_LAYERS_PER_VALUE,
    MAX_TOTAL_LAYERS,
    MAX_BOUND_TRANSACTIONS_PER_SOURCE,
    MAX_READ_ONLY_TRANSACTIONS_PER_SOURCE,
    MAX_REGISTERED_SOURCES,
    MAX_HIVES_PER_SOURCE,
    MAX_CONCURRENT_RSI_REQUESTS,
    NOTIFICATION_QUEUE_SIZE,
    MAX_SUBTREE_WATCH_DEPTH,
    MAX_TRANSACTION_WATCH_EVENT_BURST,
    MAX_SCOPE_GUIDS_PER_TOKEN,
    MAX_PRIVATE_LAYERS_PER_TOKEN,
];

/// Runtime LCS limits active for one operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LcsLimits {
    pub request_timeout_ms: u32,
    pub transaction_timeout_ms: u32,
    pub max_key_depth: usize,
    pub max_path_component_length: usize,
    pub max_total_path_length: usize,
    pub symlink_depth_limit: usize,
    pub max_value_size: usize,
    pub max_layers_per_value: usize,
    pub max_total_layers: usize,
    pub max_bound_transactions_per_source: usize,
    pub max_read_only_transactions_per_source: usize,
    pub max_registered_sources: usize,
    pub max_hives_per_source: usize,
    pub max_concurrent_rsi_requests: usize,
    pub notification_queue_size: usize,
    pub max_subtree_watch_depth: usize,
    pub max_transaction_watch_event_burst: usize,
    pub max_scope_guids_per_token: usize,
    pub max_private_layers_per_token: usize,
}

impl LcsLimits {
    /// Compiled-in PSD-005 §11.4 defaults.
    pub const DEFAULT: Self = Self {
        request_timeout_ms: REQUEST_TIMEOUT_MS.default,
        transaction_timeout_ms: TRANSACTION_TIMEOUT_MS.default,
        max_key_depth: MAX_KEY_DEPTH.default as usize,
        max_path_component_length: MAX_PATH_COMPONENT_LENGTH.default as usize,
        max_total_path_length: MAX_TOTAL_PATH_LENGTH.default as usize,
        symlink_depth_limit: SYMLINK_DEPTH_LIMIT.default as usize,
        max_value_size: MAX_VALUE_SIZE.default as usize,
        max_layers_per_value: MAX_LAYERS_PER_VALUE.default as usize,
        max_total_layers: MAX_TOTAL_LAYERS.default as usize,
        max_bound_transactions_per_source: MAX_BOUND_TRANSACTIONS_PER_SOURCE.default as usize,
        max_read_only_transactions_per_source: MAX_READ_ONLY_TRANSACTIONS_PER_SOURCE.default
            as usize,
        max_registered_sources: MAX_REGISTERED_SOURCES.default as usize,
        max_hives_per_source: MAX_HIVES_PER_SOURCE.default as usize,
        max_concurrent_rsi_requests: MAX_CONCURRENT_RSI_REQUESTS.default as usize,
        notification_queue_size: NOTIFICATION_QUEUE_SIZE.default as usize,
        max_subtree_watch_depth: MAX_SUBTREE_WATCH_DEPTH.default as usize,
        max_transaction_watch_event_burst: MAX_TRANSACTION_WATCH_EVENT_BURST.default as usize,
        max_scope_guids_per_token: MAX_SCOPE_GUIDS_PER_TOKEN.default as usize,
        max_private_layers_per_token: MAX_PRIVATE_LAYERS_PER_TOKEN.default as usize,
    };
}

impl Default for LcsLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// One self-configuration value observed under `Machine\System\Registry`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SelfConfigEntry<'a> {
    pub name: &'a str,
    pub value: SelfConfigValue,
}

/// Source-side shape of a self-configuration value before validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelfConfigValue {
    Dword(u32),
    WrongType { actual_type: u32 },
}

/// Summary of applying one self-configuration snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SelfConfigPlan {
    pub limits: LcsLimits,
    pub applied_count: usize,
    pub retained_missing_count: usize,
    pub retained_invalid_count: usize,
    pub ignored_unknown_count: usize,
    pub audit_event_count: usize,
}

/// Describes why a known parameter was retained instead of hot-swapped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelfConfigRetentionReason {
    Missing,
    WrongType { actual_type: u32 },
    OutOfRange { value: u32, min: u32, max: u32 },
}

/// Audit-intent shape for a retained self-configuration value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SelfConfigAuditIntent {
    pub parameter: &'static str,
    pub retained_value: u32,
    pub reason: SelfConfigRetentionReason,
}

/// Validates a REG_DWORD self-configuration value against its ratified range.
pub fn validate_config_value(range: ConfigRange, value: u32) -> LcsResult<u32> {
    if value < range.min || value > range.max {
        return Err(LcsError::InvalidConfigValue {
            parameter: range.name,
            value,
            min: range.min,
            max: range.max,
        });
    }
    Ok(value)
}

/// Finds a known self-configuration parameter by registry value name.
pub fn find_config_range(name: &str) -> Option<ConfigRange> {
    LCS_CONFIG_RANGES
        .iter()
        .copied()
        .find(|range| casefold_eq(name, range.name))
}

/// Returns the currently retained value for a known self-configuration range.
pub fn retained_config_value(limits: &LcsLimits, range: ConfigRange) -> u32 {
    match range.name {
        "RequestTimeoutMs" => limits.request_timeout_ms,
        "TransactionTimeoutMs" => limits.transaction_timeout_ms,
        "MaxKeyDepth" => limits.max_key_depth as u32,
        "MaxPathComponentLength" => limits.max_path_component_length as u32,
        "MaxTotalPathLength" => limits.max_total_path_length as u32,
        "SymlinkDepthLimit" => limits.symlink_depth_limit as u32,
        "MaxValueSize" => limits.max_value_size as u32,
        "MaxLayersPerValue" => limits.max_layers_per_value as u32,
        "MaxTotalLayers" => limits.max_total_layers as u32,
        "MaxBoundTransactionsPerSource" => limits.max_bound_transactions_per_source as u32,
        "MaxReadOnlyTransactionsPerSource" => limits.max_read_only_transactions_per_source as u32,
        "MaxRegisteredSources" => limits.max_registered_sources as u32,
        "MaxHivesPerSource" => limits.max_hives_per_source as u32,
        "MaxConcurrentRSIRequests" => limits.max_concurrent_rsi_requests as u32,
        "NotificationQueueSize" => limits.notification_queue_size as u32,
        "MaxSubtreeWatchDepth" => limits.max_subtree_watch_depth as u32,
        "MaxTransactionWatchEventBurst" => limits.max_transaction_watch_event_burst as u32,
        "MaxScopeGUIDsPerToken" => limits.max_scope_guids_per_token as u32,
        "MaxPrivateLayersPerToken" => limits.max_private_layers_per_token as u32,
        _ => range.default,
    }
}

fn apply_config_value(limits: &mut LcsLimits, range: ConfigRange, value: u32) {
    match range.name {
        "RequestTimeoutMs" => limits.request_timeout_ms = value,
        "TransactionTimeoutMs" => limits.transaction_timeout_ms = value,
        "MaxKeyDepth" => limits.max_key_depth = value as usize,
        "MaxPathComponentLength" => limits.max_path_component_length = value as usize,
        "MaxTotalPathLength" => limits.max_total_path_length = value as usize,
        "SymlinkDepthLimit" => limits.symlink_depth_limit = value as usize,
        "MaxValueSize" => limits.max_value_size = value as usize,
        "MaxLayersPerValue" => limits.max_layers_per_value = value as usize,
        "MaxTotalLayers" => limits.max_total_layers = value as usize,
        "MaxBoundTransactionsPerSource" => {
            limits.max_bound_transactions_per_source = value as usize;
        }
        "MaxReadOnlyTransactionsPerSource" => {
            limits.max_read_only_transactions_per_source = value as usize;
        }
        "MaxRegisteredSources" => limits.max_registered_sources = value as usize,
        "MaxHivesPerSource" => limits.max_hives_per_source = value as usize,
        "MaxConcurrentRSIRequests" => limits.max_concurrent_rsi_requests = value as usize,
        "NotificationQueueSize" => limits.notification_queue_size = value as usize,
        "MaxSubtreeWatchDepth" => limits.max_subtree_watch_depth = value as usize,
        "MaxTransactionWatchEventBurst" => {
            limits.max_transaction_watch_event_burst = value as usize;
        }
        "MaxScopeGUIDsPerToken" => limits.max_scope_guids_per_token = value as usize,
        "MaxPrivateLayersPerToken" => limits.max_private_layers_per_token = value as usize,
        _ => {}
    }
}

/// Plans hot-swapping one self-configuration snapshot.
pub fn plan_self_configuration(
    current: LcsLimits,
    entries: &[SelfConfigEntry<'_>],
) -> SelfConfigPlan {
    let mut plan = SelfConfigPlan {
        limits: current,
        applied_count: 0,
        retained_missing_count: 0,
        retained_invalid_count: 0,
        ignored_unknown_count: 0,
        audit_event_count: 0,
    };

    for entry in entries {
        if find_config_range(entry.name).is_none() {
            plan.ignored_unknown_count += 1;
        }
    }

    for range in LCS_CONFIG_RANGES {
        let entry = entries
            .iter()
            .find(|entry| casefold_eq(entry.name, range.name));

        match entry.map(|entry| entry.value) {
            Some(SelfConfigValue::Dword(value)) => match validate_config_value(range, value) {
                Ok(value) => {
                    apply_config_value(&mut plan.limits, range, value);
                    plan.applied_count += 1;
                }
                Err(_) => {
                    plan.retained_invalid_count += 1;
                    plan.audit_event_count += 1;
                }
            },
            Some(SelfConfigValue::WrongType { .. }) => {
                plan.retained_invalid_count += 1;
                plan.audit_event_count += 1;
            }
            None => {
                plan.retained_missing_count += 1;
                plan.audit_event_count += 1;
            }
        }
    }

    plan
}

/// Returns the per-parameter audit intent for a retained self-config value.
pub fn self_config_audit_intent(
    current: &LcsLimits,
    range: ConfigRange,
    value: Option<SelfConfigValue>,
) -> Option<SelfConfigAuditIntent> {
    let retained_value = retained_config_value(current, range);
    match value {
        Some(SelfConfigValue::Dword(value)) => {
            validate_config_value(range, value)
                .err()
                .map(|_| SelfConfigAuditIntent {
                    parameter: range.name,
                    retained_value,
                    reason: SelfConfigRetentionReason::OutOfRange {
                        value,
                        min: range.min,
                        max: range.max,
                    },
                })
        }
        Some(SelfConfigValue::WrongType { actual_type }) => Some(SelfConfigAuditIntent {
            parameter: range.name,
            retained_value,
            reason: SelfConfigRetentionReason::WrongType { actual_type },
        }),
        None => Some(SelfConfigAuditIntent {
            parameter: range.name,
            retained_value,
            reason: SelfConfigRetentionReason::Missing,
        }),
    }
}
