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
