use lcs_core::{
    LCS_CONFIG_RANGES, LcsLimits, MAX_READ_ONLY_TRANSACTIONS_PER_SOURCE, REG_SZ,
    REQUEST_TIMEOUT_MS, SelfConfigEntry, SelfConfigRetentionReason, SelfConfigValue,
    find_config_range, plan_self_configuration, retained_config_value, self_config_audit_intent,
};

#[test]
fn self_config_catalogue_covers_psd_005_parameters() {
    assert_eq!(LCS_CONFIG_RANGES.len(), 19);

    let range = find_config_range("MaxReadOnlyTransactionsPerSource").unwrap();
    assert_eq!(range, MAX_READ_ONLY_TRANSACTIONS_PER_SOURCE);
    assert_eq!(range.default, 16);
    assert_eq!(range.min, 1);
    assert_eq!(range.max, 256);
}

#[test]
fn self_configuration_hot_swaps_valid_known_values_and_ignores_unknowns() {
    let entries = [
        SelfConfigEntry {
            name: "RequestTimeoutMs",
            value: SelfConfigValue::Dword(1_000),
        },
        SelfConfigEntry {
            name: "maxreadonlytransactionspersource",
            value: SelfConfigValue::Dword(32),
        },
        SelfConfigEntry {
            name: "FutureParameter",
            value: SelfConfigValue::Dword(123),
        },
    ];

    let plan = plan_self_configuration(LcsLimits::default(), &entries);

    assert_eq!(plan.applied_count, 2);
    assert_eq!(plan.ignored_unknown_count, 1);
    assert_eq!(plan.retained_missing_count, LCS_CONFIG_RANGES.len() - 2);
    assert_eq!(plan.retained_invalid_count, 0);
    assert_eq!(plan.audit_event_count, LCS_CONFIG_RANGES.len() - 2);
    assert_eq!(plan.limits.request_timeout_ms, 1_000);
    assert_eq!(plan.limits.max_read_only_transactions_per_source, 32);
}

#[test]
fn self_configuration_retains_previous_known_good_for_invalid_values() {
    let current = LcsLimits {
        request_timeout_ms: 45_000,
        max_value_size: 8192,
        ..LcsLimits::default()
    };
    let entries = [
        SelfConfigEntry {
            name: "RequestTimeoutMs",
            value: SelfConfigValue::Dword(999_999),
        },
        SelfConfigEntry {
            name: "MaxValueSize",
            value: SelfConfigValue::WrongType {
                actual_type: REG_SZ,
            },
        },
    ];

    let plan = plan_self_configuration(current, &entries);

    assert_eq!(plan.applied_count, 0);
    assert_eq!(plan.retained_invalid_count, 2);
    assert_eq!(plan.retained_missing_count, LCS_CONFIG_RANGES.len() - 2);
    assert_eq!(plan.audit_event_count, LCS_CONFIG_RANGES.len());
    assert_eq!(plan.limits.request_timeout_ms, 45_000);
    assert_eq!(plan.limits.max_value_size, 8192);
}

#[test]
fn self_config_audit_intent_identifies_key_reason_and_retained_value() {
    let current = LcsLimits {
        request_timeout_ms: 45_000,
        ..LcsLimits::default()
    };

    assert_eq!(
        self_config_audit_intent(
            &current,
            REQUEST_TIMEOUT_MS,
            Some(SelfConfigValue::Dword(999_999))
        ),
        Some(lcs_core::SelfConfigAuditIntent {
            parameter: "RequestTimeoutMs",
            retained_value: 45_000,
            reason: SelfConfigRetentionReason::OutOfRange {
                value: 999_999,
                min: 1_000,
                max: 600_000,
            },
        })
    );
    assert_eq!(
        self_config_audit_intent(
            &current,
            REQUEST_TIMEOUT_MS,
            Some(SelfConfigValue::WrongType {
                actual_type: REG_SZ,
            })
        ),
        Some(lcs_core::SelfConfigAuditIntent {
            parameter: "RequestTimeoutMs",
            retained_value: 45_000,
            reason: SelfConfigRetentionReason::WrongType {
                actual_type: REG_SZ,
            },
        })
    );
    assert_eq!(
        self_config_audit_intent(&current, REQUEST_TIMEOUT_MS, None),
        Some(lcs_core::SelfConfigAuditIntent {
            parameter: "RequestTimeoutMs",
            retained_value: 45_000,
            reason: SelfConfigRetentionReason::Missing,
        })
    );
    assert_eq!(
        self_config_audit_intent(
            &current,
            REQUEST_TIMEOUT_MS,
            Some(SelfConfigValue::Dword(60_000))
        ),
        None
    );
    assert_eq!(retained_config_value(&current, REQUEST_TIMEOUT_MS), 45_000);
}
