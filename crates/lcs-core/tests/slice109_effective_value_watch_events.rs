use lcs_core::{
    EffectiveValueWatchEvent, EnumeratedValue, LcsError, LcsLimits, REG_DWORD, REG_SZ,
    RegistryValueType, ResolvedValueEntry, for_each_effective_value_watch_event,
};

fn value<'a>(
    name: &'a str,
    value_type: RegistryValueType,
    data: &'a [u8],
    layer: &'a str,
    precedence: u32,
    sequence: u64,
) -> EnumeratedValue<'a> {
    EnumeratedValue {
        name,
        value: ResolvedValueEntry {
            value_type,
            data,
            layer,
            precedence,
            sequence,
        },
    }
}

fn dword<'a>(name: &'a str, data: &'a [u8], layer: &'a str, sequence: u64) -> EnumeratedValue<'a> {
    value(
        name,
        RegistryValueType::from_code(REG_DWORD).unwrap(),
        data,
        layer,
        0,
        sequence,
    )
}

fn sz<'a>(name: &'a str, data: &'a [u8], layer: &'a str, sequence: u64) -> EnumeratedValue<'a> {
    value(
        name,
        RegistryValueType::from_code(REG_SZ).unwrap(),
        data,
        layer,
        0,
        sequence,
    )
}

fn collect<'a>(
    before: &'a [EnumeratedValue<'a>],
    after: &'a [EnumeratedValue<'a>],
) -> Result<(usize, Vec<EffectiveValueWatchEvent<'a>>), LcsError> {
    let mut events = Vec::new();
    let count =
        for_each_effective_value_watch_event(&LcsLimits::default(), before, after, |event| {
            events.push(event);
            Ok(())
        })?;
    Ok((count, events))
}

#[test]
fn effective_value_diff_emits_deletes_changes_and_creates() {
    let before = [
        dword("Old", &[1, 0, 0, 0], "base", 1),
        sz("Changed", b"old", "base", 2),
        dword("Stable", &[7, 0, 0, 0], "base", 3),
    ];
    let after = [
        sz("Changed", b"new", "policy", 4),
        dword("Stable", &[7, 0, 0, 0], "base", 3),
        dword("New", &[2, 0, 0, 0], "policy", 5),
    ];

    assert_eq!(
        collect(&before, &after),
        Ok((
            3,
            vec![
                EffectiveValueWatchEvent::ValueDeleted { name: "Old" },
                EffectiveValueWatchEvent::ValueSet { name: "Changed" },
                EffectiveValueWatchEvent::ValueSet { name: "New" },
            ],
        ))
    );
}

#[test]
fn blanket_tombstone_write_generates_per_value_deletes() {
    let before = [
        dword("Alpha", &[1, 0, 0, 0], "base", 1),
        sz("Beta", b"visible", "role", 2),
    ];

    assert_eq!(
        collect(&before, &[]),
        Ok((
            2,
            vec![
                EffectiveValueWatchEvent::ValueDeleted { name: "Alpha" },
                EffectiveValueWatchEvent::ValueDeleted { name: "Beta" },
            ],
        ))
    );
}

#[test]
fn blanket_tombstone_removal_generates_per_value_sets() {
    let after = [
        dword("Alpha", &[1, 0, 0, 0], "base", 1),
        sz("Beta", b"visible", "role", 2),
    ];

    assert_eq!(
        collect(&[], &after),
        Ok((
            2,
            vec![
                EffectiveValueWatchEvent::ValueSet { name: "Alpha" },
                EffectiveValueWatchEvent::ValueSet { name: "Beta" },
            ],
        ))
    );
}

#[test]
fn unchanged_caller_visible_effective_value_emits_no_event() {
    let before = [value(
        "Stable",
        RegistryValueType::from_code(REG_DWORD).unwrap(),
        &[9, 0, 0, 0],
        "policy",
        10,
        4,
    )];
    let after = [value(
        "Stable",
        RegistryValueType::from_code(REG_DWORD).unwrap(),
        &[9, 0, 0, 0],
        "policy",
        20,
        4,
    )];

    assert_eq!(collect(&before, &after), Ok((0, vec![])));
}

#[test]
fn case_only_name_change_is_a_value_set_for_the_after_spelling() {
    let before = [dword("Setting", &[1, 0, 0, 0], "base", 1)];
    let after = [dword("setting", &[1, 0, 0, 0], "base", 1)];

    assert_eq!(
        collect(&before, &after),
        Ok((
            1,
            vec![EffectiveValueWatchEvent::ValueSet { name: "setting" }],
        ))
    );
}

#[test]
fn effective_value_watch_snapshot_fails_closed_on_ambiguous_or_malformed_inputs() {
    let duplicate_before = [
        dword("Folded", &[1, 0, 0, 0], "base", 1),
        dword("folded", &[2, 0, 0, 0], "base", 2),
    ];
    assert_eq!(
        collect(&duplicate_before, &[]),
        Err(LcsError::DuplicateEffectiveWatchValueName {
            snapshot: "before",
            index: 1,
        })
    );

    let malformed_after = [dword("bad\0name", &[1, 0, 0, 0], "base", 1)];
    assert!(matches!(
        collect(&[], &malformed_after),
        Err(LcsError::NullByte {
            field: "value_name"
        })
    ));
}
