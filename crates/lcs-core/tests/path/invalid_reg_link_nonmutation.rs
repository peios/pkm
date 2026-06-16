use lcs_core::{
    RegistryValueType, SymlinkDefaultValue, SymlinkDefaultValueResolution, SymlinkResolutionErrno,
    classify_symlink_default_value_resolution,
};

fn classify(data: &[u8]) -> SymlinkDefaultValueResolution<'_> {
    classify_symlink_default_value_resolution(
        &Default::default(),
        Some(SymlinkDefaultValue {
            value_type: RegistryValueType::Link,
            data,
        }),
    )
}

#[test]
fn invalid_reg_link_encoding_maps_to_einval_without_mutating_payload() {
    let invalid_utf8 = [0xff, 0xfe];
    let before = invalid_utf8;

    assert_eq!(
        classify(&invalid_utf8),
        SymlinkDefaultValueResolution::Failed(SymlinkResolutionErrno::Einval)
    );
    assert_eq!(invalid_utf8, before);
}

#[test]
fn invalid_reg_link_path_structure_maps_to_einval_without_mutating_payload() {
    let cases: [&[u8]; 4] = [
        b"",
        b"Machine\\\\Software",
        b"Machine\\Software\\",
        b"Machine\\Soft\0ware",
    ];

    for payload in cases {
        let before = payload.to_vec();
        assert_eq!(
            classify(payload),
            SymlinkDefaultValueResolution::Failed(SymlinkResolutionErrno::Einval)
        );
        assert_eq!(payload, before.as_slice());
    }
}

#[test]
fn valid_reg_link_payload_still_returns_borrowed_target() {
    let payload = b"Machine\\Software";
    let SymlinkDefaultValueResolution::Target(target) = classify(payload) else {
        panic!("valid REG_LINK payload should resolve to target path");
    };

    assert_eq!(target.raw, "Machine\\Software");
    assert_eq!(payload, b"Machine\\Software");
}
