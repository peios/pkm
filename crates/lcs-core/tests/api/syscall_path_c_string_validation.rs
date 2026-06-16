use crate::common::{limits};
use lcs_core::{
    LcsError, PathKind, validate_registry_path_bytes, validate_syscall_path_c_string,
};


#[test]
fn syscall_path_c_string_strips_terminator_before_validation() {
    let summary =
        validate_syscall_path_c_string(b"Machine/System\0", PathKind::Absolute, &limits()).unwrap();

    assert_eq!(summary.raw, "Machine/System");
    assert_eq!(summary.first_component, "Machine");
    assert_eq!(summary.final_component, "System");
    assert!(summary.used_forward_separator);
}

#[test]
fn syscall_path_c_string_requires_final_terminator() {
    assert_eq!(
        validate_syscall_path_c_string(b"Machine/System", PathKind::Absolute, &limits()),
        Err(LcsError::MissingSyscallPathTerminator {
            field: "syscall_path",
        })
    );

    assert_eq!(
        validate_syscall_path_c_string(&[], PathKind::Absolute, &limits()),
        Err(LcsError::MissingSyscallPathTerminator {
            field: "syscall_path",
        })
    );
}

#[test]
fn syscall_path_c_string_rejects_interior_nulls_and_empty_paths() {
    assert_eq!(
        validate_syscall_path_c_string(b"Machine\0System\0", PathKind::Absolute, &limits()),
        Err(LcsError::NullByte { field: "path" })
    );

    assert_eq!(
        validate_syscall_path_c_string(b"\0", PathKind::Absolute, &limits()),
        Err(LcsError::EmptyPath)
    );
}

#[test]
fn syscall_path_limits_exclude_only_the_terminator_byte() {
    let mut limits = limits();
    limits.max_total_path_length = "Machine".len();
    limits.max_path_component_length = "Machine".len();

    let summary =
        validate_syscall_path_c_string(b"Machine\0", PathKind::Absolute, &limits).unwrap();
    assert_eq!(summary.raw, "Machine");

    assert_eq!(
        validate_syscall_path_c_string(b"MachineX\0", PathKind::Absolute, &limits),
        Err(LcsError::PathTooLong {
            len: "MachineX".len(),
            max: "Machine".len(),
        })
    );
}

#[test]
fn length_delimited_paths_still_reject_included_terminators() {
    assert_eq!(
        validate_registry_path_bytes(b"Machine\0", PathKind::Absolute, &limits()),
        Err(LcsError::NullByte { field: "path" })
    );

    validate_registry_path_bytes(b"Machine", PathKind::Absolute, &limits()).unwrap();
}
