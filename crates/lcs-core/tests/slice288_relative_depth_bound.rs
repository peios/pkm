use lcs_core::{LcsError, LcsLimits, validate_resolved_relative_path_depth};

fn limits(max_key_depth: usize) -> LcsLimits {
    let mut limits = LcsLimits::default();
    limits.max_key_depth = max_key_depth;
    limits
}

#[test]
fn relative_depth_bound_allows_under_and_exact_limit() {
    let limits = limits(4);

    assert_eq!(validate_resolved_relative_path_depth(1, 2, &limits), Ok(3));
    assert_eq!(validate_resolved_relative_path_depth(2, 2, &limits), Ok(4));
}

#[test]
fn relative_depth_bound_rejects_exceeding_limit() {
    let limits = limits(4);

    assert_eq!(
        validate_resolved_relative_path_depth(3, 2, &limits),
        Err(LcsError::KeyDepthExceeded { depth: 5, max: 4 })
    );
}

#[test]
fn relative_depth_bound_rejects_arithmetic_overflow() {
    let limits = limits(usize::MAX - 1);

    assert_eq!(
        validate_resolved_relative_path_depth(usize::MAX, 1, &limits),
        Err(LcsError::KeyDepthExceeded {
            depth: usize::MAX,
            max: usize::MAX - 1,
        })
    );
}
