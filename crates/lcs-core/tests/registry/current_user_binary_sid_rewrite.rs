use crate::common::{limits};
use lcs_core::{
    CurrentUserRewrite, LcsError, current_user_sid_component_from_binary_sid,
    for_each_routable_path_component,
};


fn sid_bytes(authority: [u8; 6], sub_authorities: &[u32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(8 + sub_authorities.len() * 4);
    bytes.push(1);
    bytes.push(sub_authorities.len() as u8);
    bytes.extend_from_slice(&authority);
    for sub_authority in sub_authorities {
        bytes.extend_from_slice(&sub_authority.to_le_bytes());
    }
    bytes
}

#[test]
fn binary_user_sid_component_feeds_initial_current_user_rewrite() {
    let limits = limits();
    let user_sid = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 32, 544]);
    let sid_component = current_user_sid_component_from_binary_sid(&limits, &user_sid).unwrap();
    let mut components = Vec::<&str>::new();

    let count = for_each_routable_path_component(
        &limits,
        "CurrentUser\\Software\\Policy",
        CurrentUserRewrite::InitialCallerPath {
            user_sid_component: sid_component.as_str(),
        },
        |component| {
            components.push(component);
            Ok(())
        },
    )
    .unwrap();

    assert_eq!(sid_component.as_str(), "S-1-5-21-32-544");
    assert_eq!(count, 4);
    assert_eq!(
        components,
        ["Users", "S-1-5-21-32-544", "Software", "Policy"]
    );
}

#[test]
fn malformed_binary_user_sid_fails_before_current_user_rewrite() {
    let limits = limits();

    assert_eq!(
        current_user_sid_component_from_binary_sid(&limits, &[1, 1, 0, 0]),
        Err(LcsError::MalformedTokenSid {
            field: "current_user_sid"
        })
    );
}

#[test]
fn textual_user_sid_component_obeys_key_component_length_limit() {
    let mut limits = limits();
    limits.max_path_component_length = "S-1-5-21-32".len();
    let user_sid = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 32, 544]);

    assert_eq!(
        current_user_sid_component_from_binary_sid(&limits, &user_sid),
        Err(LcsError::NameTooLong {
            field: "key_component",
            len: "S-1-5-21-32-544".len(),
            max: "S-1-5-21-32".len(),
        })
    );
}

#[test]
fn literal_current_user_target_does_not_need_or_consume_user_sid_component() {
    let limits = limits();
    let mut components = Vec::<&str>::new();

    let count = for_each_routable_path_component(
        &limits,
        "CurrentUser\\Software",
        CurrentUserRewrite::Literal,
        |component| {
            components.push(component);
            Ok(())
        },
    )
    .unwrap();

    assert_eq!(count, 2);
    assert_eq!(components, ["CurrentUser", "Software"]);
}
