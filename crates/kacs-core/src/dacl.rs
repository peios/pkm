use crate::access_mask::{GenericMapping, GENERIC_ALL, MAXIMUM_ALLOWED, READ_CONTROL, WRITE_DAC};
use crate::ace::{
    Ace, AceKind, ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_OBJECT_ACE_TYPE, ACCESS_DENIED_ACE_TYPE,
    ACCESS_DENIED_OBJECT_ACE_TYPE, ACE_OBJECT_TYPE_PRESENT,
};
use crate::error::{KacsError, KacsResult};
use crate::security_descriptor::SecurityDescriptor;
use crate::sid::{Sid, SE_GROUP_ENABLED, SE_GROUP_USE_FOR_DENY_ONLY};
use crate::token::TokenView;

const INHERIT_ONLY_ACE: u8 = 0x08;
const OWNER_RIGHTS_SID_BYTES: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 3, 4, 0, 0, 0];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DaclEvaluation {
    pub granted: u32,
    pub decided: u32,
    pub success: bool,
}

pub fn evaluate_dacl(
    sd: &SecurityDescriptor<'_>,
    token: &TokenView<'_>,
    desired_access: u32,
    mapping: &GenericMapping,
    skip_owner_implicit: bool,
) -> KacsResult<DaclEvaluation> {
    let normalized = mapping.normalize_desired_access(desired_access)?;
    let valid_rights = mapping.map_mask(GENERIC_ALL)?;
    let relevant_mask = if normalized.maximum_allowed {
        valid_rights
    } else {
        normalized.mapped
    };

    let caller_is_owner = sd.owner().is_some_and(|owner| owner == token.user);
    let owner_rights_suppressed = sd
        .dacl()
        .map(|dacl| owner_rights_suppressed(&dacl, caller_is_owner))
        .transpose()?
        .unwrap_or(false);

    let mut decided = 0u32;
    let mut granted = 0u32;

    if caller_is_owner && !skip_owner_implicit && !owner_rights_suppressed {
        let implicit = (READ_CONTROL | WRITE_DAC) & valid_rights;
        decided |= implicit;
        granted |= implicit;
    }

    match sd.dacl() {
        None => {
            let null_grant = valid_rights & !decided;
            granted |= null_grant;
            decided |= null_grant;
        }
        Some(dacl) => {
            for ace in dacl.entries() {
                let ace = ace?;
                if (ace.ace_flags() & INHERIT_ONLY_ACE) != 0 {
                    continue;
                }

                let Some((polarity, ace_mask, ace_sid)) = project_dacl_ace(&ace, mapping)? else {
                    continue;
                };

                if !ace_matches_token(token, ace_sid, polarity, caller_is_owner) {
                    continue;
                }

                let undecided = ace_mask & relevant_mask & !decided;
                if undecided == 0 {
                    continue;
                }

                decided |= undecided;
                if polarity == AcePolarity::Allow {
                    granted |= undecided;
                }

                if !normalized.maximum_allowed && (decided & relevant_mask) == relevant_mask {
                    break;
                }
            }
        }
    }

    let specific_request = normalized.requested & !MAXIMUM_ALLOWED;
    let success = if specific_request == 0 {
        true
    } else {
        (normalized.mapped & !granted) == 0
    };
    let returned_granted = if normalized.maximum_allowed {
        granted
    } else {
        granted & normalized.mapped
    };

    Ok(DaclEvaluation {
        granted: returned_granted,
        decided,
        success,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AcePolarity {
    Allow,
    Deny,
}

fn owner_rights_suppressed(dacl: &crate::acl::Acl<'_>, caller_is_owner: bool) -> KacsResult<bool> {
    let _ = caller_is_owner;
    for ace in dacl.entries() {
        let ace = ace?;
        if (ace.ace_flags() & INHERIT_ONLY_ACE) != 0 {
            continue;
        }

        match ace.kind() {
            AceKind::SingleSid { sid, .. }
            | AceKind::Object { sid, .. }
            | AceKind::Callback { sid, .. }
            | AceKind::CallbackObject { sid, .. } => {
                if sid.as_bytes() == OWNER_RIGHTS_SID_BYTES {
                    match ace.ace_type() {
                        ACCESS_ALLOWED_ACE_TYPE
                        | ACCESS_DENIED_ACE_TYPE
                        | ACCESS_ALLOWED_OBJECT_ACE_TYPE
                        | ACCESS_DENIED_OBJECT_ACE_TYPE
                        | crate::ace::ACCESS_ALLOWED_CALLBACK_ACE_TYPE
                        | crate::ace::ACCESS_DENIED_CALLBACK_ACE_TYPE
                        | crate::ace::ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
                        | crate::ace::ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE => return Ok(true),
                        _ => {}
                    }
                }
            }
            AceKind::ResourceAttribute { .. } | AceKind::Opaque => {}
        }
    }

    Ok(false)
}

fn project_dacl_ace<'a>(
    ace: &'a Ace<'a>,
    mapping: &GenericMapping,
) -> KacsResult<Option<(AcePolarity, u32, Sid<'a>)>> {
    match (ace.ace_type(), ace.kind()) {
        (ACCESS_ALLOWED_ACE_TYPE, AceKind::SingleSid { mask, sid }) => {
            Ok(Some((AcePolarity::Allow, mapping.map_mask(mask)?, sid)))
        }
        (ACCESS_DENIED_ACE_TYPE, AceKind::SingleSid { mask, sid }) => {
            Ok(Some((AcePolarity::Deny, mapping.map_mask(mask)?, sid)))
        }
        (
            ACCESS_ALLOWED_OBJECT_ACE_TYPE,
            AceKind::Object {
                mask, flags, sid, ..
            },
        ) => {
            if (flags & ACE_OBJECT_TYPE_PRESENT) != 0 {
                return Err(KacsError::UnsupportedAceInDacl {
                    ace_type: ace.ace_type(),
                    reason: "object type guid scoping is out of slice 1",
                });
            }
            Ok(Some((AcePolarity::Allow, mapping.map_mask(mask)?, sid)))
        }
        (
            ACCESS_DENIED_OBJECT_ACE_TYPE,
            AceKind::Object {
                mask, flags, sid, ..
            },
        ) => {
            if (flags & ACE_OBJECT_TYPE_PRESENT) != 0 {
                return Err(KacsError::UnsupportedAceInDacl {
                    ace_type: ace.ace_type(),
                    reason: "object type guid scoping is out of slice 1",
                });
            }
            Ok(Some((AcePolarity::Deny, mapping.map_mask(mask)?, sid)))
        }
        (
            crate::ace::ACCESS_ALLOWED_CALLBACK_ACE_TYPE
            | crate::ace::ACCESS_DENIED_CALLBACK_ACE_TYPE
            | crate::ace::ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
            | crate::ace::ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE,
            _,
        ) => Err(KacsError::UnsupportedAceInDacl {
            ace_type: ace.ace_type(),
            reason: "callback ace evaluation is out of slice 1",
        }),
        _ => Ok(None),
    }
}

fn ace_matches_token(
    token: &TokenView<'_>,
    ace_sid: Sid<'_>,
    polarity: AcePolarity,
    caller_is_owner: bool,
) -> bool {
    if ace_sid == token.user {
        return match polarity {
            AcePolarity::Allow => !token.user_deny_only,
            AcePolarity::Deny => true,
        };
    }

    if caller_is_owner && ace_sid.as_bytes() == OWNER_RIGHTS_SID_BYTES {
        return true;
    }

    for group in token.groups {
        if group.sid != ace_sid {
            continue;
        }

        let enabled = (group.attributes & SE_GROUP_ENABLED) != 0;
        let deny_only = (group.attributes & SE_GROUP_USE_FOR_DENY_ONLY) != 0;
        match polarity {
            AcePolarity::Allow => {
                if enabled && !deny_only {
                    return true;
                }
            }
            AcePolarity::Deny => {
                if enabled || deny_only {
                    return true;
                }
            }
        }
    }

    false
}
