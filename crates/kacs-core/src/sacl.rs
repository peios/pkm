use crate::ace::{AceKind, SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE, SYSTEM_SCOPED_POLICY_ID_ACE_TYPE};
use crate::claims::{parse_claim_attribute_entry, ClaimAttribute};
use crate::error::KacsResult;
use crate::pkm_alloc::{String, Vec};
use crate::security_descriptor::SecurityDescriptor;
use crate::sid::Sid;

const INHERIT_ONLY_ACE: u8 = 0x08;

#[cfg_attr(not(feature = "kernel"), derive(Clone))]
#[derive(Debug, Eq, PartialEq)]
pub struct SaclMetadata<'a> {
    pub resource_attributes: Vec<ClaimAttribute>,
    pub policy_sids: Vec<Sid<'a>>,
}

pub fn extract_sacl_metadata<'a>(sd: &SecurityDescriptor<'a>) -> KacsResult<SaclMetadata<'a>> {
    let Some(sacl) = sd.sacl() else {
        return Ok(SaclMetadata {
            resource_attributes: Vec::new(),
            policy_sids: Vec::new(),
        });
    };

    let mut resource_attributes = Vec::new();
    let mut resource_attribute_names = Vec::new();
    let mut policy_sids = Vec::new();

    for ace in sacl.entries() {
        let ace = ace?;
        if (ace.ace_flags() & INHERIT_ONLY_ACE) != 0 {
            continue;
        }
        match ace.ace_type() {
            SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE => {
                let AceKind::ResourceAttribute {
                    application_data, ..
                } = ace.kind()
                else {
                    continue;
                };

                let attribute = parse_claim_attribute_entry(application_data)?;
                let folded = fold_string(&attribute.name)?;
                if resource_attribute_names
                    .iter()
                    .any(|name: &String| *name == folded)
                {
                    continue;
                }
                resource_attribute_names.push(folded)?;
                resource_attributes.push(attribute)?;
            }
            SYSTEM_SCOPED_POLICY_ID_ACE_TYPE => {
                let AceKind::SingleSid { sid, .. } = ace.kind() else {
                    continue;
                };
                policy_sids.push(sid)?;
            }
            _ => {}
        }
    }

    Ok(SaclMetadata {
        resource_attributes,
        policy_sids,
    })
}

fn fold_string(value: &str) -> KacsResult<String> {
    let mut folded = String::new();
    for character in value.chars() {
        for lowered in character.to_lowercase() {
            folded.push(lowered)?;
        }
    }
    Ok(folded)
}
