use crate::common::{limits, system_sid};
use lcs_core::{
    Guid, LayerPublicationInput, LayerPublicationPlan, LayerView, LcsError, NIL_GUID,
    plan_layer_publication,
};

const SE_SELF_RELATIVE: u16 = 0x8000;
const METADATA_GUID: Guid = [0x5a; 16];



fn owner_only_sd() -> Vec<u8> {
    let owner = system_sid();
    let mut sd = vec![0u8; 20];
    sd[0] = 1;
    sd[2..4].copy_from_slice(&SE_SELF_RELATIVE.to_le_bytes());
    sd[4..8].copy_from_slice(&20u32.to_le_bytes());
    sd.extend_from_slice(&owner);
    sd
}

fn input<'a>(
    name: &'a str,
    metadata_key_guid: Guid,
    metadata_security_descriptor: &'a [u8],
) -> LayerPublicationInput<'a> {
    LayerPublicationInput {
        name,
        precedence: 7,
        enabled: true,
        metadata_key_guid,
        metadata_security_descriptor,
    }
}

#[test]
fn non_base_layer_publication_requires_entry_guid_and_sd_together() {
    let sd = owner_only_sd();
    let plan = plan_layer_publication(&limits(), input("role-web", METADATA_GUID, &sd)).unwrap();

    assert_eq!(
        plan,
        LayerPublicationPlan {
            view: LayerView {
                name: "role-web",
                precedence: 7,
                enabled: true,
            },
            metadata_key_guid: METADATA_GUID,
            metadata_security_descriptor: &sd,
            publish_atomically: true,
        }
    );
}

#[test]
fn layer_publication_rejects_partial_or_malformed_inputs() {
    let sd = owner_only_sd();
    assert_eq!(
        plan_layer_publication(&limits(), input("role-web", NIL_GUID, &sd)),
        Err(LcsError::NilLayerMetadataKeyGuid)
    );
    assert_eq!(
        plan_layer_publication(&limits(), input("role-web", METADATA_GUID, b"bad")),
        Err(LcsError::MalformedSecurityDescriptor {
            field: "layer_metadata.sd",
        })
    );
    assert_eq!(
        plan_layer_publication(&limits(), input("bad/layer", METADATA_GUID, &sd)),
        Err(LcsError::NameContainsSeparator {
            field: "layer_name",
        })
    );
}

#[test]
fn base_layer_does_not_use_non_base_publication_path() {
    let sd = owner_only_sd();

    assert_eq!(
        plan_layer_publication(&limits(), input("BASE", METADATA_GUID, &sd)),
        Err(LcsError::BaseLayerPublicationNotAllowed)
    );
}
