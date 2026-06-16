use lcs_core::{
    LayerOwnerSelection, LayerOwnerSelectionInput, LayerOwnerSource, LcsError, select_layer_owner,
};

const SE_SELF_RELATIVE: u16 = 0x8000;

fn sid(rid: u32) -> Vec<u8> {
    let mut sid = Vec::new();
    sid.push(1);
    sid.push(1);
    sid.extend_from_slice(&[0, 0, 0, 0, 0, 5]);
    sid.extend_from_slice(&rid.to_le_bytes());
    sid
}

fn owner_only_sd(owner: &[u8]) -> Vec<u8> {
    let mut sd = vec![0u8; 20];
    sd[0] = 1;
    sd[2..4].copy_from_slice(&SE_SELF_RELATIVE.to_le_bytes());
    sd[4..8].copy_from_slice(&20u32.to_le_bytes());
    sd.extend_from_slice(owner);
    sd
}

fn input<'a>(
    metadata_owner_sid: Option<&'a [u8]>,
    creator_sid: Option<&'a [u8]>,
    previous_known_good_owner_sid: Option<&'a [u8]>,
    metadata_security_descriptor: Option<&'a [u8]>,
    is_new_layer: bool,
) -> LayerOwnerSelectionInput<'a> {
    LayerOwnerSelectionInput {
        metadata_owner_sid,
        creator_sid,
        previous_known_good_owner_sid,
        metadata_security_descriptor,
        is_new_layer,
    }
}

#[test]
fn present_owner_metadata_wins_and_remains_informational() {
    let metadata_owner = sid(18);
    let creator = sid(19);
    let previous = sid(20);
    let sd_owner = sid(21);
    let sd = owner_only_sd(&sd_owner);

    assert_eq!(
        select_layer_owner(input(
            Some(&metadata_owner),
            Some(&creator),
            Some(&previous),
            Some(&sd),
            true,
        )),
        Ok(LayerOwnerSelection {
            owner_sid: &metadata_owner,
            source: LayerOwnerSource::MetadataValue,
            informational_only: true,
        })
    );
}

#[test]
fn missing_new_layer_owner_uses_creator_sid() {
    let creator = sid(19);

    assert_eq!(
        select_layer_owner(input(None, Some(&creator), None, None, true)),
        Ok(LayerOwnerSelection {
            owner_sid: &creator,
            source: LayerOwnerSource::CreatorToken,
            informational_only: true,
        })
    );
}

#[test]
fn missing_refresh_owner_prefers_previous_known_good_before_sd_owner() {
    let previous = sid(20);
    let sd_owner = sid(21);
    let sd = owner_only_sd(&sd_owner);

    assert_eq!(
        select_layer_owner(input(None, None, Some(&previous), Some(&sd), false)),
        Ok(LayerOwnerSelection {
            owner_sid: &previous,
            source: LayerOwnerSource::PreviousKnownGood,
            informational_only: true,
        })
    );
}

#[test]
fn missing_refresh_owner_can_fallback_to_metadata_sd_owner() {
    let sd_owner = sid(21);
    let sd = owner_only_sd(&sd_owner);

    assert_eq!(
        select_layer_owner(input(None, None, None, Some(&sd), false)),
        Ok(LayerOwnerSelection {
            owner_sid: &sd_owner,
            source: LayerOwnerSource::MetadataSecurityDescriptorOwner,
            informational_only: true,
        })
    );
}

#[test]
fn owner_selection_fails_closed_when_selected_sid_or_fallback_is_unavailable() {
    assert_eq!(
        select_layer_owner(input(Some(b"bad"), None, None, None, false)),
        Err(LcsError::MalformedLayerOwnerSid)
    );
    assert_eq!(
        select_layer_owner(input(None, None, None, None, true)),
        Err(LcsError::LayerOwnerUnavailable)
    );
    assert_eq!(
        select_layer_owner(input(None, None, None, Some(b"bad-sd"), false)),
        Err(LcsError::MalformedSecurityDescriptor {
            field: "layer_metadata.sd",
        })
    );
}
