use lcs_core::{
    LcsError, REG_WATCH_OVERFLOW, REG_WATCH_SD_CHANGED, REG_WATCH_SUBKEY_CREATED,
    REG_WATCH_VALUE_SET, WatchEventRecordRequest, WatchEventRecordWritePlan,
    write_watch_event_record,
};

fn extend_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn extend_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

#[test]
fn direct_watch_event_serializes_exact_psd_005_layout() {
    let request = WatchEventRecordRequest {
        event_type: REG_WATCH_VALUE_SET,
        name: "Value",
        subtree: false,
        path_components: &[],
    };
    let mut output = [0u8; 13];
    let mut expected = Vec::new();
    extend_u32(&mut expected, 13);
    extend_u16(&mut expected, REG_WATCH_VALUE_SET as u16);
    extend_u16(&mut expected, 5);
    expected.extend_from_slice(b"Value");

    assert_eq!(
        write_watch_event_record(&request, &mut output),
        Ok(WatchEventRecordWritePlan::Written { bytes: 13 })
    );
    assert_eq!(output.as_slice(), expected.as_slice());
}

#[test]
fn subtree_watch_event_serializes_depth_and_length_prefixed_components() {
    let components = ["Services", "Child"];
    let request = WatchEventRecordRequest {
        event_type: REG_WATCH_SUBKEY_CREATED,
        name: "Child",
        subtree: true,
        path_components: &components,
    };
    let mut output = [0u8; 32];
    let mut expected = Vec::new();
    extend_u32(&mut expected, 32);
    extend_u16(&mut expected, REG_WATCH_SUBKEY_CREATED as u16);
    extend_u16(&mut expected, 5);
    expected.extend_from_slice(b"Child");
    extend_u16(&mut expected, 2);
    extend_u16(&mut expected, 8);
    expected.extend_from_slice(b"Services");
    extend_u16(&mut expected, 5);
    expected.extend_from_slice(b"Child");

    assert_eq!(
        write_watch_event_record(&request, &mut output),
        Ok(WatchEventRecordWritePlan::Written { bytes: 32 })
    );
    assert_eq!(output.as_slice(), expected.as_slice());
}

#[test]
fn zero_depth_subtree_no_name_event_serializes_path_depth_only() {
    let request = WatchEventRecordRequest {
        event_type: REG_WATCH_SD_CHANGED,
        name: "",
        subtree: true,
        path_components: &[],
    };
    let mut output = [0u8; 10];
    let mut expected = Vec::new();
    extend_u32(&mut expected, 10);
    extend_u16(&mut expected, REG_WATCH_SD_CHANGED as u16);
    extend_u16(&mut expected, 0);
    extend_u16(&mut expected, 0);

    assert_eq!(
        write_watch_event_record(&request, &mut output),
        Ok(WatchEventRecordWritePlan::Written { bytes: 10 })
    );
    assert_eq!(output.as_slice(), expected.as_slice());
}

#[test]
fn unrepresentable_event_serialization_selects_overflow_without_writing_bytes() {
    let oversized_name = "x".repeat(u16::MAX as usize + 1);
    let request = WatchEventRecordRequest {
        event_type: REG_WATCH_VALUE_SET,
        name: &oversized_name,
        subtree: false,
        path_components: &[],
    };
    let mut output = [0xaa; 16];

    assert_eq!(
        write_watch_event_record(&request, &mut output),
        Ok(WatchEventRecordWritePlan::OverflowInstead)
    );
    assert_eq!(output, [0xaa; 16]);
}

#[test]
fn serialization_rejects_too_small_output_without_partial_write() {
    let request = WatchEventRecordRequest {
        event_type: REG_WATCH_VALUE_SET,
        name: "Value",
        subtree: false,
        path_components: &[],
    };
    let mut output = [0xaa; 12];

    assert_eq!(
        write_watch_event_record(&request, &mut output),
        Err(LcsError::WatchEventOutputBufferTooSmall {
            buffer_len: 12,
            required_len: 13,
        })
    );
    assert_eq!(output, [0xaa; 12]);
}

#[test]
fn overflow_event_itself_serializes_as_minimum_no_name_record() {
    let request = WatchEventRecordRequest {
        event_type: REG_WATCH_OVERFLOW,
        name: "",
        subtree: false,
        path_components: &[],
    };
    let mut output = [0u8; 8];
    let mut expected = Vec::new();
    extend_u32(&mut expected, 8);
    extend_u16(&mut expected, REG_WATCH_OVERFLOW as u16);
    extend_u16(&mut expected, 0);

    assert_eq!(
        write_watch_event_record(&request, &mut output),
        Ok(WatchEventRecordWritePlan::Written { bytes: 8 })
    );
    assert_eq!(output.as_slice(), expected.as_slice());
}
