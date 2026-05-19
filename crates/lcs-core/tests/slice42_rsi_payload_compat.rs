use lcs_core::{LcsError, RsiLengthPrefixedField, RsiPayloadCursor, RsiTrailingOptionalFieldsPlan};

fn payload_with_length_prefixed(data: &[u8], trailing: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&[0xaa; 16]);
    payload.extend_from_slice(&(data.len() as u32).to_le_bytes());
    payload.extend_from_slice(data);
    payload.extend_from_slice(trailing);
    payload
}

#[test]
fn payload_cursor_reads_fixed_then_length_prefixed_fields_in_order() {
    let payload = payload_with_length_prefixed(b"child", &[]);
    let mut cursor = RsiPayloadCursor::new(&payload);

    assert_eq!(cursor.read_fixed(16), Ok(&[0xaa; 16][..]));
    assert_eq!(
        cursor.read_length_prefixed(),
        Ok(RsiLengthPrefixedField {
            len: 5,
            data: b"child",
        })
    );
    assert_eq!(cursor.position(), 25);
    assert_eq!(cursor.remaining_len(), 0);
}

#[test]
fn payload_cursor_rejects_truncated_length_prefix_or_data() {
    let mut short_prefix = RsiPayloadCursor::new(&[1, 2, 3]);
    assert_eq!(
        short_prefix.read_length_prefixed(),
        Err(LcsError::RsiMessageTooShort { len: 3, min: 4 })
    );

    let mut short_data = RsiPayloadCursor::new(&[5, 0, 0, 0, b'a']);
    assert_eq!(
        short_data.read_length_prefixed(),
        Err(LcsError::RsiMessageTooShort { len: 5, min: 9 })
    );
}

#[test]
fn payload_cursor_allows_sources_to_ignore_appended_optional_request_fields() {
    let payload = payload_with_length_prefixed(b"child", &[0xde, 0xad, 0xbe, 0xef]);
    let mut cursor = RsiPayloadCursor::new(&payload);

    assert_eq!(cursor.read_fixed(16), Ok(&[0xaa; 16][..]));
    assert_eq!(
        cursor.read_length_prefixed(),
        Ok(RsiLengthPrefixedField {
            len: 5,
            data: b"child",
        })
    );
    assert_eq!(
        cursor.finish_allowing_trailing_optional_fields(),
        RsiTrailingOptionalFieldsPlan {
            ignored_trailing_len: 4,
        }
    );
}

#[test]
fn payload_cursor_reports_fixed_field_truncation_at_current_position() {
    let payload = [1, 2, 3, 4, 5];
    let mut cursor = RsiPayloadCursor::new(&payload);

    assert_eq!(cursor.read_fixed(4), Ok(&[1, 2, 3, 4][..]));
    assert_eq!(
        cursor.read_fixed(2),
        Err(LcsError::RsiMessageTooShort { len: 5, min: 6 })
    );
}
