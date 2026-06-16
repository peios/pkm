use crate::common::{limits, system_sid};
use lcs_core::{
    BACKUP_RECORD_HEADER_LEN, BACKUP_TRAILER_CHECKSUM_LEN, Guid, PathTarget,
    REG_BACKUP_BLANKET_TOMBSTONE, REG_BACKUP_HEADER, REG_BACKUP_KEY, REG_BACKUP_LAYER,
    REG_BACKUP_PATH_ENTRY, REG_BACKUP_TRAILER, REG_BACKUP_VALUE, REG_BINARY,
    write_backup_blanket_tombstone_record_frame, write_backup_header_record_frame,
    write_backup_key_record_frame, write_backup_layer_manifest_record_frame,
    write_backup_path_entry_record_frame, write_backup_trailer_record_frame,
    write_backup_value_record_frame,
};

const SE_SELF_RELATIVE: u16 = 0x8000;
const ROOT: Guid = [0x10; 16];
const CHILD: Guid = [0x20; 16];



fn owner_only_sd() -> Vec<u8> {
    let owner = system_sid();
    let mut sd = vec![0u8; 20];
    sd[0] = 1;
    sd[2..4].copy_from_slice(&SE_SELF_RELATIVE.to_le_bytes());
    sd[4..8].copy_from_slice(&20u32.to_le_bytes());
    sd.extend_from_slice(&owner);
    sd
}

fn assert_common_header(frame: &[u8], len: usize, record_type: u16) {
    assert_eq!(&frame[0..2], &record_type.to_le_bytes());
    assert_eq!(&frame[2..6], &(len as u32).to_le_bytes());
}

#[test]
fn backup_header_layer_and_key_writers_use_little_endian_scalars() {
    let mut frame = [0u8; 256];
    let len = write_backup_header_record_frame(
        &limits(),
        &mut frame,
        0x0102_0304,
        0x0506_0708,
        0x1112_1314_1516_1718,
        ROOT,
        "Hive",
    )
    .unwrap();
    assert_common_header(&frame, len, REG_BACKUP_HEADER as u16);
    let payload = &frame[BACKUP_RECORD_HEADER_LEN..len];
    assert_eq!(&payload[8..12], &[0x04, 0x03, 0x02, 0x01]);
    assert_eq!(&payload[12..16], &[0x08, 0x07, 0x06, 0x05]);
    assert_eq!(&payload[16..24], &0x1112_1314_1516_1718i64.to_le_bytes());
    assert_eq!(&payload[40..44], &4u32.to_le_bytes());

    let owner = system_sid();
    let len = write_backup_layer_manifest_record_frame(
        &limits(),
        &mut frame,
        "Layer",
        0x2122_2324,
        true,
        &owner,
    )
    .unwrap();
    assert_common_header(&frame, len, REG_BACKUP_LAYER as u16);
    let payload = &frame[BACKUP_RECORD_HEADER_LEN..len];
    assert_eq!(&payload[0..4], &5u32.to_le_bytes());
    assert_eq!(&payload[9..13], &[0x24, 0x23, 0x22, 0x21]);
    assert_eq!(payload[13], 1);
    assert_eq!(&payload[14..18], &(owner.len() as u32).to_le_bytes());

    let sd = owner_only_sd();
    let len =
        write_backup_key_record_frame(&mut frame, CHILD, true, true, &sd, 0x3132_3334_3536_3738)
            .unwrap();
    assert_common_header(&frame, len, REG_BACKUP_KEY as u16);
    let payload = &frame[BACKUP_RECORD_HEADER_LEN..len];
    assert_eq!(&payload[16..20], &3u32.to_le_bytes());
    assert_eq!(&payload[20..24], &(sd.len() as u32).to_le_bytes());
    let last_write_offset = 24 + sd.len();
    assert_eq!(
        &payload[last_write_offset..last_write_offset + 8],
        &0x3132_3334_3536_3738i64.to_le_bytes()
    );
}

#[test]
fn backup_path_value_blanket_and_trailer_writers_use_little_endian_scalars() {
    let mut frame = [0u8; 256];
    let len = write_backup_path_entry_record_frame(
        &limits(),
        &mut frame,
        ROOT,
        "Child",
        PathTarget::Guid(CHILD),
        "Layer",
        0x4142_4344_4546_4748,
    )
    .unwrap();
    assert_common_header(&frame, len, REG_BACKUP_PATH_ENTRY as u16);
    let payload = &frame[BACKUP_RECORD_HEADER_LEN..len];
    assert_eq!(&payload[16..20], &5u32.to_le_bytes());
    assert_eq!(&payload[41..45], &5u32.to_le_bytes());
    assert_eq!(&payload[50..58], &0x4142_4344_4546_4748u64.to_le_bytes());

    let len = write_backup_value_record_frame(
        &limits(),
        &mut frame,
        CHILD,
        "Value",
        REG_BINARY,
        b"data",
        "Layer",
        0x5152_5354_5556_5758,
    )
    .unwrap();
    assert_common_header(&frame, len, REG_BACKUP_VALUE as u16);
    let payload = &frame[BACKUP_RECORD_HEADER_LEN..len];
    assert_eq!(&payload[16..20], &5u32.to_le_bytes());
    assert_eq!(&payload[25..29], &REG_BINARY.to_le_bytes());
    assert_eq!(&payload[29..33], &4u32.to_le_bytes());
    assert_eq!(&payload[37..41], &5u32.to_le_bytes());
    assert_eq!(&payload[46..54], &0x5152_5354_5556_5758u64.to_le_bytes());

    let len = write_backup_blanket_tombstone_record_frame(
        &limits(),
        &mut frame,
        CHILD,
        "Layer",
        0x6162_6364_6566_6768,
    )
    .unwrap();
    assert_common_header(&frame, len, REG_BACKUP_BLANKET_TOMBSTONE as u16);
    let payload = &frame[BACKUP_RECORD_HEADER_LEN..len];
    assert_eq!(&payload[16..20], &5u32.to_le_bytes());
    assert_eq!(&payload[25..33], &0x6162_6364_6566_6768u64.to_le_bytes());

    let checksum = [0x5a; BACKUP_TRAILER_CHECKSUM_LEN];
    let len =
        write_backup_trailer_record_frame(&mut frame, 0x7172_7374_7576_7778, checksum).unwrap();
    assert_common_header(&frame, len, REG_BACKUP_TRAILER as u16);
    let payload = &frame[BACKUP_RECORD_HEADER_LEN..len];
    assert_eq!(&payload[0..8], &0x7172_7374_7576_7778u64.to_le_bytes());
    assert_eq!(&payload[8..], checksum);
}
