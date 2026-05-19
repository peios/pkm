use crate::config::LcsLimits;
use crate::constants::{
    REG_BACKUP_BLANKET_TOMBSTONE, REG_BACKUP_HEADER, REG_BACKUP_KEY, REG_BACKUP_LAYER,
    REG_BACKUP_MAGIC, REG_BACKUP_PATH_ENTRY, REG_BACKUP_TRAILER, REG_BACKUP_VALUE,
};
use crate::error::{LcsError, LcsResult};
use crate::path::{
    validate_hive_name_bytes, validate_key_component_bytes, validate_layer_name_bytes,
};
use crate::resolution::{Guid, PathTarget, validate_path_target};
use crate::source::NIL_GUID;

pub const BACKUP_RECORD_HEADER_LEN: usize = 6;
const BACKUP_HEADER_FIXED_PAYLOAD_LEN: usize = 8 + 4 + 4 + 8 + 16 + 4;

/// Parsed common backup record header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupRecordHeader {
    pub record_type: u16,
    pub record_len: u32,
}

/// Parsed backup record frame with payload borrowed from the input frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupRecordFrame<'a> {
    pub header: BackupRecordHeader,
    pub kind: BackupRecordKind,
    pub payload: &'a [u8],
}

/// Parsed HEADER record payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupHeaderPayload<'a> {
    pub format_version: u32,
    pub min_reader_version: u32,
    pub timestamp_ns: i64,
    pub root_guid: Guid,
    pub hive_name: &'a str,
}

/// Parsed LAYER manifest record payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupLayerManifestPayload<'a> {
    pub name: &'a str,
    pub precedence: u32,
    pub enabled: bool,
    pub owner_sid: &'a [u8],
}

/// Parsed PATH_ENTRY record payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupPathEntryPayload<'a> {
    pub parent_guid: Guid,
    pub child_name: &'a str,
    pub target: PathTarget,
    pub layer_name: &'a str,
    pub sequence: u64,
}

/// Known backup record type vocabulary, preserving unknown extensions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupRecordKind {
    Header,
    LayerManifest,
    Key,
    PathEntry,
    Value,
    BlanketTombstone,
    Trailer,
    Unknown(u16),
}

impl BackupRecordKind {
    pub fn from_code(code: u16) -> Self {
        match code {
            code if code == REG_BACKUP_HEADER as u16 => Self::Header,
            code if code == REG_BACKUP_LAYER as u16 => Self::LayerManifest,
            code if code == REG_BACKUP_KEY as u16 => Self::Key,
            code if code == REG_BACKUP_PATH_ENTRY as u16 => Self::PathEntry,
            code if code == REG_BACKUP_VALUE as u16 => Self::Value,
            code if code == REG_BACKUP_BLANKET_TOMBSTONE as u16 => Self::BlanketTombstone,
            code if code == REG_BACKUP_TRAILER as u16 => Self::Trailer,
            other => Self::Unknown(other),
        }
    }

    pub fn code(self) -> u16 {
        match self {
            Self::Header => REG_BACKUP_HEADER as u16,
            Self::LayerManifest => REG_BACKUP_LAYER as u16,
            Self::Key => REG_BACKUP_KEY as u16,
            Self::PathEntry => REG_BACKUP_PATH_ENTRY as u16,
            Self::Value => REG_BACKUP_VALUE as u16,
            Self::BlanketTombstone => REG_BACKUP_BLANKET_TOMBSTONE as u16,
            Self::Trailer => REG_BACKUP_TRAILER as u16,
            Self::Unknown(code) => code,
        }
    }
}

/// Parses the common 6-byte backup record header.
pub fn parse_backup_record_header(frame: &[u8]) -> LcsResult<BackupRecordHeader> {
    if frame.len() < BACKUP_RECORD_HEADER_LEN {
        return Err(LcsError::BackupRecordHeaderTooShort { len: frame.len() });
    }

    Ok(BackupRecordHeader {
        record_type: u16::from_le_bytes([frame[0], frame[1]]),
        record_len: u32::from_le_bytes([frame[2], frame[3], frame[4], frame[5]]),
    })
}

/// Parses a complete backup record frame and returns its payload.
pub fn parse_backup_record_frame(frame: &[u8]) -> LcsResult<BackupRecordFrame<'_>> {
    let header = parse_backup_record_header(frame)?;
    validate_backup_record_len(header.record_len, frame.len())?;
    Ok(BackupRecordFrame {
        header,
        kind: BackupRecordKind::from_code(header.record_type),
        payload: &frame[BACKUP_RECORD_HEADER_LEN..],
    })
}

/// Parses and validates the HEADER payload.
pub fn parse_backup_header_payload<'a>(
    limits: &LcsLimits,
    payload: &'a [u8],
    supported_version: u32,
) -> LcsResult<BackupHeaderPayload<'a>> {
    let mut cursor = BackupPayloadCursor::new(payload);
    let magic = cursor.read_fixed(8)?;
    let mut actual_magic = [0u8; 8];
    actual_magic.copy_from_slice(magic);
    if actual_magic != REG_BACKUP_MAGIC {
        return Err(LcsError::InvalidBackupMagic {
            actual: actual_magic,
        });
    }

    let format_version = cursor.read_u32_le()?;
    let min_reader_version = cursor.read_u32_le()?;
    if min_reader_version > supported_version {
        return Err(LcsError::UnsupportedBackupMinReaderVersion {
            min_reader_version,
            supported_version,
        });
    }

    let timestamp_ns = cursor.read_i64_le()?;
    let root_guid = cursor.read_guid()?;
    let hive_name = cursor.read_length_prefixed_hive_name(limits)?;
    cursor.finish_exact(REG_BACKUP_HEADER as u16)?;

    Ok(BackupHeaderPayload {
        format_version,
        min_reader_version,
        timestamp_ns,
        root_guid,
        hive_name,
    })
}

/// Parses a complete HEADER record frame and validates the payload.
pub fn parse_backup_header_record<'a>(
    limits: &LcsLimits,
    frame: &'a [u8],
    supported_version: u32,
) -> LcsResult<BackupHeaderPayload<'a>> {
    let record = parse_backup_record_frame(frame)?;
    if record.kind != BackupRecordKind::Header {
        return Err(LcsError::BackupRecordKindMismatch {
            expected: REG_BACKUP_HEADER as u16,
            actual: record.header.record_type,
        });
    }
    parse_backup_header_payload(limits, record.payload, supported_version)
}

/// Parses and validates one LAYER manifest payload.
pub fn parse_backup_layer_manifest_payload<'a>(
    limits: &LcsLimits,
    payload: &'a [u8],
) -> LcsResult<BackupLayerManifestPayload<'a>> {
    let mut cursor = BackupPayloadCursor::new(payload);
    let name = cursor.read_length_prefixed_layer_name(limits)?;
    let precedence = cursor.read_u32_le()?;
    let enabled = cursor.read_bool("backup_layer.enabled")?;
    let owner_sid = cursor.read_length_prefixed_bytes()?;
    kacs_core::Sid::parse(owner_sid).map_err(|_| LcsError::MalformedBackupSid {
        field: "backup_layer.owner",
    })?;
    cursor.finish_exact(REG_BACKUP_LAYER as u16)?;

    Ok(BackupLayerManifestPayload {
        name,
        precedence,
        enabled,
        owner_sid,
    })
}

/// Parses a complete LAYER manifest record frame and validates the payload.
pub fn parse_backup_layer_manifest_record<'a>(
    limits: &LcsLimits,
    frame: &'a [u8],
) -> LcsResult<BackupLayerManifestPayload<'a>> {
    let record = parse_backup_record_frame(frame)?;
    if record.kind != BackupRecordKind::LayerManifest {
        return Err(LcsError::BackupRecordKindMismatch {
            expected: REG_BACKUP_LAYER as u16,
            actual: record.header.record_type,
        });
    }
    parse_backup_layer_manifest_payload(limits, record.payload)
}

/// Parses and validates one PATH_ENTRY payload.
pub fn parse_backup_path_entry_payload<'a>(
    limits: &LcsLimits,
    payload: &'a [u8],
) -> LcsResult<BackupPathEntryPayload<'a>> {
    let mut cursor = BackupPayloadCursor::new(payload);
    let parent_guid = cursor.read_guid()?;
    if parent_guid == NIL_GUID {
        return Err(LcsError::NilParentGuid);
    }
    let child_name = cursor.read_length_prefixed_key_component(limits)?;
    let child_guid = cursor.read_guid()?;
    let target = if child_guid == NIL_GUID {
        PathTarget::Hidden
    } else {
        validate_path_target(PathTarget::Guid(child_guid))?
    };
    let layer_name = cursor.read_length_prefixed_layer_name(limits)?;
    let sequence = cursor.read_u64_le()?;
    cursor.finish_exact(REG_BACKUP_PATH_ENTRY as u16)?;

    Ok(BackupPathEntryPayload {
        parent_guid,
        child_name,
        target,
        layer_name,
        sequence,
    })
}

/// Parses a complete PATH_ENTRY record frame and validates the payload.
pub fn parse_backup_path_entry_record<'a>(
    limits: &LcsLimits,
    frame: &'a [u8],
) -> LcsResult<BackupPathEntryPayload<'a>> {
    let record = parse_backup_record_frame(frame)?;
    if record.kind != BackupRecordKind::PathEntry {
        return Err(LcsError::BackupRecordKindMismatch {
            expected: REG_BACKUP_PATH_ENTRY as u16,
            actual: record.header.record_type,
        });
    }
    parse_backup_path_entry_payload(limits, record.payload)
}

/// Writes the common backup record header into a caller-provided buffer.
pub fn write_backup_record_header(
    dst: &mut [u8],
    record_type: u16,
    record_len: u32,
) -> LcsResult<()> {
    if dst.len() < BACKUP_RECORD_HEADER_LEN {
        return Err(LcsError::BackupRecordHeaderBufferTooSmall { len: dst.len() });
    }
    if record_len < BACKUP_RECORD_HEADER_LEN as u32 {
        return Err(LcsError::BackupRecordTooSmall { record_len });
    }

    dst[..2].copy_from_slice(&record_type.to_le_bytes());
    dst[2..6].copy_from_slice(&record_len.to_le_bytes());
    Ok(())
}

/// Writes a complete HEADER record frame into a caller-provided buffer.
pub fn write_backup_header_record_frame(
    limits: &LcsLimits,
    dst: &mut [u8],
    format_version: u32,
    min_reader_version: u32,
    timestamp_ns: i64,
    root_guid: Guid,
    hive_name: &str,
) -> LcsResult<usize> {
    let hive_name = validate_hive_name_bytes(hive_name.as_bytes(), limits)?;
    let payload_len = checked_add_len(BACKUP_HEADER_FIXED_PAYLOAD_LEN, hive_name.len())?;
    let total_len = checked_add_len(BACKUP_RECORD_HEADER_LEN, payload_len)?;
    let record_len = u32::try_from(total_len).map_err(|_| LcsError::BackupPayloadLengthOverflow)?;
    if dst.len() < total_len {
        return Err(LcsError::BackupRecordFrameBufferTooSmall {
            len: dst.len(),
            required: total_len,
        });
    }

    write_backup_record_header(
        &mut dst[..BACKUP_RECORD_HEADER_LEN],
        REG_BACKUP_HEADER as u16,
        record_len,
    )?;
    let payload = &mut dst[BACKUP_RECORD_HEADER_LEN..total_len];
    let mut offset = 0usize;
    write_fixed(payload, &mut offset, &REG_BACKUP_MAGIC);
    write_fixed(payload, &mut offset, &format_version.to_le_bytes());
    write_fixed(payload, &mut offset, &min_reader_version.to_le_bytes());
    write_fixed(payload, &mut offset, &timestamp_ns.to_le_bytes());
    write_fixed(payload, &mut offset, &root_guid);
    write_fixed(
        payload,
        &mut offset,
        &(hive_name.len() as u32).to_le_bytes(),
    );
    write_fixed(payload, &mut offset, hive_name.as_bytes());

    Ok(total_len)
}

/// Writes a complete LAYER manifest record frame into a caller-provided buffer.
pub fn write_backup_layer_manifest_record_frame(
    limits: &LcsLimits,
    dst: &mut [u8],
    name: &str,
    precedence: u32,
    enabled: bool,
    owner_sid: &[u8],
) -> LcsResult<usize> {
    let name = validate_layer_name_bytes(name.as_bytes(), limits)?;
    kacs_core::Sid::parse(owner_sid).map_err(|_| LcsError::MalformedBackupSid {
        field: "backup_layer.owner",
    })?;
    let payload_len = checked_add_len(4, name.len())?;
    let payload_len = checked_add_len(payload_len, 4 + 1 + 4)?;
    let payload_len = checked_add_len(payload_len, owner_sid.len())?;
    let total_len = checked_add_len(BACKUP_RECORD_HEADER_LEN, payload_len)?;
    let record_len = u32::try_from(total_len).map_err(|_| LcsError::BackupPayloadLengthOverflow)?;
    if dst.len() < total_len {
        return Err(LcsError::BackupRecordFrameBufferTooSmall {
            len: dst.len(),
            required: total_len,
        });
    }

    write_backup_record_header(
        &mut dst[..BACKUP_RECORD_HEADER_LEN],
        REG_BACKUP_LAYER as u16,
        record_len,
    )?;
    let payload = &mut dst[BACKUP_RECORD_HEADER_LEN..total_len];
    let mut offset = 0usize;
    write_fixed(payload, &mut offset, &(name.len() as u32).to_le_bytes());
    write_fixed(payload, &mut offset, name.as_bytes());
    write_fixed(payload, &mut offset, &precedence.to_le_bytes());
    write_fixed(payload, &mut offset, &[u8::from(enabled)]);
    write_fixed(
        payload,
        &mut offset,
        &(owner_sid.len() as u32).to_le_bytes(),
    );
    write_fixed(payload, &mut offset, owner_sid);

    Ok(total_len)
}

/// Writes a complete PATH_ENTRY record frame into a caller-provided buffer.
pub fn write_backup_path_entry_record_frame(
    limits: &LcsLimits,
    dst: &mut [u8],
    parent_guid: Guid,
    child_name: &str,
    target: PathTarget,
    layer_name: &str,
    sequence: u64,
) -> LcsResult<usize> {
    if parent_guid == NIL_GUID {
        return Err(LcsError::NilParentGuid);
    }
    let child_name = validate_key_component_bytes(child_name.as_bytes(), limits)?;
    let target = validate_path_target(target)?;
    let layer_name = validate_layer_name_bytes(layer_name.as_bytes(), limits)?;
    let payload_len = checked_add_len(16, 4 + child_name.len())?;
    let payload_len = checked_add_len(payload_len, 16)?;
    let payload_len = checked_add_len(payload_len, 4 + layer_name.len())?;
    let payload_len = checked_add_len(payload_len, 8)?;
    let total_len = checked_add_len(BACKUP_RECORD_HEADER_LEN, payload_len)?;
    let record_len = u32::try_from(total_len).map_err(|_| LcsError::BackupPayloadLengthOverflow)?;
    if dst.len() < total_len {
        return Err(LcsError::BackupRecordFrameBufferTooSmall {
            len: dst.len(),
            required: total_len,
        });
    }

    write_backup_record_header(
        &mut dst[..BACKUP_RECORD_HEADER_LEN],
        REG_BACKUP_PATH_ENTRY as u16,
        record_len,
    )?;
    let payload = &mut dst[BACKUP_RECORD_HEADER_LEN..total_len];
    let mut offset = 0usize;
    write_fixed(payload, &mut offset, &parent_guid);
    write_fixed(
        payload,
        &mut offset,
        &(child_name.len() as u32).to_le_bytes(),
    );
    write_fixed(payload, &mut offset, child_name.as_bytes());
    let child_guid = match target {
        PathTarget::Guid(guid) => guid,
        PathTarget::Hidden => NIL_GUID,
    };
    write_fixed(payload, &mut offset, &child_guid);
    write_fixed(
        payload,
        &mut offset,
        &(layer_name.len() as u32).to_le_bytes(),
    );
    write_fixed(payload, &mut offset, layer_name.as_bytes());
    write_fixed(payload, &mut offset, &sequence.to_le_bytes());

    Ok(total_len)
}

fn validate_backup_record_len(record_len: u32, actual_len: usize) -> LcsResult<()> {
    if record_len < BACKUP_RECORD_HEADER_LEN as u32 {
        return Err(LcsError::BackupRecordTooSmall { record_len });
    }
    if record_len as usize != actual_len {
        return Err(LcsError::BackupRecordLengthMismatch {
            record_len,
            actual_len,
        });
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BackupPayloadCursor<'a> {
    payload: &'a [u8],
    offset: usize,
}

impl<'a> BackupPayloadCursor<'a> {
    const fn new(payload: &'a [u8]) -> Self {
        Self { payload, offset: 0 }
    }

    fn read_fixed(&mut self, len: usize) -> LcsResult<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(LcsError::BackupPayloadLengthOverflow)?;
        if end > self.payload.len() {
            return Err(LcsError::BackupPayloadTooShort {
                len: self.payload.len(),
                min: end,
            });
        }
        let data = &self.payload[self.offset..end];
        self.offset = end;
        Ok(data)
    }

    fn read_u32_le(&mut self) -> LcsResult<u32> {
        let bytes = self.read_fixed(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_u64_le(&mut self) -> LcsResult<u64> {
        let bytes = self.read_fixed(8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn read_u8(&mut self) -> LcsResult<u8> {
        Ok(self.read_fixed(1)?[0])
    }

    fn read_bool(&mut self, field: &'static str) -> LcsResult<bool> {
        match self.read_u8()? {
            0 => Ok(false),
            1 => Ok(true),
            value => Err(LcsError::InvalidBooleanFlag { field, value }),
        }
    }

    fn read_i64_le(&mut self) -> LcsResult<i64> {
        let bytes = self.read_fixed(8)?;
        Ok(i64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn read_guid(&mut self) -> LcsResult<Guid> {
        let bytes = self.read_fixed(16)?;
        let mut guid = [0u8; 16];
        guid.copy_from_slice(bytes);
        Ok(guid)
    }

    fn read_length_prefixed_hive_name(&mut self, limits: &LcsLimits) -> LcsResult<&'a str> {
        let len = self.read_u32_le()?;
        let bytes = self.read_fixed(len as usize)?;
        validate_hive_name_bytes(bytes, limits)
    }

    fn read_length_prefixed_key_component(&mut self, limits: &LcsLimits) -> LcsResult<&'a str> {
        let len = self.read_u32_le()?;
        let bytes = self.read_fixed(len as usize)?;
        validate_key_component_bytes(bytes, limits)
    }

    fn read_length_prefixed_layer_name(&mut self, limits: &LcsLimits) -> LcsResult<&'a str> {
        let len = self.read_u32_le()?;
        let bytes = self.read_fixed(len as usize)?;
        validate_layer_name_bytes(bytes, limits)
    }

    fn read_length_prefixed_bytes(&mut self) -> LcsResult<&'a [u8]> {
        let len = self.read_u32_le()?;
        self.read_fixed(len as usize)
    }

    fn finish_exact(&self, record_type: u16) -> LcsResult<()> {
        let extra_len = self.payload.len() - self.offset;
        if extra_len != 0 {
            return Err(LcsError::BackupUnexpectedPayload {
                record_type,
                extra_len,
            });
        }
        Ok(())
    }
}

fn checked_add_len(a: usize, b: usize) -> LcsResult<usize> {
    a.checked_add(b)
        .ok_or(LcsError::BackupPayloadLengthOverflow)
}

fn write_fixed(dst: &mut [u8], offset: &mut usize, bytes: &[u8]) {
    let end = *offset + bytes.len();
    dst[*offset..end].copy_from_slice(bytes);
    *offset = end;
}
