use crate::constants::{
    REG_BACKUP_BLANKET_TOMBSTONE, REG_BACKUP_HEADER, REG_BACKUP_KEY, REG_BACKUP_LAYER,
    REG_BACKUP_PATH_ENTRY, REG_BACKUP_TRAILER, REG_BACKUP_VALUE,
};
use crate::error::{LcsError, LcsResult};

pub const BACKUP_RECORD_HEADER_LEN: usize = 6;

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
