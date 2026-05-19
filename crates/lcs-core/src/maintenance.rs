use crate::config::LcsLimits;
use crate::constants::RSI_FLUSH;
use crate::error::{LcsError, LcsResult};
use crate::hives::{HiveStatus, SourceId};
use crate::path::validate_hive_name_bytes;

/// Hive/source identity captured by a key fd.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyFdHiveView<'a> {
    pub hive_name: &'a str,
    pub source_id: SourceId,
    pub status: HiveStatus,
}

/// Source-dispatch-ready flush plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlannedFlush<'a> {
    pub source_id: SourceId,
    pub hive_name: &'a str,
    pub rsi_op_code: u16,
    pub request_payload_len: usize,
}

/// Plans `REG_IOC_FLUSH` for the hive captured on a key fd.
pub fn plan_flush_for_key_fd<'a>(
    limits: &LcsLimits,
    key_fd: &KeyFdHiveView<'a>,
) -> LcsResult<PlannedFlush<'a>> {
    let hive_name = validate_hive_name_bytes(key_fd.hive_name.as_bytes(), limits)?;
    if key_fd.status != HiveStatus::Active {
        return Err(LcsError::HiveSourceUnavailable);
    }

    Ok(PlannedFlush {
        source_id: key_fd.source_id,
        hive_name,
        rsi_op_code: RSI_FLUSH,
        request_payload_len: 4 + hive_name.len(),
    })
}
