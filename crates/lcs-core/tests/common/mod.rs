//! Shared helpers for lcs-core integration tests.
#![allow(dead_code, unused_imports)]

use lcs_core::*;

pub fn limits() -> LcsLimits {
    LcsLimits::default()
}

pub fn response_frame(request_id: u64, op_code: u16) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&0u32.to_le_bytes());
    frame.extend_from_slice(&request_id.to_le_bytes());
    frame.extend_from_slice(&op_code.to_le_bytes());
    frame.extend_from_slice(&RSI_OK.to_le_bytes());
    frame
}

pub fn finish_total_len(frame: &mut [u8]) {
    let total_len = frame.len() as u32;
    frame[..4].copy_from_slice(&total_len.to_le_bytes());
}

pub fn push_len_prefixed(frame: &mut Vec<u8>, bytes: &[u8]) {
    frame.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    frame.extend_from_slice(bytes);
}

pub fn system_sid() -> Vec<u8> {
    let mut sid = Vec::new();
    sid.push(1);
    sid.push(1);
    sid.extend_from_slice(&[0, 0, 0, 0, 0, 5]);
    sid.extend_from_slice(&18u32.to_le_bytes());
    sid
}

pub fn sid(authority: u8, subauths: &[u32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(8 + subauths.len() * 4);
    bytes.push(1);
    bytes.push(subauths.len() as u8);
    bytes.extend_from_slice(&[0, 0, 0, 0, 0, authority]);
    for subauth in subauths {
        bytes.extend_from_slice(&subauth.to_le_bytes());
    }
    bytes
}

pub fn field(data: &[u8]) -> RsiLengthPrefixedField<'_> {
    RsiLengthPrefixedField {
        len: data.len() as u32,
        data,
    }
}

pub fn context<'a>(layers: &'a [LayerView<'a>], limits: &'a LcsLimits) -> LayerResolutionContext<'a> {
    LayerResolutionContext {
        layers,
        private_layers: &[],
        limits,
        next_sequence: 100,
    }
}

