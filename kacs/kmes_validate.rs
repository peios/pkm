// SPDX-License-Identifier: GPL-2.0-only

//! Narrow KMES syscall-side UTF-8 and msgpack structural validator.

use core::ffi::c_int;
use core::slice;
use core::str;

const EINVAL: c_int = 22;
const MAX_VALIDATION_DEPTH: usize = 256;

fn read_be_u16(bytes: &[u8], pos: &mut usize) -> Option<u16> {
    let end = pos.checked_add(2)?;
    let chunk = bytes.get(*pos..end)?;
    *pos = end;
    Some(u16::from_be_bytes([chunk[0], chunk[1]]))
}

fn read_be_u32(bytes: &[u8], pos: &mut usize) -> Option<u32> {
    let end = pos.checked_add(4)?;
    let chunk = bytes.get(*pos..end)?;
    *pos = end;
    Some(u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
}

fn read_be_u64(bytes: &[u8], pos: &mut usize) -> Option<u64> {
    let end = pos.checked_add(8)?;
    let chunk = bytes.get(*pos..end)?;
    *pos = end;
    Some(u64::from_be_bytes([
        chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
    ]))
}

fn validate_msgpack_str(bytes: &[u8], pos: &mut usize, len: usize) -> bool {
    let Some(end) = pos.checked_add(len) else {
        return false;
    };
    let Some(chunk) = bytes.get(*pos..end) else {
        return false;
    };
    if str::from_utf8(chunk).is_err() {
        return false;
    }
    *pos = end;
    true
}

fn validate_msgpack_blob(bytes: &[u8], pos: &mut usize, len: usize) -> bool {
    let Some(end) = pos.checked_add(len) else {
        return false;
    };
    if bytes.get(*pos..end).is_none() {
        return false;
    }
    *pos = end;
    true
}

fn validate_msgpack(bytes: &[u8], max_nesting_depth: u32) -> bool {
    let max_nesting_depth = usize::try_from(max_nesting_depth).unwrap_or(MAX_VALIDATION_DEPTH + 1);
    let mut stack = [0u32; MAX_VALIDATION_DEPTH];
    let mut depth = 1usize;
    let mut pos = 0usize;

    if bytes.is_empty() || max_nesting_depth == 0 || max_nesting_depth > MAX_VALIDATION_DEPTH {
        return false;
    }

    stack[0] = 1;

    while depth > 0 {
        let remaining = &mut stack[depth - 1];
        if *remaining == 0 {
            depth -= 1;
            continue;
        }

        if pos >= bytes.len() {
            return false;
        }

        *remaining -= 1;
        match bytes[pos] {
            0x00..=0x7f | 0xc0 | 0xc2 | 0xc3 | 0xe0..=0xff => {
                pos += 1;
            }
            0x80..=0x8f => {
                let entries = u32::from(bytes[pos] & 0x0f);
                let Some(values) = entries.checked_mul(2) else {
                    return false;
                };
                pos += 1;
                if values != 0 {
                    if depth >= max_nesting_depth || depth >= MAX_VALIDATION_DEPTH {
                        return false;
                    }
                    stack[depth] = values;
                    depth += 1;
                }
            }
            0x90..=0x9f => {
                let values = u32::from(bytes[pos] & 0x0f);
                pos += 1;
                if values != 0 {
                    if depth >= max_nesting_depth || depth >= MAX_VALIDATION_DEPTH {
                        return false;
                    }
                    stack[depth] = values;
                    depth += 1;
                }
            }
            0xa0..=0xbf => {
                let len = usize::from(bytes[pos] & 0x1f);
                pos += 1;
                if !validate_msgpack_str(bytes, &mut pos, len) {
                    return false;
                }
            }
            0xc4 => {
                pos += 1;
                let Some(len) = bytes.get(pos).copied() else {
                    return false;
                };
                pos += 1;
                if !validate_msgpack_blob(bytes, &mut pos, usize::from(len)) {
                    return false;
                }
            }
            0xc5 => {
                pos += 1;
                let Some(len) = read_be_u16(bytes, &mut pos) else {
                    return false;
                };
                if !validate_msgpack_blob(bytes, &mut pos, usize::from(len)) {
                    return false;
                }
            }
            0xc6 => {
                pos += 1;
                let Some(len) = read_be_u32(bytes, &mut pos) else {
                    return false;
                };
                let Ok(len) = usize::try_from(len) else {
                    return false;
                };
                if !validate_msgpack_blob(bytes, &mut pos, len) {
                    return false;
                }
            }
            0xc7 => {
                pos += 1;
                let Some(len) = bytes.get(pos).copied() else {
                    return false;
                };
                pos += 1;
                if !validate_msgpack_blob(bytes, &mut pos, 1 + usize::from(len)) {
                    return false;
                }
            }
            0xc8 => {
                pos += 1;
                let Some(len) = read_be_u16(bytes, &mut pos) else {
                    return false;
                };
                if !validate_msgpack_blob(bytes, &mut pos, 1 + usize::from(len)) {
                    return false;
                }
            }
            0xc9 => {
                pos += 1;
                let Some(len) = read_be_u32(bytes, &mut pos) else {
                    return false;
                };
                let Ok(len) = usize::try_from(len) else {
                    return false;
                };
                if !validate_msgpack_blob(bytes, &mut pos, 1 + len) {
                    return false;
                }
            }
            0xca => {
                pos += 1;
                if !validate_msgpack_blob(bytes, &mut pos, 4) {
                    return false;
                }
            }
            0xcb => {
                pos += 1;
                if !validate_msgpack_blob(bytes, &mut pos, 8) {
                    return false;
                }
            }
            0xcc | 0xd0 => {
                pos += 1;
                if !validate_msgpack_blob(bytes, &mut pos, 1) {
                    return false;
                }
            }
            0xcd | 0xd1 => {
                pos += 1;
                if !validate_msgpack_blob(bytes, &mut pos, 2) {
                    return false;
                }
            }
            0xce | 0xd2 => {
                pos += 1;
                if !validate_msgpack_blob(bytes, &mut pos, 4) {
                    return false;
                }
            }
            0xcf | 0xd3 => {
                pos += 1;
                if !validate_msgpack_blob(bytes, &mut pos, 8) {
                    return false;
                }
            }
            0xd4 => {
                pos += 1;
                if !validate_msgpack_blob(bytes, &mut pos, 2) {
                    return false;
                }
            }
            0xd5 => {
                pos += 1;
                if !validate_msgpack_blob(bytes, &mut pos, 3) {
                    return false;
                }
            }
            0xd6 => {
                pos += 1;
                if !validate_msgpack_blob(bytes, &mut pos, 5) {
                    return false;
                }
            }
            0xd7 => {
                pos += 1;
                if !validate_msgpack_blob(bytes, &mut pos, 9) {
                    return false;
                }
            }
            0xd8 => {
                pos += 1;
                if !validate_msgpack_blob(bytes, &mut pos, 17) {
                    return false;
                }
            }
            0xd9 => {
                pos += 1;
                let Some(len) = bytes.get(pos).copied() else {
                    return false;
                };
                pos += 1;
                if !validate_msgpack_str(bytes, &mut pos, usize::from(len)) {
                    return false;
                }
            }
            0xda => {
                pos += 1;
                let Some(len) = read_be_u16(bytes, &mut pos) else {
                    return false;
                };
                if !validate_msgpack_str(bytes, &mut pos, usize::from(len)) {
                    return false;
                }
            }
            0xdb => {
                pos += 1;
                let Some(len) = read_be_u32(bytes, &mut pos) else {
                    return false;
                };
                let Ok(len) = usize::try_from(len) else {
                    return false;
                };
                if !validate_msgpack_str(bytes, &mut pos, len) {
                    return false;
                }
            }
            0xdc => {
                pos += 1;
                let Some(values) = read_be_u16(bytes, &mut pos) else {
                    return false;
                };
                if values != 0 {
                    if depth >= max_nesting_depth || depth >= MAX_VALIDATION_DEPTH {
                        return false;
                    }
                    stack[depth] = u32::from(values);
                    depth += 1;
                }
            }
            0xdd => {
                pos += 1;
                let Some(values) = read_be_u32(bytes, &mut pos) else {
                    return false;
                };
                if values != 0 {
                    if depth >= max_nesting_depth || depth >= MAX_VALIDATION_DEPTH {
                        return false;
                    }
                    stack[depth] = values;
                    depth += 1;
                }
            }
            0xde => {
                pos += 1;
                let Some(entries) = read_be_u16(bytes, &mut pos) else {
                    return false;
                };
                let Some(values) = u32::from(entries).checked_mul(2) else {
                    return false;
                };
                if values != 0 {
                    if depth >= max_nesting_depth || depth >= MAX_VALIDATION_DEPTH {
                        return false;
                    }
                    stack[depth] = values;
                    depth += 1;
                }
            }
            0xdf => {
                pos += 1;
                let Some(entries) = read_be_u32(bytes, &mut pos) else {
                    return false;
                };
                let Some(values) = entries.checked_mul(2) else {
                    return false;
                };
                if values != 0 {
                    if depth >= max_nesting_depth || depth >= MAX_VALIDATION_DEPTH {
                        return false;
                    }
                    stack[depth] = values;
                    depth += 1;
                }
            }
            _ => {
                return false;
            }
        }
    }

    pos == bytes.len()
}

#[no_mangle]
/// Validates one staged KMES syscall event type string and msgpack payload.
pub extern "C" fn kacs_rust_kmes_validate_staged_event(
    event_type_ptr: *const u8,
    event_type_len: usize,
    payload_ptr: *const u8,
    payload_len: usize,
    max_nesting_depth: u32,
) -> c_int {
    let event_type = if event_type_len == 0 {
        &[][..]
    } else if event_type_ptr.is_null() {
        return -EINVAL;
    } else {
        unsafe { slice::from_raw_parts(event_type_ptr, event_type_len) }
    };
    let payload = if payload_len == 0 {
        &[][..]
    } else if payload_ptr.is_null() {
        return -EINVAL;
    } else {
        unsafe { slice::from_raw_parts(payload_ptr, payload_len) }
    };

    if event_type.is_empty() || str::from_utf8(event_type).is_err() {
        return -EINVAL;
    }
    if !validate_msgpack(payload, max_nesting_depth) {
        return -EINVAL;
    }

    0
}
