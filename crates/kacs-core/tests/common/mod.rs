//! Shared helpers for kacs_core integration tests.
#![allow(dead_code, unused_imports)]

use kacs_core::*;

pub fn sid_bytes(authority: [u8; 6], sub_authorities: &[u32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(8 + (sub_authorities.len() * 4));
    bytes.push(1);
    bytes.push(sub_authorities.len() as u8);
    bytes.extend_from_slice(&authority);
    for sub_authority in sub_authorities {
        bytes.extend_from_slice(&sub_authority.to_le_bytes());
    }
    bytes
}

pub fn acl_bytes(aces: &[Vec<u8>]) -> Vec<u8> {
    let size = 8 + aces.iter().map(Vec::len).sum::<usize>();
    let mut bytes = Vec::with_capacity(size);
    bytes.push(4);
    bytes.push(0);
    bytes.extend_from_slice(&(size as u16).to_le_bytes());
    bytes.extend_from_slice(&(aces.len() as u16).to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    for ace in aces {
        bytes.extend_from_slice(ace);
    }
    bytes
}

pub fn mapping() -> GenericMapping {
    GenericMapping {
        read: READ_CONTROL,
        write: WRITE_DAC,
        execute: 0x0000_0020,
        all: READ_CONTROL | WRITE_DAC | WRITE_OWNER | 0x0000_0020,
    }
}

pub fn basic_ace(ace_type: u8, flags: u8, mask: u32, sid: &[u8]) -> Vec<u8> {
    let size = 8 + sid.len();
    let mut bytes = Vec::with_capacity(size);
    bytes.push(ace_type);
    bytes.push(flags);
    bytes.extend_from_slice(&(size as u16).to_le_bytes());
    bytes.extend_from_slice(&mask.to_le_bytes());
    bytes.extend_from_slice(sid);
    bytes
}

pub fn parse_sid(bytes: &[u8]) -> Sid<'_> {
    Sid::parse(bytes).expect("sid should parse")
}

pub fn object_ace(ace_type: u8, flags: u8, mask: u32, sid: &[u8]) -> Vec<u8> {
    let size = 12 + sid.len();
    let mut bytes = Vec::with_capacity(size);
    bytes.push(ace_type);
    bytes.push(flags);
    bytes.extend_from_slice(&(size as u16).to_le_bytes());
    bytes.extend_from_slice(&mask.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(sid);
    bytes
}

pub fn resource_attribute_ace(flags: u8, application_data: &[u8]) -> Vec<u8> {
    let sid = sid_bytes([0, 0, 0, 0, 0, 1], &[0]);
    let unpadded_size = 8 + sid.len() + application_data.len();
    let size = (unpadded_size + 3) & !3;
    let mut bytes = Vec::with_capacity(size);
    bytes.push(SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE);
    bytes.push(flags);
    bytes.extend_from_slice(&(size as u16).to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&sid);
    bytes.extend_from_slice(application_data);
    bytes.resize(size, 0);
    bytes
}

pub fn expr(tokens: &[u8]) -> Vec<u8> {
    let mut bytes = b"artx".to_vec();
    bytes.extend_from_slice(tokens);
    bytes
}

pub fn callback_ace(ace_type: u8, flags: u8, mask: u32, sid: &[u8], app_data: &[u8]) -> Vec<u8> {
    let size = (8 + sid.len() + app_data.len() + 3) & !3;
    let mut bytes = Vec::with_capacity(size);
    bytes.push(ace_type);
    bytes.push(flags);
    bytes.extend_from_slice(&(size as u16).to_le_bytes());
    bytes.extend_from_slice(&mask.to_le_bytes());
    bytes.extend_from_slice(sid);
    bytes.extend_from_slice(app_data);
    while bytes.len() < size {
        bytes.push(0);
    }
    bytes
}

pub fn append_tokens(tokens: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for token in tokens {
        bytes.extend_from_slice(token);
    }
    bytes
}

