use crate::access_mask::validate_ace_mask;
use crate::error::{KacsError, KacsResult};
use crate::sid::Sid;

pub const ACCESS_ALLOWED_ACE_TYPE: u8 = 0x00;
pub const ACCESS_DENIED_ACE_TYPE: u8 = 0x01;
pub const SYSTEM_AUDIT_ACE_TYPE: u8 = 0x02;
pub const SYSTEM_ALARM_ACE_TYPE: u8 = 0x03;
pub const ACCESS_ALLOWED_OBJECT_ACE_TYPE: u8 = 0x05;
pub const ACCESS_DENIED_OBJECT_ACE_TYPE: u8 = 0x06;
pub const SYSTEM_AUDIT_OBJECT_ACE_TYPE: u8 = 0x07;
pub const SYSTEM_ALARM_OBJECT_ACE_TYPE: u8 = 0x08;
pub const ACCESS_ALLOWED_CALLBACK_ACE_TYPE: u8 = 0x09;
pub const ACCESS_DENIED_CALLBACK_ACE_TYPE: u8 = 0x0a;
pub const ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE: u8 = 0x0b;
pub const ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE: u8 = 0x0c;
pub const SYSTEM_AUDIT_CALLBACK_ACE_TYPE: u8 = 0x0d;
pub const SYSTEM_ALARM_CALLBACK_ACE_TYPE: u8 = 0x0e;
pub const SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE: u8 = 0x0f;
pub const SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE: u8 = 0x10;
pub const SYSTEM_MANDATORY_LABEL_ACE_TYPE: u8 = 0x11;
pub const SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE: u8 = 0x12;
pub const SYSTEM_SCOPED_POLICY_ID_ACE_TYPE: u8 = 0x13;
pub const SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE: u8 = 0x14;

pub const ACE_OBJECT_TYPE_PRESENT: u32 = 0x0000_0001;
pub const ACE_INHERITED_OBJECT_TYPE_PRESENT: u32 = 0x0000_0002;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ace<'a> {
    bytes: &'a [u8],
    ace_type: u8,
    ace_flags: u8,
    ace_size: u16,
    kind: AceKind<'a>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AceKind<'a> {
    SingleSid {
        mask: u32,
        sid: Sid<'a>,
    },
    Object {
        mask: u32,
        flags: u32,
        object_type: Option<&'a [u8; 16]>,
        inherited_object_type: Option<&'a [u8; 16]>,
        sid: Sid<'a>,
    },
    Callback {
        mask: u32,
        sid: Sid<'a>,
        application_data: &'a [u8],
    },
    CallbackObject {
        mask: u32,
        flags: u32,
        object_type: Option<&'a [u8; 16]>,
        inherited_object_type: Option<&'a [u8; 16]>,
        sid: Sid<'a>,
        application_data: &'a [u8],
    },
    ResourceAttribute {
        mask: u32,
        sid: Sid<'a>,
        application_data: &'a [u8],
    },
    Opaque,
}

impl<'a> Ace<'a> {
    const HEADER_SIZE: usize = 4;
    const SINGLE_SID_PREFIX_SIZE: usize = 8;
    const OBJECT_PREFIX_SIZE: usize = 12;
    const MIN_SINGLE_SID_SIZE: usize = 16;
    const MIN_OBJECT_SIZE: usize = 20;

    pub fn parse(bytes: &'a [u8]) -> KacsResult<Self> {
        let (ace, consumed) = Self::parse_prefix(bytes)?;
        if consumed != bytes.len() {
            return Err(KacsError::InvalidAceSize(ace.ace_size));
        }
        Ok(ace)
    }

    pub fn parse_prefix(bytes: &'a [u8]) -> KacsResult<(Self, usize)> {
        if bytes.len() < Self::HEADER_SIZE {
            return Err(KacsError::Truncated("ace"));
        }

        let ace_type = bytes[0];
        let ace_flags = bytes[1];
        let ace_size = u16::from_le_bytes([bytes[2], bytes[3]]);
        let ace_size_usize = usize::from(ace_size);

        if ace_size_usize < Self::HEADER_SIZE || (ace_size_usize % 4) != 0 {
            return Err(KacsError::InvalidAceSize(ace_size));
        }
        if bytes.len() < ace_size_usize {
            return Err(KacsError::Truncated("ace"));
        }

        let ace_bytes = &bytes[..ace_size_usize];
        let kind = Self::parse_kind(ace_type, ace_bytes)?;

        Ok((
            Self {
                bytes: ace_bytes,
                ace_type,
                ace_flags,
                ace_size,
                kind,
            },
            ace_size_usize,
        ))
    }

    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    pub fn ace_type(&self) -> u8 {
        self.ace_type
    }

    pub fn ace_flags(&self) -> u8 {
        self.ace_flags
    }

    pub fn ace_size(&self) -> u16 {
        self.ace_size
    }

    pub fn kind(&self) -> AceKind<'a> {
        self.kind
    }

    fn parse_kind(ace_type: u8, bytes: &'a [u8]) -> KacsResult<AceKind<'a>> {
        match ace_type {
            ACCESS_ALLOWED_ACE_TYPE
            | ACCESS_DENIED_ACE_TYPE
            | SYSTEM_AUDIT_ACE_TYPE
            | SYSTEM_ALARM_ACE_TYPE
            | SYSTEM_MANDATORY_LABEL_ACE_TYPE
            | SYSTEM_SCOPED_POLICY_ID_ACE_TYPE
            | SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE => Self::parse_single_sid(bytes),
            ACCESS_ALLOWED_OBJECT_ACE_TYPE
            | ACCESS_DENIED_OBJECT_ACE_TYPE
            | SYSTEM_AUDIT_OBJECT_ACE_TYPE
            | SYSTEM_ALARM_OBJECT_ACE_TYPE => Self::parse_object(bytes),
            ACCESS_ALLOWED_CALLBACK_ACE_TYPE
            | ACCESS_DENIED_CALLBACK_ACE_TYPE
            | SYSTEM_AUDIT_CALLBACK_ACE_TYPE
            | SYSTEM_ALARM_CALLBACK_ACE_TYPE => Self::parse_callback(bytes),
            ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
            | ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE
            | SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE
            | SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE => Self::parse_callback_object(bytes),
            SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE => Self::parse_resource_attribute(bytes),
            _ => Ok(AceKind::Opaque),
        }
    }

    fn parse_single_sid(bytes: &'a [u8]) -> KacsResult<AceKind<'a>> {
        if bytes.len() < Self::MIN_SINGLE_SID_SIZE {
            return Err(KacsError::Truncated("ace single sid"));
        }

        let mask = read_u32(bytes, 4);
        validate_ace_mask(mask)?;
        let sid = Sid::parse(&bytes[Self::SINGLE_SID_PREFIX_SIZE..])?;

        Ok(AceKind::SingleSid { mask, sid })
    }

    fn parse_object(bytes: &'a [u8]) -> KacsResult<AceKind<'a>> {
        if bytes.len() < Self::MIN_OBJECT_SIZE {
            return Err(KacsError::Truncated("ace object"));
        }

        let mask = read_u32(bytes, 4);
        validate_ace_mask(mask)?;
        let flags = read_u32(bytes, 8);
        let (object_type, inherited_object_type, sid_offset) = parse_object_fields(bytes, flags)?;
        let sid = Sid::parse(&bytes[sid_offset..])?;

        Ok(AceKind::Object {
            mask,
            flags,
            object_type,
            inherited_object_type,
            sid,
        })
    }

    fn parse_callback(bytes: &'a [u8]) -> KacsResult<AceKind<'a>> {
        if bytes.len() < Self::MIN_SINGLE_SID_SIZE {
            return Err(KacsError::Truncated("ace callback"));
        }

        let mask = read_u32(bytes, 4);
        validate_ace_mask(mask)?;
        let (sid, consumed) = Sid::parse_prefix(&bytes[Self::SINGLE_SID_PREFIX_SIZE..])?;
        let application_data = &bytes[Self::SINGLE_SID_PREFIX_SIZE + consumed..];

        Ok(AceKind::Callback {
            mask,
            sid,
            application_data,
        })
    }

    fn parse_callback_object(bytes: &'a [u8]) -> KacsResult<AceKind<'a>> {
        if bytes.len() < Self::MIN_OBJECT_SIZE {
            return Err(KacsError::Truncated("ace callback object"));
        }

        let mask = read_u32(bytes, 4);
        validate_ace_mask(mask)?;
        let flags = read_u32(bytes, 8);
        let (object_type, inherited_object_type, sid_offset) = parse_object_fields(bytes, flags)?;
        let (sid, consumed) = Sid::parse_prefix(&bytes[sid_offset..])?;
        let application_data = &bytes[sid_offset + consumed..];

        Ok(AceKind::CallbackObject {
            mask,
            flags,
            object_type,
            inherited_object_type,
            sid,
            application_data,
        })
    }

    fn parse_resource_attribute(bytes: &'a [u8]) -> KacsResult<AceKind<'a>> {
        if bytes.len() < Self::MIN_SINGLE_SID_SIZE {
            return Err(KacsError::Truncated("ace resource attribute"));
        }

        let mask = read_u32(bytes, 4);
        let (sid, consumed) = Sid::parse_prefix(&bytes[Self::SINGLE_SID_PREFIX_SIZE..])?;
        if sid.as_bytes() != everyone_sid_bytes() {
            return Err(KacsError::InvalidResourceAttributeSid);
        }
        let application_data = &bytes[Self::SINGLE_SID_PREFIX_SIZE + consumed..];

        Ok(AceKind::ResourceAttribute {
            mask,
            sid,
            application_data,
        })
    }
}

fn parse_object_fields<'a>(
    bytes: &'a [u8],
    flags: u32,
) -> KacsResult<(Option<&'a [u8; 16]>, Option<&'a [u8; 16]>, usize)> {
    let mut offset = Ace::OBJECT_PREFIX_SIZE;
    let object_type = if (flags & ACE_OBJECT_TYPE_PRESENT) != 0 {
        let guid = read_guid(bytes, offset)?;
        offset += 16;
        Some(guid)
    } else {
        None
    };

    let inherited_object_type = if (flags & ACE_INHERITED_OBJECT_TYPE_PRESENT) != 0 {
        let guid = read_guid(bytes, offset)?;
        offset += 16;
        Some(guid)
    } else {
        None
    };

    if bytes.len() < offset + Sid::MIN_SIZE {
        return Err(KacsError::InvalidObjectAceLayout(
            "missing sid after object fields",
        ));
    }

    Ok((object_type, inherited_object_type, offset))
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_guid(bytes: &[u8], offset: usize) -> KacsResult<&[u8; 16]> {
    let slice = bytes
        .get(offset..offset + 16)
        .ok_or(KacsError::Truncated("ace guid"))?;
    let guid: &[u8; 16] = slice
        .try_into()
        .map_err(|_| KacsError::InvalidObjectAceLayout("guid width"))?;
    Ok(guid)
}

fn everyone_sid_bytes() -> &'static [u8] {
    &[1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]
}
