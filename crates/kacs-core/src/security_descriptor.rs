use crate::acl::Acl;
use crate::error::{KacsError, KacsResult};
use crate::sid::Sid;

pub const SE_DACL_PRESENT: u16 = 0x0004;
pub const SE_SACL_PRESENT: u16 = 0x0010;
pub const SE_SELF_RELATIVE: u16 = 0x8000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecurityDescriptor<'a> {
    bytes: &'a [u8],
    control: u16,
    owner: Option<Sid<'a>>,
    group: Option<Sid<'a>>,
    sacl: Option<Acl<'a>>,
    dacl: Option<Acl<'a>>,
}

impl<'a> SecurityDescriptor<'a> {
    pub const HEADER_SIZE: usize = 20;

    pub fn parse(bytes: &'a [u8]) -> KacsResult<Self> {
        if bytes.len() < Self::HEADER_SIZE {
            return Err(KacsError::Truncated("security descriptor"));
        }
        if bytes[0] != 1 {
            return Err(KacsError::InvalidSecurityDescriptorRevision(bytes[0]));
        }

        let control = u16::from_le_bytes([bytes[2], bytes[3]]);
        if (control & SE_SELF_RELATIVE) == 0 {
            return Err(KacsError::MissingSelfRelativeControl(control));
        }

        let owner = parse_optional_sid(bytes, "owner", read_offset(bytes, 4), true)?;
        let group = parse_optional_sid(bytes, "group", read_offset(bytes, 8), true)?;
        let sacl = parse_optional_acl(
            bytes,
            "sacl",
            (control & SE_SACL_PRESENT) != 0,
            read_offset(bytes, 12),
        )?;
        let dacl = parse_optional_acl(
            bytes,
            "dacl",
            (control & SE_DACL_PRESENT) != 0,
            read_offset(bytes, 16),
        )?;

        Ok(Self {
            bytes,
            control,
            owner,
            group,
            sacl,
            dacl,
        })
    }

    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    pub fn control(&self) -> u16 {
        self.control
    }

    pub fn owner(&self) -> Option<Sid<'a>> {
        self.owner
    }

    pub fn group(&self) -> Option<Sid<'a>> {
        self.group
    }

    pub fn sacl(&self) -> Option<Acl<'a>> {
        self.sacl
    }

    pub fn dacl(&self) -> Option<Acl<'a>> {
        self.dacl
    }
}

fn parse_optional_sid<'a>(
    bytes: &'a [u8],
    field: &'static str,
    offset: u32,
    zero_is_absent: bool,
) -> KacsResult<Option<Sid<'a>>> {
    if offset == 0 && zero_is_absent {
        return Ok(None);
    }

    let offset_usize =
        usize::try_from(offset).map_err(|_| KacsError::SecurityDescriptorOffsetOutOfBounds {
            field,
            offset,
            buffer_len: bytes.len(),
        })?;
    if offset_usize >= bytes.len() {
        return Err(KacsError::SecurityDescriptorOffsetOutOfBounds {
            field,
            offset,
            buffer_len: bytes.len(),
        });
    }

    let (sid, _) = Sid::parse_prefix(&bytes[offset_usize..])?;
    Ok(Some(sid))
}

fn parse_optional_acl<'a>(
    bytes: &'a [u8],
    field: &'static str,
    present: bool,
    offset: u32,
) -> KacsResult<Option<Acl<'a>>> {
    if !present {
        if offset != 0 {
            return Err(KacsError::InconsistentSecurityDescriptorField {
                field,
                present,
                offset,
            });
        }
        return Ok(None);
    }

    if offset == 0 {
        return Err(KacsError::InconsistentSecurityDescriptorField {
            field,
            present,
            offset,
        });
    }

    let offset_usize =
        usize::try_from(offset).map_err(|_| KacsError::SecurityDescriptorOffsetOutOfBounds {
            field,
            offset,
            buffer_len: bytes.len(),
        })?;
    if offset_usize >= bytes.len() {
        return Err(KacsError::SecurityDescriptorOffsetOutOfBounds {
            field,
            offset,
            buffer_len: bytes.len(),
        });
    }

    let (acl, _) = Acl::parse_prefix(&bytes[offset_usize..])?;
    Ok(Some(acl))
}

fn read_offset(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}
