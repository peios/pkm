use crate::acl::Acl;
use crate::error::{KacsError, KacsResult};
use crate::sid::Sid;

/// Control bit indicating that the descriptor carries a DACL offset.
pub const SE_DACL_PRESENT: u16 = 0x0004;
/// Control bit indicating that the descriptor carries a SACL offset.
pub const SE_SACL_PRESENT: u16 = 0x0010;
/// Control bit indicating self-relative layout.
pub const SE_SELF_RELATIVE: u16 = 0x8000;

/// Parsed self-relative security descriptor with borrowed component views.
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
    /// Size in bytes of the fixed self-relative security descriptor header.
    pub const HEADER_SIZE: usize = 20;

    /// Parses a self-relative security descriptor and validates component
    /// offsets and overlap.
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

        let (owner, owner_region) =
            parse_optional_sid(bytes, "owner", read_offset(bytes, 4), true)?;
        let (group, group_region) =
            parse_optional_sid(bytes, "group", read_offset(bytes, 8), true)?;
        let (sacl, sacl_region) = parse_optional_acl(
            bytes,
            "sacl",
            (control & SE_SACL_PRESENT) != 0,
            read_offset(bytes, 12),
        )?;
        let (dacl, dacl_region) = parse_optional_acl(
            bytes,
            "dacl",
            (control & SE_DACL_PRESENT) != 0,
            read_offset(bytes, 16),
        )?;

        validate_component_overlap(&[owner_region, group_region, sacl_region, dacl_region])?;

        Ok(Self {
            bytes,
            control,
            owner,
            group,
            sacl,
            dacl,
        })
    }

    /// Returns the full original descriptor bytes.
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the descriptor control field.
    pub fn control(&self) -> u16 {
        self.control
    }

    /// Returns the parsed owner SID, if present.
    pub fn owner(&self) -> Option<Sid<'a>> {
        self.owner
    }

    /// Returns the parsed primary-group SID, if present.
    pub fn group(&self) -> Option<Sid<'a>> {
        self.group
    }

    /// Returns the parsed SACL, if present.
    pub fn sacl(&self) -> Option<Acl<'a>> {
        self.sacl
    }

    /// Returns the parsed DACL, if present.
    pub fn dacl(&self) -> Option<Acl<'a>> {
        self.dacl
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ComponentRegion {
    field: &'static str,
    start: usize,
    end: usize,
}

fn parse_optional_sid<'a>(
    bytes: &'a [u8],
    field: &'static str,
    offset: u32,
    zero_is_absent: bool,
) -> KacsResult<(Option<Sid<'a>>, Option<ComponentRegion>)> {
    if offset == 0 && zero_is_absent {
        return Ok((None, None));
    }

    let offset_usize =
        usize::try_from(offset).map_err(|_| KacsError::SecurityDescriptorOffsetOutOfBounds {
            field,
            offset,
            buffer_len: bytes.len(),
        })?;
    if offset_usize < SecurityDescriptor::HEADER_SIZE {
        return Err(KacsError::SecurityDescriptorOffsetInsideHeader {
            field,
            offset,
            header_len: SecurityDescriptor::HEADER_SIZE,
        });
    }
    if offset_usize >= bytes.len() {
        return Err(KacsError::SecurityDescriptorOffsetOutOfBounds {
            field,
            offset,
            buffer_len: bytes.len(),
        });
    }

    let (sid, consumed) = Sid::parse_prefix(&bytes[offset_usize..])?;
    Ok((
        Some(sid),
        Some(ComponentRegion {
            field,
            start: offset_usize,
            end: offset_usize + consumed,
        }),
    ))
}

fn parse_optional_acl<'a>(
    bytes: &'a [u8],
    field: &'static str,
    present: bool,
    offset: u32,
) -> KacsResult<(Option<Acl<'a>>, Option<ComponentRegion>)> {
    if !present {
        if offset != 0 {
            return Err(KacsError::InconsistentSecurityDescriptorField {
                field,
                present,
                offset,
            });
        }
        return Ok((None, None));
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
    if offset_usize < SecurityDescriptor::HEADER_SIZE {
        return Err(KacsError::SecurityDescriptorOffsetInsideHeader {
            field,
            offset,
            header_len: SecurityDescriptor::HEADER_SIZE,
        });
    }
    if offset_usize >= bytes.len() {
        return Err(KacsError::SecurityDescriptorOffsetOutOfBounds {
            field,
            offset,
            buffer_len: bytes.len(),
        });
    }

    let (acl, consumed) = Acl::parse_prefix(&bytes[offset_usize..])?;
    Ok((
        Some(acl),
        Some(ComponentRegion {
            field,
            start: offset_usize,
            end: offset_usize + consumed,
        }),
    ))
}

fn read_offset(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn validate_component_overlap(regions: &[Option<ComponentRegion>]) -> KacsResult<()> {
    for (index, first) in regions.iter().enumerate() {
        let Some(first) = first else {
            continue;
        };
        for second in regions.iter().skip(index + 1) {
            let Some(second) = second else {
                continue;
            };
            if first.start < second.end && second.start < first.end {
                return Err(KacsError::SecurityDescriptorComponentsOverlap {
                    first: first.field,
                    second: second.field,
                });
            }
        }
    }
    Ok(())
}
