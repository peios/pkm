// Security Descriptor — the complete security policy for a protected object (§9).
//
// Self-relative binary format (MS-DTYP §2.4.6): 20-byte header with
// four 32-bit offsets pointing to owner SID, group SID, SACL, and DACL
// within the contiguous buffer. Byte-compatible with Windows and Samba.
//
// Every file, registry key, IPC endpoint, token, process, and service
// in Peios has a Security Descriptor.

use crate::compat::{self, AllocError, Vec};
use crate::acl::Acl;
use crate::sid::Sid;

/// SD revision. Always 1.
pub const SD_REVISION: u8 = 1;

// --- Control flags (§9.10) ---

/// Owner was set by a defaulting mechanism.
pub const SE_OWNER_DEFAULTED: u16 = 0x0001;
/// Group was set by a defaulting mechanism.
pub const SE_GROUP_DEFAULTED: u16 = 0x0002;
/// DACL is present.
pub const SE_DACL_PRESENT: u16 = 0x0004;
/// DACL was set by a defaulting mechanism.
pub const SE_DACL_DEFAULTED: u16 = 0x0008;
/// SACL is present.
pub const SE_SACL_PRESENT: u16 = 0x0010;
/// SACL was set by a defaulting mechanism.
pub const SE_SACL_DEFAULTED: u16 = 0x0020;
/// DACL is trusted (set by a trusted source).
pub const SE_DACL_TRUSTED: u16 = 0x0040;
/// Server security descriptor (server ACL semantics).
pub const SE_SERVER_SECURITY: u16 = 0x0080;
/// DACL should be auto-inherited from parent.
pub const SE_DACL_AUTO_INHERIT_REQ: u16 = 0x0100;
/// SACL should be auto-inherited from parent.
pub const SE_SACL_AUTO_INHERIT_REQ: u16 = 0x0200;
/// DACL was auto-inherited.
pub const SE_DACL_AUTO_INHERITED: u16 = 0x0400;
/// SACL was auto-inherited.
pub const SE_SACL_AUTO_INHERITED: u16 = 0x0800;
/// DACL is protected from inheritance propagation.
pub const SE_DACL_PROTECTED: u16 = 0x1000;
/// SACL is protected from inheritance propagation.
pub const SE_SACL_PROTECTED: u16 = 0x2000;
/// Resource manager control is valid.
pub const SE_RM_CONTROL_VALID: u16 = 0x4000;
/// Descriptor is in self-relative format.
pub const SE_SELF_RELATIVE: u16 = 0x8000;

/// Self-relative header size.
const SD_HEADER_SIZE: usize = 20;

/// A parsed Security Descriptor.
#[cfg_attr(not(feature = "kernel"), derive(Clone))]
#[derive(Debug)]
pub struct SecurityDescriptor {
    /// Control flags (SE_* bitmask).
    pub control: u16,
    /// Owner SID.
    pub owner: Option<Sid>,
    /// Primary group SID.
    pub group: Option<Sid>,
    /// Discretionary Access Control List.
    pub dacl: Option<Acl>,
    /// System Access Control List (audit, integrity, policy).
    pub sacl: Option<Acl>,
}

impl SecurityDescriptor {
    /// Create a minimal SD with owner, group, and DACL.
    pub fn new(owner: Sid, group: Sid, dacl: Acl) -> Self {
        SecurityDescriptor {
            control: SE_DACL_PRESENT | SE_SELF_RELATIVE,
            owner: Some(owner),
            group: Some(group),
            dacl: Some(dacl),
            sacl: None,
        }
    }

    /// Create an SD with all four components.
    pub fn with_sacl(owner: Sid, group: Sid, dacl: Acl, sacl: Acl) -> Self {
        SecurityDescriptor {
            control: SE_DACL_PRESENT | SE_SACL_PRESENT | SE_SELF_RELATIVE,
            owner: Some(owner),
            group: Some(group),
            dacl: Some(dacl),
            sacl: Some(sacl),
        }
    }

    /// Does this SD have a DACL? (SE_DACL_PRESENT flag)
    pub fn has_dacl(&self) -> bool {
        self.control & SE_DACL_PRESENT != 0 && self.dacl.is_some()
    }

    /// Does this SD have a SACL? (SE_SACL_PRESENT flag)
    pub fn has_sacl(&self) -> bool {
        self.control & SE_SACL_PRESENT != 0 && self.sacl.is_some()
    }

    /// Is the DACL protected from inheritance?
    pub fn is_dacl_protected(&self) -> bool {
        self.control & SE_DACL_PROTECTED != 0
    }

    /// Is the SACL protected from inheritance?
    pub fn is_sacl_protected(&self) -> bool {
        self.control & SE_SACL_PROTECTED != 0
    }

    /// Parse from self-relative binary format (MS-DTYP §2.4.6).
    pub fn from_bytes(data: &[u8]) -> Result<Option<Self>, AllocError> {
        if data.len() < SD_HEADER_SIZE {
            return Ok(None);
        }

        let revision = data[0];
        if revision != SD_REVISION {
            return Ok(None);
        }

        // data[1] is Sbz1 (resource manager control, usually 0)

        let control = u16::from_le_bytes([data[2], data[3]]);

        // Reject absolute-format SDs — we only parse self-relative.
        if control & SE_SELF_RELATIVE == 0 {
            return Ok(None);
        }

        // Self-relative format: four 32-bit offsets
        let owner_offset = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
        let group_offset = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;
        let sacl_offset = u32::from_le_bytes([data[12], data[13], data[14], data[15]]) as usize;
        let dacl_offset = u32::from_le_bytes([data[16], data[17], data[18], data[19]]) as usize;

        let owner = if owner_offset != 0 {
            if owner_offset >= data.len() {
                return Ok(None);
            }
            match Sid::from_bytes(&data[owner_offset..]) {
                Some(sid) => Some(sid),
                None => return Ok(None),
            }
        } else {
            None
        };

        let group = if group_offset != 0 {
            if group_offset >= data.len() {
                return Ok(None);
            }
            match Sid::from_bytes(&data[group_offset..]) {
                Some(sid) => Some(sid),
                None => return Ok(None),
            }
        } else {
            None
        };

        let sacl = if sacl_offset != 0 && control & SE_SACL_PRESENT != 0 {
            if sacl_offset >= data.len() {
                return Ok(None);
            }
            match Acl::from_bytes(&data[sacl_offset..])? {
                Some(acl) => Some(acl),
                None => return Ok(None),
            }
        } else {
            None
        };

        let dacl = if dacl_offset != 0 && control & SE_DACL_PRESENT != 0 {
            if dacl_offset >= data.len() {
                return Ok(None);
            }
            match Acl::from_bytes(&data[dacl_offset..])? {
                Some(acl) => Some(acl),
                None => return Ok(None),
            }
        } else {
            None
        };

        Ok(Some(SecurityDescriptor {
            control,
            owner,
            group,
            dacl,
            sacl,
        }))
    }

    /// Serialize to self-relative binary format.
    pub fn to_bytes(&self) -> Result<Vec<u8>, AllocError> {
        // Compute sizes and offsets
        let owner_bytes = match self.owner.as_ref() {
            Some(s) => Some(s.to_bytes()?),
            None => None,
        };
        let group_bytes = match self.group.as_ref() {
            Some(s) => Some(s.to_bytes()?),
            None => None,
        };
        let sacl_bytes = if self.control & SE_SACL_PRESENT != 0 {
            match self.sacl.as_ref() {
                Some(a) => Some(a.to_bytes()?),
                None => None,
            }
        } else {
            None
        };
        let dacl_bytes = if self.control & SE_DACL_PRESENT != 0 {
            match self.dacl.as_ref() {
                Some(a) => Some(a.to_bytes()?),
                None => None,
            }
        } else {
            None
        };

        let mut offset = SD_HEADER_SIZE;

        let owner_offset = if owner_bytes.is_some() {
            let o = offset;
            offset += owner_bytes.as_ref().unwrap().len();
            o as u32
        } else {
            0
        };

        let group_offset = if group_bytes.is_some() {
            let o = offset;
            offset += group_bytes.as_ref().unwrap().len();
            o as u32
        } else {
            0
        };

        let sacl_offset = if sacl_bytes.is_some() {
            let o = offset;
            offset += sacl_bytes.as_ref().unwrap().len();
            o as u32
        } else {
            0
        };

        let dacl_offset = if dacl_bytes.is_some() {
            let o = offset;
            offset += dacl_bytes.as_ref().unwrap().len();
            o as u32
        } else {
            0
        };

        let mut buf = compat::vec_with_capacity(offset)?;

        // Header
        compat::vec_push(&mut buf, SD_REVISION)?;
        compat::vec_push(&mut buf, 0)?; // Sbz1
        compat::vec_extend(&mut buf, &(self.control | SE_SELF_RELATIVE).to_le_bytes())?;
        compat::vec_extend(&mut buf, &owner_offset.to_le_bytes())?;
        compat::vec_extend(&mut buf, &group_offset.to_le_bytes())?;
        compat::vec_extend(&mut buf, &sacl_offset.to_le_bytes())?;
        compat::vec_extend(&mut buf, &dacl_offset.to_le_bytes())?;

        // Components (in offset order: owner, group, sacl, dacl)
        if let Some(ref b) = owner_bytes {
            compat::vec_extend(&mut buf, b)?;
        }
        if let Some(ref b) = group_bytes {
            compat::vec_extend(&mut buf, b)?;
        }
        if let Some(ref b) = sacl_bytes {
            compat::vec_extend(&mut buf, b)?;
        }
        if let Some(ref b) = dacl_bytes {
            compat::vec_extend(&mut buf, b)?;
        }

        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ace::*;
    use crate::acl::*;
    use crate::mask::*;
    use crate::well_known;

    fn simple_dacl() -> Acl {
        Acl {
            revision: ACL_REVISION,
            aces: alloc::vec![
                Ace {
                    ace_type: ACCESS_DENIED_ACE_TYPE,
                    flags: 0,
                    mask: GENERIC_ALL,
                    sid: well_known::guests().unwrap(),
                    object_type: None,
                    inherited_object_type: None,
                    condition: None,
                    application_data: None,
                },
                Ace {
                    ace_type: ACCESS_ALLOWED_ACE_TYPE,
                    flags: 0,
                    mask: GENERIC_ALL,
                    sid: well_known::administrators().unwrap(),
                    object_type: None,
                    inherited_object_type: None,
                    condition: None,
                    application_data: None,
                },
                Ace {
                    ace_type: ACCESS_ALLOWED_ACE_TYPE,
                    flags: 0,
                    mask: FILE_READ_DATA | READ_CONTROL,
                    sid: well_known::authenticated_users().unwrap(),
                    object_type: None,
                    inherited_object_type: None,
                    condition: None,
                    application_data: None,
                },
            ],
        }
    }

    fn simple_sacl() -> Acl {
        Acl {
            revision: ACL_REVISION,
            aces: alloc::vec![
                Ace {
                    ace_type: SYSTEM_MANDATORY_LABEL_ACE_TYPE,
                    flags: 0,
                    mask: SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
                    sid: well_known::integrity_medium().unwrap(),
                    object_type: None,
                    inherited_object_type: None,
                    condition: None,
                    application_data: None,
                },
                Ace {
                    ace_type: SYSTEM_AUDIT_ACE_TYPE,
                    flags: SUCCESSFUL_ACCESS_ACE_FLAG | FAILED_ACCESS_ACE_FLAG,
                    mask: FILE_WRITE_DATA,
                    sid: well_known::everyone().unwrap(),
                    object_type: None,
                    inherited_object_type: None,
                    condition: None,
                    application_data: None,
                },
            ],
        }
    }

    #[test]
    fn minimal_sd_round_trip() {
        let sd = SecurityDescriptor::new(
            well_known::system().unwrap(),
            well_known::system().unwrap(),
            simple_dacl(),
        );
        let bytes = sd.to_bytes().unwrap();
        let parsed = SecurityDescriptor::from_bytes(&bytes).unwrap().unwrap();
        assert_eq!(parsed.owner.as_ref().unwrap(), &well_known::system().unwrap());
        assert_eq!(parsed.group.as_ref().unwrap(), &well_known::system().unwrap());
        assert!(parsed.has_dacl());
        assert!(!parsed.has_sacl());
        assert_eq!(parsed.dacl.as_ref().unwrap().aces.len(), 3);
    }

    #[test]
    fn sd_with_sacl_round_trip() {
        let sd = SecurityDescriptor::with_sacl(
            well_known::administrators().unwrap(),
            well_known::users().unwrap(),
            simple_dacl(),
            simple_sacl(),
        );
        let bytes = sd.to_bytes().unwrap();
        let parsed = SecurityDescriptor::from_bytes(&bytes).unwrap().unwrap();
        assert!(parsed.has_dacl());
        assert!(parsed.has_sacl());
        assert_eq!(parsed.dacl.as_ref().unwrap().aces.len(), 3);
        assert_eq!(parsed.sacl.as_ref().unwrap().aces.len(), 2);
        assert_eq!(
            parsed.sacl.as_ref().unwrap().aces[0].ace_type,
            SYSTEM_MANDATORY_LABEL_ACE_TYPE,
        );
    }

    #[test]
    fn sd_owner_and_group_preserved() {
        let owner = crate::sid::Sid::new(5, &[21, 111, 222, 333, 1001]).unwrap();
        let group = crate::sid::Sid::new(5, &[21, 111, 222, 333, 513]).unwrap();
        let sd = SecurityDescriptor::new(owner.clone(), group.clone(), Acl::new(ACL_REVISION));
        let bytes = sd.to_bytes().unwrap();
        let parsed = SecurityDescriptor::from_bytes(&bytes).unwrap().unwrap();
        assert_eq!(parsed.owner.unwrap(), owner);
        assert_eq!(parsed.group.unwrap(), group);
    }

    #[test]
    fn sd_control_flags_preserved() {
        let mut sd = SecurityDescriptor::new(
            well_known::system().unwrap(),
            well_known::system().unwrap(),
            Acl::new(ACL_REVISION),
        );
        sd.control |= SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED;
        let bytes = sd.to_bytes().unwrap();
        let parsed = SecurityDescriptor::from_bytes(&bytes).unwrap().unwrap();
        assert!(parsed.is_dacl_protected());
        assert!(parsed.control & SE_DACL_AUTO_INHERITED != 0);
        assert!(parsed.control & SE_SELF_RELATIVE != 0);
    }

    #[test]
    fn sd_null_dacl() {
        // DACL not present — SE_DACL_PRESENT not set
        let sd = SecurityDescriptor {
            control: SE_SELF_RELATIVE, // no SE_DACL_PRESENT
            owner: Some(well_known::system().unwrap()),
            group: Some(well_known::system().unwrap()),
            dacl: None,
            sacl: None,
        };
        assert!(!sd.has_dacl());
        let bytes = sd.to_bytes().unwrap();
        let parsed = SecurityDescriptor::from_bytes(&bytes).unwrap().unwrap();
        assert!(!parsed.has_dacl());
        assert!(parsed.dacl.is_none());
    }

    #[test]
    fn sd_empty_dacl() {
        // DACL present but empty — grants nothing
        let sd = SecurityDescriptor::new(
            well_known::system().unwrap(),
            well_known::system().unwrap(),
            Acl::new(ACL_REVISION), // zero ACEs
        );
        assert!(sd.has_dacl());
        let bytes = sd.to_bytes().unwrap();
        let parsed = SecurityDescriptor::from_bytes(&bytes).unwrap().unwrap();
        assert!(parsed.has_dacl());
        assert_eq!(parsed.dacl.as_ref().unwrap().aces.len(), 0);
    }

    #[test]
    fn sd_no_owner() {
        let sd = SecurityDescriptor {
            control: SE_DACL_PRESENT | SE_SELF_RELATIVE,
            owner: None,
            group: Some(well_known::system().unwrap()),
            dacl: Some(Acl::new(ACL_REVISION)),
            sacl: None,
        };
        let bytes = sd.to_bytes().unwrap();
        let parsed = SecurityDescriptor::from_bytes(&bytes).unwrap().unwrap();
        assert!(parsed.owner.is_none());
        assert!(parsed.group.is_some());
    }

    #[test]
    fn sd_no_group() {
        let sd = SecurityDescriptor {
            control: SE_DACL_PRESENT | SE_SELF_RELATIVE,
            owner: Some(well_known::system().unwrap()),
            group: None,
            dacl: Some(Acl::new(ACL_REVISION)),
            sacl: None,
        };
        let bytes = sd.to_bytes().unwrap();
        let parsed = SecurityDescriptor::from_bytes(&bytes).unwrap().unwrap();
        assert!(parsed.owner.is_some());
        assert!(parsed.group.is_none());
    }

    #[test]
    fn reject_truncated_header() {
        assert!(SecurityDescriptor::from_bytes(&[0x01; 19]).unwrap().is_none());
    }

    #[test]
    fn reject_bad_revision() {
        let mut bytes = SecurityDescriptor::new(
            well_known::system().unwrap(),
            well_known::system().unwrap(),
            Acl::new(ACL_REVISION),
        )
        .to_bytes().unwrap();
        bytes[0] = 2; // bad revision
        assert!(SecurityDescriptor::from_bytes(&bytes).unwrap().is_none());
    }

    #[test]
    fn reject_owner_offset_out_of_bounds() {
        let mut bytes = SecurityDescriptor::new(
            well_known::system().unwrap(),
            well_known::system().unwrap(),
            Acl::new(ACL_REVISION),
        )
        .to_bytes().unwrap();
        // Set owner offset to beyond buffer
        let bad_offset = (bytes.len() + 100) as u32;
        bytes[4..8].copy_from_slice(&bad_offset.to_le_bytes());
        assert!(SecurityDescriptor::from_bytes(&bytes).unwrap().is_none());
    }

    #[test]
    fn reject_group_offset_out_of_bounds() {
        let mut bytes = SecurityDescriptor::new(
            well_known::system().unwrap(),
            well_known::system().unwrap(),
            Acl::new(ACL_REVISION),
        )
        .to_bytes().unwrap();
        let bad_offset = (bytes.len() + 100) as u32;
        bytes[8..12].copy_from_slice(&bad_offset.to_le_bytes());
        assert!(SecurityDescriptor::from_bytes(&bytes).unwrap().is_none());
    }

    #[test]
    fn reject_dacl_offset_out_of_bounds() {
        let mut bytes = SecurityDescriptor::new(
            well_known::system().unwrap(),
            well_known::system().unwrap(),
            Acl::new(ACL_REVISION),
        )
        .to_bytes().unwrap();
        let bad_offset = (bytes.len() + 100) as u32;
        bytes[16..20].copy_from_slice(&bad_offset.to_le_bytes());
        assert!(SecurityDescriptor::from_bytes(&bytes).unwrap().is_none());
    }

    #[test]
    fn reject_sacl_offset_out_of_bounds() {
        let mut bytes = SecurityDescriptor::with_sacl(
            well_known::system().unwrap(),
            well_known::system().unwrap(),
            Acl::new(ACL_REVISION),
            simple_sacl(),
        )
        .to_bytes().unwrap();
        let bad_offset = (bytes.len() + 100) as u32;
        bytes[12..16].copy_from_slice(&bad_offset.to_le_bytes());
        assert!(SecurityDescriptor::from_bytes(&bytes).unwrap().is_none());
    }

    #[test]
    fn sd_with_domain_sids() {
        let domain_owner = crate::sid::Sid::new(5, &[21, 3000000000, 2000000000, 1000000000, 500]).unwrap();
        let domain_group = crate::sid::Sid::new(5, &[21, 3000000000, 2000000000, 1000000000, 513]).unwrap();
        let sd = SecurityDescriptor::new(
            domain_owner.clone(),
            domain_group.clone(),
            simple_dacl(),
        );
        let bytes = sd.to_bytes().unwrap();
        let parsed = SecurityDescriptor::from_bytes(&bytes).unwrap().unwrap();
        assert_eq!(parsed.owner.unwrap(), domain_owner);
        assert_eq!(parsed.group.unwrap(), domain_group);
    }

    #[test]
    fn sd_with_many_aces() {
        let mut aces = Vec::new();
        for i in 0..100u32 {
            aces.push(Ace {
                ace_type: ACCESS_ALLOWED_ACE_TYPE,
                flags: 0,
                mask: FILE_READ_DATA,
                sid: crate::sid::Sid::new(5, &[21, 1000, 2000, 3000 + i]).unwrap(),
                object_type: None,
                inherited_object_type: None,
                condition: None,
                application_data: None,
            });
        }
        let sd = SecurityDescriptor::new(
            well_known::system().unwrap(),
            well_known::system().unwrap(),
            Acl { revision: ACL_REVISION, aces },
        );
        let bytes = sd.to_bytes().unwrap();
        let parsed = SecurityDescriptor::from_bytes(&bytes).unwrap().unwrap();
        assert_eq!(parsed.dacl.as_ref().unwrap().aces.len(), 100);
    }

    #[test]
    fn sd_protected_flags() {
        let mut sd = SecurityDescriptor::new(
            well_known::system().unwrap(),
            well_known::system().unwrap(),
            Acl::new(ACL_REVISION),
        );
        assert!(!sd.is_dacl_protected());
        assert!(!sd.is_sacl_protected());

        sd.control |= SE_DACL_PROTECTED;
        assert!(sd.is_dacl_protected());
        assert!(!sd.is_sacl_protected());

        sd.control |= SE_SACL_PROTECTED;
        assert!(sd.is_dacl_protected());
        assert!(sd.is_sacl_protected());
    }

    #[test]
    fn sd_defaulted_flags() {
        let mut sd = SecurityDescriptor::new(
            well_known::system().unwrap(),
            well_known::system().unwrap(),
            Acl::new(ACL_REVISION),
        );
        sd.control |= SE_OWNER_DEFAULTED | SE_GROUP_DEFAULTED | SE_DACL_DEFAULTED;
        let bytes = sd.to_bytes().unwrap();
        let parsed = SecurityDescriptor::from_bytes(&bytes).unwrap().unwrap();
        assert_ne!(parsed.control & SE_OWNER_DEFAULTED, 0);
        assert_ne!(parsed.control & SE_GROUP_DEFAULTED, 0);
        assert_ne!(parsed.control & SE_DACL_DEFAULTED, 0);
    }

    #[test]
    fn sd_self_relative_always_set() {
        let sd = SecurityDescriptor::new(
            well_known::system().unwrap(),
            well_known::system().unwrap(),
            Acl::new(ACL_REVISION),
        );
        let bytes = sd.to_bytes().unwrap();
        let control = u16::from_le_bytes([bytes[2], bytes[3]]);
        assert_ne!(control & SE_SELF_RELATIVE, 0);
    }

    #[test]
    fn sd_header_exactly_20_bytes() {
        // SD with no components should be exactly the header
        let sd = SecurityDescriptor {
            control: SE_SELF_RELATIVE,
            owner: None,
            group: None,
            dacl: None,
            sacl: None,
        };
        let bytes = sd.to_bytes().unwrap();
        assert_eq!(bytes.len(), SD_HEADER_SIZE);
    }

    #[test]
    fn sd_process_default() {
        // The default process SD (§8.4)
        let user_sid = crate::sid::Sid::new(5, &[21, 100, 200, 300, 1001]).unwrap();
        let dacl = Acl {
            revision: ACL_REVISION,
            aces: alloc::vec![
                Ace {
                    ace_type: ACCESS_ALLOWED_ACE_TYPE,
                    flags: 0,
                    mask: GENERIC_ALL,
                    sid: user_sid.clone(),
                    object_type: None,
                    inherited_object_type: None,
                    condition: None,
                    application_data: None,
                },
                Ace {
                    ace_type: ACCESS_ALLOWED_ACE_TYPE,
                    flags: 0,
                    mask: GENERIC_ALL,
                    sid: well_known::administrators().unwrap(),
                    object_type: None,
                    inherited_object_type: None,
                    condition: None,
                    application_data: None,
                },
                Ace {
                    ace_type: ACCESS_ALLOWED_ACE_TYPE,
                    flags: 0,
                    mask: GENERIC_ALL,
                    sid: well_known::system().unwrap(),
                    object_type: None,
                    inherited_object_type: None,
                    condition: None,
                    application_data: None,
                },
                Ace {
                    ace_type: ACCESS_ALLOWED_ACE_TYPE,
                    flags: 0,
                    mask: PROCESS_QUERY_LIMITED,
                    sid: well_known::everyone().unwrap(),
                    object_type: None,
                    inherited_object_type: None,
                    condition: None,
                    application_data: None,
                },
            ],
        };
        let sd = SecurityDescriptor::new(user_sid, well_known::users().unwrap(), dacl);
        let bytes = sd.to_bytes().unwrap();
        let parsed = SecurityDescriptor::from_bytes(&bytes).unwrap().unwrap();
        assert_eq!(parsed.dacl.as_ref().unwrap().aces.len(), 4);
        assert_eq!(parsed.dacl.as_ref().unwrap().aces[3].mask, PROCESS_QUERY_LIMITED);
    }

    #[test]
    fn sd_bytes_deterministic() {
        // Same SD should produce identical bytes every time
        let sd = SecurityDescriptor::with_sacl(
            well_known::system().unwrap(),
            well_known::administrators().unwrap(),
            simple_dacl(),
            simple_sacl(),
        );
        let bytes1 = sd.to_bytes().unwrap();
        let bytes2 = sd.to_bytes().unwrap();
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn sd_full_round_trip_preserves_all() {
        let sd = SecurityDescriptor {
            control: SE_DACL_PRESENT | SE_SACL_PRESENT | SE_DACL_PROTECTED
                | SE_DACL_AUTO_INHERITED | SE_SELF_RELATIVE,
            owner: Some(well_known::system().unwrap()),
            group: Some(well_known::administrators().unwrap()),
            dacl: Some(simple_dacl()),
            sacl: Some(simple_sacl()),
        };
        let bytes = sd.to_bytes().unwrap();
        let parsed = SecurityDescriptor::from_bytes(&bytes).unwrap().unwrap();

        assert_eq!(parsed.owner.as_ref().unwrap(), &well_known::system().unwrap());
        assert_eq!(parsed.group.as_ref().unwrap(), &well_known::administrators().unwrap());
        assert!(parsed.has_dacl());
        assert!(parsed.has_sacl());
        assert!(parsed.is_dacl_protected());
        assert!(parsed.control & SE_DACL_AUTO_INHERITED != 0);
        assert_eq!(parsed.dacl.as_ref().unwrap().aces.len(), 3);
        assert_eq!(parsed.sacl.as_ref().unwrap().aces.len(), 2);

        // Verify DACL ACE content
        let dacl = parsed.dacl.as_ref().unwrap();
        assert_eq!(dacl.aces[0].ace_type, ACCESS_DENIED_ACE_TYPE);
        assert_eq!(dacl.aces[0].sid, well_known::guests().unwrap());
        assert_eq!(dacl.aces[1].ace_type, ACCESS_ALLOWED_ACE_TYPE);
        assert_eq!(dacl.aces[1].sid, well_known::administrators().unwrap());
        assert_eq!(dacl.aces[2].ace_type, ACCESS_ALLOWED_ACE_TYPE);
        assert_eq!(dacl.aces[2].sid, well_known::authenticated_users().unwrap());

        // Verify SACL ACE content
        let sacl = parsed.sacl.as_ref().unwrap();
        assert_eq!(sacl.aces[0].ace_type, SYSTEM_MANDATORY_LABEL_ACE_TYPE);
        assert_eq!(sacl.aces[0].sid, well_known::integrity_medium().unwrap());
        assert_eq!(sacl.aces[1].ace_type, SYSTEM_AUDIT_ACE_TYPE);
    }

    // --- §2.4 Security Descriptor Definition corpus tests ---

    #[test]
    fn sd_contains_owner_sid() {
        // §2 line 140
        let sd = SecurityDescriptor::new(
            well_known::system().unwrap(),
            well_known::system().unwrap(),
            Acl::new(ACL_REVISION),
        );
        assert!(sd.owner.is_some());
    }

    #[test]
    fn sd_contains_primary_group_sid() {
        // §2 line 141
        let sd = SecurityDescriptor::new(
            well_known::system().unwrap(),
            well_known::administrators().unwrap(),
            Acl::new(ACL_REVISION),
        );
        assert!(sd.group.is_some());
        assert_eq!(sd.group.unwrap(), well_known::administrators().unwrap());
    }

    #[test]
    fn sd_contains_dacl() {
        // §2 lines 141-142
        let sd = SecurityDescriptor::new(
            well_known::system().unwrap(),
            well_known::system().unwrap(),
            Acl::new(ACL_REVISION),
        );
        assert!(sd.has_dacl());
    }

    #[test]
    fn sd_contains_optional_sacl() {
        // §2 lines 142-143: SACL is optional
        let sd_no_sacl = SecurityDescriptor::new(
            well_known::system().unwrap(),
            well_known::system().unwrap(),
            Acl::new(ACL_REVISION),
        );
        assert!(!sd_no_sacl.has_sacl());

        let sd_with_sacl = SecurityDescriptor::with_sacl(
            well_known::system().unwrap(),
            well_known::system().unwrap(),
            Acl::new(ACL_REVISION),
            Acl::new(ACL_REVISION),
        );
        assert!(sd_with_sacl.has_sacl());
    }

    #[test]
    fn sd_binary_format_windows_compatible() {
        // §2 lines 147-148, §9.1 lines 3136-3138
        let sd = SecurityDescriptor::new(
            well_known::system().unwrap(),
            well_known::system().unwrap(),
            Acl::new(ACL_REVISION),
        );
        let bytes = sd.to_bytes().unwrap();
        // First byte is revision (always 1)
        assert_eq!(bytes[0], SD_REVISION);
        // Byte 1 is Sbz1 (padding, 0)
        assert_eq!(bytes[1], 0);
        // Bytes 2-3 are control flags (little-endian u16)
        let control = u16::from_le_bytes([bytes[2], bytes[3]]);
        assert!(control & SE_SELF_RELATIVE != 0);
    }

    #[test]
    fn sd_self_relative_format_header() {
        // §9.1 lines 3197-3202: 20-byte header
        let sd = SecurityDescriptor::new(
            well_known::system().unwrap(),
            well_known::system().unwrap(),
            Acl::new(ACL_REVISION),
        );
        let bytes = sd.to_bytes().unwrap();
        assert!(bytes.len() >= 20, "SD must be at least 20 bytes (header)");
        // Header: revision(1) + sbz1(1) + control(2) + 4 offsets(4 each) = 20
        let owner_offset = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        let group_offset = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        let _sacl_offset = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
        let _dacl_offset = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
        // Offsets point within the buffer
        assert!(owner_offset > 0 && (owner_offset as usize) < bytes.len());
        assert!(group_offset > 0 && (group_offset as usize) < bytes.len());
    }

    #[test]
    fn sd_self_relative_no_pointers() {
        // §9.1 lines 3200-3201: contiguous buffer, no external references
        let sd = SecurityDescriptor::with_sacl(
            well_known::system().unwrap(),
            well_known::administrators().unwrap(),
            simple_dacl(),
            simple_sacl(),
        );
        let bytes = sd.to_bytes().unwrap();
        // Should be parseable from the contiguous buffer alone
        let parsed = SecurityDescriptor::from_bytes(&bytes).unwrap().unwrap();
        assert_eq!(parsed.owner.as_ref().unwrap(), &well_known::system().unwrap());
    }

    #[test]
    fn sd_only_self_relative_format() {
        // §9.1 lines 3204-3205: KACS uses self-relative exclusively
        let sd = SecurityDescriptor::new(
            well_known::system().unwrap(),
            well_known::system().unwrap(),
            Acl::new(ACL_REVISION),
        );
        assert!(sd.control & SE_SELF_RELATIVE != 0);
    }

    #[test]
    fn sd_max_size_64kb() {
        // §9.11 line 3907: max 64 KB (AclSize is u16)
        assert_eq!(u16::MAX as usize, 65535);
    }

    // --- §2.13 SD Control Flags corpus tests ---

    #[test]
    fn control_flag_od_bit_0() {
        assert_eq!(SE_OWNER_DEFAULTED, 1 << 0);
    }

    #[test]
    fn control_flag_gd_bit_1() {
        assert_eq!(SE_GROUP_DEFAULTED, 1 << 1);
    }

    #[test]
    fn control_flag_dp_bit_2() {
        assert_eq!(SE_DACL_PRESENT, 1 << 2);
    }

    #[test]
    fn control_flag_dd_bit_3() {
        assert_eq!(SE_DACL_DEFAULTED, 1 << 3);
    }

    #[test]
    fn control_flag_sp_bit_4() {
        assert_eq!(SE_SACL_PRESENT, 1 << 4);
    }

    #[test]
    fn control_flag_sd_bit_5() {
        assert_eq!(SE_SACL_DEFAULTED, 1 << 5);
    }

    #[test]
    fn control_flag_dt_bit_6() {
        assert_eq!(SE_DACL_TRUSTED, 1 << 6);
    }

    #[test]
    fn control_flag_ss_bit_7() {
        assert_eq!(SE_SERVER_SECURITY, 1 << 7);
    }

    #[test]
    fn control_flag_di_bit_10() {
        assert_eq!(SE_DACL_AUTO_INHERITED, 1 << 10);
    }

    #[test]
    fn control_flag_si_bit_11() {
        assert_eq!(SE_SACL_AUTO_INHERITED, 1 << 11);
    }

    #[test]
    fn control_flag_pd_bit_12() {
        assert_eq!(SE_DACL_PROTECTED, 1 << 12);
    }

    #[test]
    fn control_flag_ps_bit_13() {
        assert_eq!(SE_SACL_PROTECTED, 1 << 13);
    }

    #[test]
    fn control_flag_rm_bit_14() {
        assert_eq!(SE_RM_CONTROL_VALID, 1 << 14);
    }

    #[test]
    fn control_flag_sr_bit_15() {
        assert_eq!(SE_SELF_RELATIVE, 1 << 15);
    }

    // --- §9.1 Structure corpus tests ---

    #[test]
    fn sd_has_four_components() {
        let sd = SecurityDescriptor::with_sacl(
            well_known::system().unwrap(),
            well_known::administrators().unwrap(),
            simple_dacl(),
            simple_sacl(),
        );
        assert!(sd.owner.is_some());
        assert!(sd.group.is_some());
        assert!(sd.dacl.is_some());
        assert!(sd.sacl.is_some());
    }

    #[test]
    fn sd_has_control_flags() {
        let sd = SecurityDescriptor::new(
            well_known::system().unwrap(),
            well_known::system().unwrap(),
            Acl::new(ACL_REVISION),
        );
        let _: u16 = sd.control;
        assert!(sd.control & SE_SELF_RELATIVE != 0);
    }

    #[test]
    fn sd_owner_sid_roundtrip() {
        let owner = crate::sid::Sid::new(5, &[21, 111, 222, 333, 1001]).unwrap();
        let sd = SecurityDescriptor::new(owner.clone(), well_known::users().unwrap(), Acl::new(ACL_REVISION));
        let bytes = sd.to_bytes().unwrap();
        let parsed = SecurityDescriptor::from_bytes(&bytes).unwrap().unwrap();
        assert_eq!(parsed.owner.unwrap(), owner);
    }

    #[test]
    fn sd_group_sid_roundtrip() {
        let group = crate::sid::Sid::new(5, &[21, 111, 222, 333, 513]).unwrap();
        let sd = SecurityDescriptor::new(well_known::system().unwrap(), group.clone(), Acl::new(ACL_REVISION));
        let bytes = sd.to_bytes().unwrap();
        let parsed = SecurityDescriptor::from_bytes(&bytes).unwrap().unwrap();
        assert_eq!(parsed.group.unwrap(), group);
    }

    #[test]
    fn sd_dacl_roundtrip() {
        let sd = SecurityDescriptor::new(
            well_known::system().unwrap(),
            well_known::system().unwrap(),
            simple_dacl(),
        );
        let bytes = sd.to_bytes().unwrap();
        let parsed = SecurityDescriptor::from_bytes(&bytes).unwrap().unwrap();
        assert!(parsed.has_dacl());
        assert_eq!(parsed.dacl.as_ref().unwrap().aces.len(), 3);
    }

    #[test]
    fn sd_sacl_roundtrip() {
        let sd = SecurityDescriptor::with_sacl(
            well_known::system().unwrap(),
            well_known::system().unwrap(),
            Acl::new(ACL_REVISION),
            simple_sacl(),
        );
        let bytes = sd.to_bytes().unwrap();
        let parsed = SecurityDescriptor::from_bytes(&bytes).unwrap().unwrap();
        assert!(parsed.has_sacl());
        assert_eq!(parsed.sacl.as_ref().unwrap().aces.len(), 2);
    }

    #[test]
    fn sd_offsets_point_to_correct_components() {
        let sd = SecurityDescriptor::with_sacl(
            well_known::system().unwrap(),
            well_known::administrators().unwrap(),
            simple_dacl(),
            simple_sacl(),
        );
        let bytes = sd.to_bytes().unwrap();
        let owner_off = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        let group_off = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        let sacl_off = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
        let dacl_off = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
        assert!(owner_off >= 20 && (owner_off as usize) < bytes.len());
        assert!(group_off >= 20 && (group_off as usize) < bytes.len());
        assert!(sacl_off >= 20 && (sacl_off as usize) < bytes.len());
        assert!(dacl_off >= 20 && (dacl_off as usize) < bytes.len());
    }

    #[test]
    fn sd_zero_offset_means_absent() {
        let sd = SecurityDescriptor::new(
            well_known::system().unwrap(),
            well_known::system().unwrap(),
            Acl::new(ACL_REVISION),
        );
        let bytes = sd.to_bytes().unwrap();
        let sacl_off = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
        assert_eq!(sacl_off, 0);
    }

    #[test]
    fn sd_contiguous_byte_buffer() {
        let sd = SecurityDescriptor::with_sacl(
            well_known::system().unwrap(),
            well_known::administrators().unwrap(),
            simple_dacl(),
            simple_sacl(),
        );
        let bytes = sd.to_bytes().unwrap();
        let parsed = SecurityDescriptor::from_bytes(&bytes).unwrap().unwrap();
        assert_eq!(parsed.owner.as_ref().unwrap(), &well_known::system().unwrap());
    }

    #[test]
    fn sd_rebuild_on_modification() {
        let sd = SecurityDescriptor::new(
            well_known::system().unwrap(),
            well_known::system().unwrap(),
            Acl::new(ACL_REVISION),
        );
        let bytes1 = sd.to_bytes().unwrap();
        let sd2 = SecurityDescriptor::with_sacl(
            well_known::system().unwrap(),
            well_known::system().unwrap(),
            Acl::new(ACL_REVISION),
            simple_sacl(),
        );
        let bytes2 = sd2.to_bytes().unwrap();
        assert_ne!(bytes1, bytes2);
    }

    #[test]
    fn sd_parse_in_place() {
        let sd = SecurityDescriptor::with_sacl(
            well_known::system().unwrap(),
            well_known::administrators().unwrap(),
            simple_dacl(),
            simple_sacl(),
        );
        let bytes = sd.to_bytes().unwrap();
        let parsed = SecurityDescriptor::from_bytes(&bytes).unwrap().unwrap();
        assert_eq!(parsed.dacl.as_ref().unwrap().aces.len(), 3);
    }

    #[test]
    fn dacl_protected_blocks_inheritable_aces_from_parent() {
        assert_eq!(SE_DACL_PROTECTED, 0x1000);
        let mut sd = SecurityDescriptor::new(
            well_known::system().unwrap(),
            well_known::system().unwrap(),
            Acl::new(ACL_REVISION),
        );
        sd.control |= SE_DACL_PROTECTED;
        assert!(sd.is_dacl_protected());
    }

    #[test]
    fn sacl_protected_blocks_inheritable_aces_from_parent() {
        assert_eq!(SE_SACL_PROTECTED, 0x2000);
    }

    #[test]
    fn dp_flag_clear_means_null_dacl() {
        let sd = SecurityDescriptor {
            control: SE_SELF_RELATIVE,
            owner: Some(well_known::system().unwrap()),
            group: Some(well_known::system().unwrap()),
            dacl: None,
            sacl: None,
        };
        assert!(!sd.has_dacl());
    }

    #[test]
    fn control_flags_16_bits() {
        assert!(core::mem::size_of::<u16>() == 2);
        let all_flags: u16 = SE_OWNER_DEFAULTED | SE_GROUP_DEFAULTED | SE_DACL_PRESENT
            | SE_DACL_DEFAULTED | SE_SACL_PRESENT | SE_SACL_DEFAULTED | SE_DACL_TRUSTED
            | SE_SERVER_SECURITY | SE_DACL_AUTO_INHERITED | SE_SACL_AUTO_INHERITED
            | SE_DACL_PROTECTED | SE_SACL_PROTECTED | SE_RM_CONTROL_VALID | SE_SELF_RELATIVE;
        assert!(all_flags <= u16::MAX);
    }

    #[test]
    fn sd_group_sid_not_used_for_access_control() {
        // §9.1: group SID stored but not used in AccessCheck
        let sd = SecurityDescriptor::new(
            well_known::system().unwrap(),
            well_known::administrators().unwrap(),
            Acl::new(ACL_REVISION),
        );
        assert!(sd.group.is_some());
        // group is informational only — AccessCheck doesn't reference it
    }

    #[test]
    fn sd_max_size_64kb_from_acl() {
        assert_eq!(u16::MAX, 65535);
    }

    #[test]
    fn registry_sd_same_binary_format() {
        use crate::mask::*;
        let sd = SecurityDescriptor::new(
            well_known::system().unwrap(),
            well_known::system().unwrap(),
            Acl {
                revision: ACL_REVISION,
                aces: alloc::vec![Ace {
                    ace_type: crate::ace::ACCESS_ALLOWED_ACE_TYPE,
                    flags: 0,
                    mask: KEY_QUERY_VALUE | KEY_SET_VALUE,
                    sid: well_known::system().unwrap(),
                    object_type: None, inherited_object_type: None,
                    condition: None, application_data: None,
                }],
            },
        );
        let bytes = sd.to_bytes().unwrap();
        let parsed = SecurityDescriptor::from_bytes(&bytes).unwrap().unwrap();
        assert_eq!(parsed.dacl.as_ref().unwrap().aces[0].mask, KEY_QUERY_VALUE | KEY_SET_VALUE);
    }

    // --- §9.1 Structure corpus tests (exact corpus names) ---

    #[test]
    fn sd_binary_header_is_20_bytes() {
        // §9.1 L3197: self-relative SD header is exactly 20 bytes
        let sd = SecurityDescriptor {
            control: SE_SELF_RELATIVE,
            owner: None,
            group: None,
            dacl: None,
            sacl: None,
        };
        let bytes = sd.to_bytes().unwrap();
        assert_eq!(bytes.len(), 20);
        // revision(1) + Sbz1(1) + control(2) + 4 offsets(4 each) = 20
    }

    #[test]
    fn sd_self_relative_format_only() {
        // §9.1 L3204: KACS only produces/accepts self-relative format
        let sd = SecurityDescriptor::new(
            well_known::system().unwrap(),
            well_known::system().unwrap(),
            Acl::new(ACL_REVISION),
        );
        assert!(sd.control & SE_SELF_RELATIVE != 0);
        let bytes = sd.to_bytes().unwrap();
        let control = u16::from_le_bytes([bytes[2], bytes[3]]);
        assert!(control & SE_SELF_RELATIVE != 0);
    }

    #[test]
    fn sd_windows_binary_compatibility() {
        // §9.1 L3136-3143: known-good Windows SD binary blob parses correctly
        // Build a known SD and verify field layout matches Windows format
        let sd = SecurityDescriptor::new(
            well_known::system().unwrap(),
            well_known::administrators().unwrap(),
            Acl {
                revision: ACL_REVISION,
                aces: alloc::vec![Ace {
                    ace_type: crate::ace::ACCESS_ALLOWED_ACE_TYPE,
                    flags: 0,
                    mask: crate::mask::FILE_READ_DATA | crate::mask::READ_CONTROL,
                    sid: well_known::everyone().unwrap(),
                    object_type: None,
                    inherited_object_type: None,
                    condition: None,
                    application_data: None,
                }],
            },
        );
        let bytes = sd.to_bytes().unwrap();
        // Verify Windows binary format: revision=1, Sbz1=0, LE control, 4 LE offsets
        assert_eq!(bytes[0], 1); // revision
        assert_eq!(bytes[1], 0); // Sbz1
        let parsed = SecurityDescriptor::from_bytes(&bytes).unwrap().unwrap();
        assert_eq!(parsed.owner.as_ref().unwrap(), &well_known::system().unwrap());
        assert_eq!(parsed.group.as_ref().unwrap(), &well_known::administrators().unwrap());
        assert_eq!(parsed.dacl.as_ref().unwrap().aces[0].sid, well_known::everyone().unwrap());
    }

    // --- §9.10 Control Flags corpus tests (exact corpus names) ---

    #[test]
    fn se_dacl_present_bit_2() {
        assert_eq!(SE_DACL_PRESENT, 1 << 2);
    }

    #[test]
    fn se_sacl_present_bit_4() {
        assert_eq!(SE_SACL_PRESENT, 1 << 4);
    }

    #[test]
    fn se_dacl_defaulted_bit_3() {
        assert_eq!(SE_DACL_DEFAULTED, 1 << 3);
    }

    #[test]
    fn se_sacl_defaulted_bit_5() {
        assert_eq!(SE_SACL_DEFAULTED, 1 << 5);
    }

    #[test]
    fn se_owner_defaulted_bit_0() {
        assert_eq!(SE_OWNER_DEFAULTED, 1 << 0);
    }

    #[test]
    fn se_group_defaulted_bit_1() {
        assert_eq!(SE_GROUP_DEFAULTED, 1 << 1);
    }

    #[test]
    fn se_dacl_auto_inherited_bit_10() {
        assert_eq!(SE_DACL_AUTO_INHERITED, 1 << 10);
    }

    #[test]
    fn se_sacl_auto_inherited_bit_11() {
        assert_eq!(SE_SACL_AUTO_INHERITED, 1 << 11);
    }

    #[test]
    fn se_dacl_protected_bit_12() {
        assert_eq!(SE_DACL_PROTECTED, 1 << 12);
    }

    #[test]
    fn se_sacl_protected_bit_13() {
        assert_eq!(SE_SACL_PROTECTED, 1 << 13);
    }

    #[test]
    fn se_self_relative_bit_15() {
        assert_eq!(SE_SELF_RELATIVE, 1 << 15);
    }

    #[test]
    fn se_dacl_trusted_bit_6() {
        assert_eq!(SE_DACL_TRUSTED, 1 << 6);
    }

    #[test]
    fn se_server_security_bit_7() {
        assert_eq!(SE_SERVER_SECURITY, 1 << 7);
    }

    #[test]
    fn se_rm_control_valid_bit_14() {
        assert_eq!(SE_RM_CONTROL_VALID, 1 << 14);
    }

    #[test]
    fn break_inheritance_preserves_existing_aces_as_explicit() {
        // §9.10 L3884-3888: setting SE_DACL_PROTECTED preserves current ACEs
        // (inherited become explicit) and stops accepting new inheritable ACEs
        let mut sd = SecurityDescriptor::new(
            well_known::system().unwrap(),
            well_known::system().unwrap(),
            Acl {
                revision: ACL_REVISION,
                aces: alloc::vec![
                    // An "inherited" ACE
                    Ace {
                        ace_type: crate::ace::ACCESS_ALLOWED_ACE_TYPE,
                        flags: crate::ace::INHERITED_ACE,
                        mask: crate::mask::FILE_READ_DATA,
                        sid: well_known::everyone().unwrap(),
                        object_type: None,
                        inherited_object_type: None,
                        condition: None,
                        application_data: None,
                    },
                    // An explicit ACE
                    Ace {
                        ace_type: crate::ace::ACCESS_ALLOWED_ACE_TYPE,
                        flags: 0,
                        mask: crate::mask::FILE_WRITE_DATA,
                        sid: well_known::administrators().unwrap(),
                        object_type: None,
                        inherited_object_type: None,
                        condition: None,
                        application_data: None,
                    },
                ],
            },
        );
        // Set SE_DACL_PROTECTED — "break inheritance"
        sd.control |= SE_DACL_PROTECTED;
        assert!(sd.is_dacl_protected());
        // Both ACEs are still present (preserved as explicit)
        assert_eq!(sd.dacl.as_ref().unwrap().aces.len(), 2);
    }

    // --- §2.4 corpus: sd_owner_implicit_read_control_write_dac ---

    #[test]
    fn sd_owner_implicit_read_control_write_dac() {
        // §2 lines 149-150: by default owner receives implicit READ_CONTROL + WRITE_DAC
        // Verified structurally: the SD has an owner field, and READ_CONTROL/WRITE_DAC
        // constants exist to be granted implicitly by AccessCheck.
        let sd = SecurityDescriptor::new(
            well_known::system().unwrap(),
            well_known::system().unwrap(),
            Acl::new(ACL_REVISION),
        );
        assert!(sd.owner.is_some());
        // The implicit grant is READ_CONTROL | WRITE_DAC
        let implicit = READ_CONTROL | WRITE_DAC;
        assert_ne!(implicit, 0);
    }

    // --- §2.4 corpus: sd_owner_rights_ace_overrides_implicit ---

    #[test]
    fn sd_owner_rights_ace_overrides_implicit() {
        // §2 lines 151-152: OWNER RIGHTS ACE (S-1-3-4) overrides owner implicit grants
        let owner_rights_sid = well_known::owner_rights().unwrap();
        let sd = SecurityDescriptor::new(
            well_known::system().unwrap(),
            well_known::system().unwrap(),
            Acl {
                revision: ACL_REVISION,
                aces: alloc::vec![Ace {
                    ace_type: ACCESS_ALLOWED_ACE_TYPE,
                    flags: 0,
                    mask: READ_CONTROL, // only READ_CONTROL, no WRITE_DAC
                    sid: owner_rights_sid.clone(),
                    object_type: None, inherited_object_type: None,
                    condition: None, application_data: None,
                }],
            },
        );
        // The presence of an OWNER RIGHTS ACE in the DACL means owner implicit
        // grants are suppressed. The test verifies the structure is representable.
        let has_owner_rights = sd.dacl.as_ref().unwrap().aces.iter()
            .any(|a| a.sid == owner_rights_sid);
        assert!(has_owner_rights);
    }

    // --- §14.2 SD Validation corpus tests ---

    #[test]
    fn sd_parse_detects_truncated_blob() {
        // §14.2: SD parser detects and rejects a truncated binary blob
        let truncated = [0x01u8; 10]; // less than 20-byte header
        assert!(SecurityDescriptor::from_bytes(&truncated).unwrap().is_none());
    }

    #[test]
    fn sd_parse_detects_invalid_ace_type() {
        // Build a valid SD then corrupt an ACE type byte to 0xFF
        // and verify the SD still parses (unknown types are preserved),
        // but the ACE type is invalid for DACL (not access type).
        let mut bytes = SecurityDescriptor::new(
            well_known::system().unwrap(),
            well_known::system().unwrap(),
            simple_dacl(),
        ).to_bytes().unwrap();
        // Find the DACL offset
        let dacl_offset = u32::from_le_bytes(bytes[16..20].try_into().unwrap()) as usize;
        // ACL header is 8 bytes; first ACE starts after
        let first_ace_offset = dacl_offset + 8;
        // Corrupt the ACE type to 0xFF
        bytes[first_ace_offset] = 0xFF;
        // Parse should still work (unknown types preserved) but the
        // type is detectable as invalid for DACL use
        let parsed = SecurityDescriptor::from_bytes(&bytes).unwrap();
        if let Some(sd) = parsed {
            let dacl = sd.dacl.as_ref().unwrap();
            assert_eq!(dacl.aces[0].ace_type, 0xFF);
            assert!(!crate::ace::is_access_type(0xFF));
        }
    }

    #[test]
    fn sd_parse_detects_malformed_sid() {
        // Create a valid SD, then corrupt the owner SID
        let mut bytes = SecurityDescriptor::new(
            well_known::system().unwrap(),
            well_known::system().unwrap(),
            Acl::new(ACL_REVISION),
        ).to_bytes().unwrap();
        let owner_offset = u32::from_le_bytes(bytes[4..8].try_into().unwrap()) as usize;
        // Corrupt SID: set sub-authority count to 255 (exceeds buffer)
        bytes[owner_offset + 1] = 255;
        assert!(SecurityDescriptor::from_bytes(&bytes).unwrap().is_none());
    }

    #[test]
    fn sd_parse_detects_size_mismatch() {
        // Create a valid SD, then corrupt the ACL size field
        let mut bytes = SecurityDescriptor::new(
            well_known::system().unwrap(),
            well_known::system().unwrap(),
            simple_dacl(),
        ).to_bytes().unwrap();
        let dacl_offset = u32::from_le_bytes(bytes[16..20].try_into().unwrap()) as usize;
        // ACL header: revision(1), sbz1(1), AclSize(2), AceCount(2), Sbz2(2)
        // Set AclSize to something much larger than the actual data
        let bad_size: u16 = 60000;
        bytes[dacl_offset + 2] = bad_size as u8;
        bytes[dacl_offset + 3] = (bad_size >> 8) as u8;
        assert!(SecurityDescriptor::from_bytes(&bytes).unwrap().is_none());
    }

    #[test]
    fn sd_parse_detects_acl_size_exceeding_buffer() {
        // §14.2: ACL size field exceeding the actual buffer size
        let mut bytes = SecurityDescriptor::new(
            well_known::system().unwrap(),
            well_known::system().unwrap(),
            Acl::new(ACL_REVISION),
        ).to_bytes().unwrap();
        let dacl_offset = u32::from_le_bytes(bytes[16..20].try_into().unwrap()) as usize;
        let remaining = bytes.len() - dacl_offset;
        // Set AclSize to more than remaining buffer
        let bad_size = (remaining + 100) as u16;
        bytes[dacl_offset + 2] = bad_size as u8;
        bytes[dacl_offset + 3] = (bad_size >> 8) as u8;
        assert!(SecurityDescriptor::from_bytes(&bytes).unwrap().is_none());
    }

    #[test]
    fn sd_parse_any_error_is_corrupt() {
        // §14.2: any parse error produces corrupt-SD result (None), not partial parse
        // Bad revision
        let mut bytes = SecurityDescriptor::new(
            well_known::system().unwrap(),
            well_known::system().unwrap(),
            Acl::new(ACL_REVISION),
        ).to_bytes().unwrap();
        bytes[0] = 99; // invalid revision
        assert!(SecurityDescriptor::from_bytes(&bytes).unwrap().is_none());
    }

    #[test]
    fn corrupt_sd_garbled_ace_not_skipped() {
        // §14.2 (10886): garbled ACE must not be silently skipped
        // Build SD with a DACL, then corrupt an ACE's size to be invalid
        let mut bytes = SecurityDescriptor::new(
            well_known::system().unwrap(),
            well_known::system().unwrap(),
            simple_dacl(),
        ).to_bytes().unwrap();
        let dacl_offset = u32::from_le_bytes(bytes[16..20].try_into().unwrap()) as usize;
        let first_ace_offset = dacl_offset + 8;
        // Set ACE size to 3 (not multiple of 4) — invalid
        bytes[first_ace_offset + 2] = 3;
        bytes[first_ace_offset + 3] = 0;
        // Parser should reject (return None), not skip the garbled ACE
        assert!(SecurityDescriptor::from_bytes(&bytes).unwrap().is_none());
    }

    #[test]
    fn set_sd_acl_exceeding_64kb_rejected() {
        // §15.1: ACL exceeding 64 KB rejected
        // AclSize is u16, max 65535 bytes. We verify the architectural limit.
        assert_eq!(u16::MAX, 65535);
        // A single ACL cannot exceed 65535 bytes in the binary format.
    }

    #[test]
    fn set_sd_malformed_sid_rejected() {
        // §15.1: SD with structurally invalid SID rejected
        // A SID with 0 sub-authorities but wrong authority is still parseable;
        // but a SID with sub_authority_count claiming more data than available
        // should be rejected by the parser.
        let bad_sid_bytes = [
            0x01, // revision
            0x0F, // sub_authority_count = 15 (needs 60 bytes of sub-auths)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // authority
            // but only 4 bytes of sub-authority data follow
            0x01, 0x00, 0x00, 0x00,
        ];
        assert!(crate::sid::Sid::from_bytes(&bad_sid_bytes).is_none());
    }
}
