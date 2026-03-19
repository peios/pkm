// Security Descriptor — the complete security policy for a protected object (§9).
//
// Self-relative binary format (MS-DTYP §2.4.6): 20-byte header with
// four 32-bit offsets pointing to owner SID, group SID, SACL, and DACL
// within the contiguous buffer. Byte-compatible with Windows and Samba.
//
// Every file, registry key, IPC endpoint, token, process, and service
// in Peios has a Security Descriptor.

use alloc::vec::Vec;
use crate::acl::Acl;
use crate::sid::Sid;

/// SD revision. Always 1.
pub const SD_REVISION: u8 = 1;

// --- Control flags (§9.10) ---

pub const SE_OWNER_DEFAULTED: u16 = 0x0001;
pub const SE_GROUP_DEFAULTED: u16 = 0x0002;
pub const SE_DACL_PRESENT: u16 = 0x0004;
pub const SE_DACL_DEFAULTED: u16 = 0x0008;
pub const SE_SACL_PRESENT: u16 = 0x0010;
pub const SE_SACL_DEFAULTED: u16 = 0x0020;
pub const SE_DACL_TRUSTED: u16 = 0x0040;
pub const SE_SERVER_SECURITY: u16 = 0x0080;
pub const SE_DACL_AUTO_INHERIT_REQ: u16 = 0x0100;
pub const SE_SACL_AUTO_INHERIT_REQ: u16 = 0x0200;
pub const SE_DACL_AUTO_INHERITED: u16 = 0x0400;
pub const SE_SACL_AUTO_INHERITED: u16 = 0x0800;
pub const SE_DACL_PROTECTED: u16 = 0x1000;
pub const SE_SACL_PROTECTED: u16 = 0x2000;
pub const SE_RM_CONTROL_VALID: u16 = 0x4000;
pub const SE_SELF_RELATIVE: u16 = 0x8000;

/// Self-relative header size.
const SD_HEADER_SIZE: usize = 20;

/// A parsed Security Descriptor.
#[derive(Clone, Debug)]
pub struct SecurityDescriptor {
    pub control: u16,
    pub owner: Option<Sid>,
    pub group: Option<Sid>,
    pub dacl: Option<Acl>,
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
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < SD_HEADER_SIZE {
            return None;
        }

        let revision = data[0];
        if revision != SD_REVISION {
            return None;
        }

        // data[1] is Sbz1 (resource manager control, usually 0)

        let control = u16::from_le_bytes([data[2], data[3]]);

        // Self-relative format: four 32-bit offsets
        let owner_offset = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
        let group_offset = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;
        let sacl_offset = u32::from_le_bytes([data[12], data[13], data[14], data[15]]) as usize;
        let dacl_offset = u32::from_le_bytes([data[16], data[17], data[18], data[19]]) as usize;

        let owner = if owner_offset != 0 {
            if owner_offset >= data.len() {
                return None;
            }
            Some(Sid::from_bytes(&data[owner_offset..])?)
        } else {
            None
        };

        let group = if group_offset != 0 {
            if group_offset >= data.len() {
                return None;
            }
            Some(Sid::from_bytes(&data[group_offset..])?)
        } else {
            None
        };

        let sacl = if sacl_offset != 0 && control & SE_SACL_PRESENT != 0 {
            if sacl_offset >= data.len() {
                return None;
            }
            Some(Acl::from_bytes(&data[sacl_offset..])?)
        } else {
            None
        };

        let dacl = if dacl_offset != 0 && control & SE_DACL_PRESENT != 0 {
            if dacl_offset >= data.len() {
                return None;
            }
            Some(Acl::from_bytes(&data[dacl_offset..])?)
        } else {
            None
        };

        Some(SecurityDescriptor {
            control,
            owner,
            group,
            dacl,
            sacl,
        })
    }

    /// Serialize to self-relative binary format.
    pub fn to_bytes(&self) -> Vec<u8> {
        // Compute sizes and offsets
        let owner_bytes = self.owner.as_ref().map(|s| s.to_bytes());
        let group_bytes = self.group.as_ref().map(|s| s.to_bytes());
        let sacl_bytes = if self.control & SE_SACL_PRESENT != 0 {
            self.sacl.as_ref().map(|a| a.to_bytes())
        } else {
            None
        };
        let dacl_bytes = if self.control & SE_DACL_PRESENT != 0 {
            self.dacl.as_ref().map(|a| a.to_bytes())
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

        let mut buf = Vec::with_capacity(offset);

        // Header
        buf.push(SD_REVISION);
        buf.push(0); // Sbz1
        buf.extend_from_slice(&(self.control | SE_SELF_RELATIVE).to_le_bytes());
        buf.extend_from_slice(&owner_offset.to_le_bytes());
        buf.extend_from_slice(&group_offset.to_le_bytes());
        buf.extend_from_slice(&sacl_offset.to_le_bytes());
        buf.extend_from_slice(&dacl_offset.to_le_bytes());

        // Components (in offset order: owner, group, sacl, dacl)
        if let Some(ref b) = owner_bytes {
            buf.extend_from_slice(b);
        }
        if let Some(ref b) = group_bytes {
            buf.extend_from_slice(b);
        }
        if let Some(ref b) = sacl_bytes {
            buf.extend_from_slice(b);
        }
        if let Some(ref b) = dacl_bytes {
            buf.extend_from_slice(b);
        }

        buf
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
                    sid: well_known::guests(),
                    object_type: None,
                    inherited_object_type: None,
                    condition: None,
                    application_data: None,
                },
                Ace {
                    ace_type: ACCESS_ALLOWED_ACE_TYPE,
                    flags: 0,
                    mask: GENERIC_ALL,
                    sid: well_known::administrators(),
                    object_type: None,
                    inherited_object_type: None,
                    condition: None,
                    application_data: None,
                },
                Ace {
                    ace_type: ACCESS_ALLOWED_ACE_TYPE,
                    flags: 0,
                    mask: FILE_READ_DATA | READ_CONTROL,
                    sid: well_known::authenticated_users(),
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
                    sid: well_known::integrity_medium(),
                    object_type: None,
                    inherited_object_type: None,
                    condition: None,
                    application_data: None,
                },
                Ace {
                    ace_type: SYSTEM_AUDIT_ACE_TYPE,
                    flags: SUCCESSFUL_ACCESS_ACE_FLAG | FAILED_ACCESS_ACE_FLAG,
                    mask: FILE_WRITE_DATA,
                    sid: well_known::everyone(),
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
            well_known::system(),
            well_known::system(),
            simple_dacl(),
        );
        let bytes = sd.to_bytes();
        let parsed = SecurityDescriptor::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.owner.as_ref().unwrap(), &well_known::system());
        assert_eq!(parsed.group.as_ref().unwrap(), &well_known::system());
        assert!(parsed.has_dacl());
        assert!(!parsed.has_sacl());
        assert_eq!(parsed.dacl.as_ref().unwrap().aces.len(), 3);
    }

    #[test]
    fn sd_with_sacl_round_trip() {
        let sd = SecurityDescriptor::with_sacl(
            well_known::administrators(),
            well_known::users(),
            simple_dacl(),
            simple_sacl(),
        );
        let bytes = sd.to_bytes();
        let parsed = SecurityDescriptor::from_bytes(&bytes).unwrap();
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
        let owner = crate::sid::Sid::new(5, &[21, 111, 222, 333, 1001]);
        let group = crate::sid::Sid::new(5, &[21, 111, 222, 333, 513]);
        let sd = SecurityDescriptor::new(owner.clone(), group.clone(), Acl::new(ACL_REVISION));
        let bytes = sd.to_bytes();
        let parsed = SecurityDescriptor::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.owner.unwrap(), owner);
        assert_eq!(parsed.group.unwrap(), group);
    }

    #[test]
    fn sd_control_flags_preserved() {
        let mut sd = SecurityDescriptor::new(
            well_known::system(),
            well_known::system(),
            Acl::new(ACL_REVISION),
        );
        sd.control |= SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED;
        let bytes = sd.to_bytes();
        let parsed = SecurityDescriptor::from_bytes(&bytes).unwrap();
        assert!(parsed.is_dacl_protected());
        assert!(parsed.control & SE_DACL_AUTO_INHERITED != 0);
        assert!(parsed.control & SE_SELF_RELATIVE != 0);
    }

    #[test]
    fn sd_null_dacl() {
        // DACL not present — SE_DACL_PRESENT not set
        let sd = SecurityDescriptor {
            control: SE_SELF_RELATIVE, // no SE_DACL_PRESENT
            owner: Some(well_known::system()),
            group: Some(well_known::system()),
            dacl: None,
            sacl: None,
        };
        assert!(!sd.has_dacl());
        let bytes = sd.to_bytes();
        let parsed = SecurityDescriptor::from_bytes(&bytes).unwrap();
        assert!(!parsed.has_dacl());
        assert!(parsed.dacl.is_none());
    }

    #[test]
    fn sd_empty_dacl() {
        // DACL present but empty — grants nothing
        let sd = SecurityDescriptor::new(
            well_known::system(),
            well_known::system(),
            Acl::new(ACL_REVISION), // zero ACEs
        );
        assert!(sd.has_dacl());
        let bytes = sd.to_bytes();
        let parsed = SecurityDescriptor::from_bytes(&bytes).unwrap();
        assert!(parsed.has_dacl());
        assert_eq!(parsed.dacl.as_ref().unwrap().aces.len(), 0);
    }

    #[test]
    fn sd_no_owner() {
        let sd = SecurityDescriptor {
            control: SE_DACL_PRESENT | SE_SELF_RELATIVE,
            owner: None,
            group: Some(well_known::system()),
            dacl: Some(Acl::new(ACL_REVISION)),
            sacl: None,
        };
        let bytes = sd.to_bytes();
        let parsed = SecurityDescriptor::from_bytes(&bytes).unwrap();
        assert!(parsed.owner.is_none());
        assert!(parsed.group.is_some());
    }

    #[test]
    fn sd_no_group() {
        let sd = SecurityDescriptor {
            control: SE_DACL_PRESENT | SE_SELF_RELATIVE,
            owner: Some(well_known::system()),
            group: None,
            dacl: Some(Acl::new(ACL_REVISION)),
            sacl: None,
        };
        let bytes = sd.to_bytes();
        let parsed = SecurityDescriptor::from_bytes(&bytes).unwrap();
        assert!(parsed.owner.is_some());
        assert!(parsed.group.is_none());
    }

    #[test]
    fn reject_truncated_header() {
        assert!(SecurityDescriptor::from_bytes(&[0x01; 19]).is_none());
    }

    #[test]
    fn reject_bad_revision() {
        let mut bytes = SecurityDescriptor::new(
            well_known::system(),
            well_known::system(),
            Acl::new(ACL_REVISION),
        )
        .to_bytes();
        bytes[0] = 2; // bad revision
        assert!(SecurityDescriptor::from_bytes(&bytes).is_none());
    }

    #[test]
    fn reject_owner_offset_out_of_bounds() {
        let mut bytes = SecurityDescriptor::new(
            well_known::system(),
            well_known::system(),
            Acl::new(ACL_REVISION),
        )
        .to_bytes();
        // Set owner offset to beyond buffer
        let bad_offset = (bytes.len() + 100) as u32;
        bytes[4..8].copy_from_slice(&bad_offset.to_le_bytes());
        assert!(SecurityDescriptor::from_bytes(&bytes).is_none());
    }

    #[test]
    fn reject_group_offset_out_of_bounds() {
        let mut bytes = SecurityDescriptor::new(
            well_known::system(),
            well_known::system(),
            Acl::new(ACL_REVISION),
        )
        .to_bytes();
        let bad_offset = (bytes.len() + 100) as u32;
        bytes[8..12].copy_from_slice(&bad_offset.to_le_bytes());
        assert!(SecurityDescriptor::from_bytes(&bytes).is_none());
    }

    #[test]
    fn reject_dacl_offset_out_of_bounds() {
        let mut bytes = SecurityDescriptor::new(
            well_known::system(),
            well_known::system(),
            Acl::new(ACL_REVISION),
        )
        .to_bytes();
        let bad_offset = (bytes.len() + 100) as u32;
        bytes[16..20].copy_from_slice(&bad_offset.to_le_bytes());
        assert!(SecurityDescriptor::from_bytes(&bytes).is_none());
    }

    #[test]
    fn reject_sacl_offset_out_of_bounds() {
        let mut bytes = SecurityDescriptor::with_sacl(
            well_known::system(),
            well_known::system(),
            Acl::new(ACL_REVISION),
            simple_sacl(),
        )
        .to_bytes();
        let bad_offset = (bytes.len() + 100) as u32;
        bytes[12..16].copy_from_slice(&bad_offset.to_le_bytes());
        assert!(SecurityDescriptor::from_bytes(&bytes).is_none());
    }

    #[test]
    fn sd_with_domain_sids() {
        let domain_owner = crate::sid::Sid::new(5, &[21, 3000000000, 2000000000, 1000000000, 500]);
        let domain_group = crate::sid::Sid::new(5, &[21, 3000000000, 2000000000, 1000000000, 513]);
        let sd = SecurityDescriptor::new(
            domain_owner.clone(),
            domain_group.clone(),
            simple_dacl(),
        );
        let bytes = sd.to_bytes();
        let parsed = SecurityDescriptor::from_bytes(&bytes).unwrap();
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
                sid: crate::sid::Sid::new(5, &[21, 1000, 2000, 3000 + i]),
                object_type: None,
                inherited_object_type: None,
                condition: None,
                application_data: None,
            });
        }
        let sd = SecurityDescriptor::new(
            well_known::system(),
            well_known::system(),
            Acl { revision: ACL_REVISION, aces },
        );
        let bytes = sd.to_bytes();
        let parsed = SecurityDescriptor::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.dacl.as_ref().unwrap().aces.len(), 100);
    }

    #[test]
    fn sd_protected_flags() {
        let mut sd = SecurityDescriptor::new(
            well_known::system(),
            well_known::system(),
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
            well_known::system(),
            well_known::system(),
            Acl::new(ACL_REVISION),
        );
        sd.control |= SE_OWNER_DEFAULTED | SE_GROUP_DEFAULTED | SE_DACL_DEFAULTED;
        let bytes = sd.to_bytes();
        let parsed = SecurityDescriptor::from_bytes(&bytes).unwrap();
        assert_ne!(parsed.control & SE_OWNER_DEFAULTED, 0);
        assert_ne!(parsed.control & SE_GROUP_DEFAULTED, 0);
        assert_ne!(parsed.control & SE_DACL_DEFAULTED, 0);
    }

    #[test]
    fn sd_self_relative_always_set() {
        let sd = SecurityDescriptor::new(
            well_known::system(),
            well_known::system(),
            Acl::new(ACL_REVISION),
        );
        let bytes = sd.to_bytes();
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
        let bytes = sd.to_bytes();
        assert_eq!(bytes.len(), SD_HEADER_SIZE);
    }

    #[test]
    fn sd_process_default() {
        // The default process SD (§8.4)
        let user_sid = crate::sid::Sid::new(5, &[21, 100, 200, 300, 1001]);
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
                    sid: well_known::administrators(),
                    object_type: None,
                    inherited_object_type: None,
                    condition: None,
                    application_data: None,
                },
                Ace {
                    ace_type: ACCESS_ALLOWED_ACE_TYPE,
                    flags: 0,
                    mask: GENERIC_ALL,
                    sid: well_known::system(),
                    object_type: None,
                    inherited_object_type: None,
                    condition: None,
                    application_data: None,
                },
                Ace {
                    ace_type: ACCESS_ALLOWED_ACE_TYPE,
                    flags: 0,
                    mask: PROCESS_QUERY_LIMITED,
                    sid: well_known::everyone(),
                    object_type: None,
                    inherited_object_type: None,
                    condition: None,
                    application_data: None,
                },
            ],
        };
        let sd = SecurityDescriptor::new(user_sid, well_known::users(), dacl);
        let bytes = sd.to_bytes();
        let parsed = SecurityDescriptor::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.dacl.as_ref().unwrap().aces.len(), 4);
        assert_eq!(parsed.dacl.as_ref().unwrap().aces[3].mask, PROCESS_QUERY_LIMITED);
    }

    #[test]
    fn sd_bytes_deterministic() {
        // Same SD should produce identical bytes every time
        let sd = SecurityDescriptor::with_sacl(
            well_known::system(),
            well_known::administrators(),
            simple_dacl(),
            simple_sacl(),
        );
        let bytes1 = sd.to_bytes();
        let bytes2 = sd.to_bytes();
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn sd_full_round_trip_preserves_all() {
        let sd = SecurityDescriptor {
            control: SE_DACL_PRESENT | SE_SACL_PRESENT | SE_DACL_PROTECTED
                | SE_DACL_AUTO_INHERITED | SE_SELF_RELATIVE,
            owner: Some(well_known::system()),
            group: Some(well_known::administrators()),
            dacl: Some(simple_dacl()),
            sacl: Some(simple_sacl()),
        };
        let bytes = sd.to_bytes();
        let parsed = SecurityDescriptor::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.owner.as_ref().unwrap(), &well_known::system());
        assert_eq!(parsed.group.as_ref().unwrap(), &well_known::administrators());
        assert!(parsed.has_dacl());
        assert!(parsed.has_sacl());
        assert!(parsed.is_dacl_protected());
        assert!(parsed.control & SE_DACL_AUTO_INHERITED != 0);
        assert_eq!(parsed.dacl.as_ref().unwrap().aces.len(), 3);
        assert_eq!(parsed.sacl.as_ref().unwrap().aces.len(), 2);

        // Verify DACL ACE content
        let dacl = parsed.dacl.as_ref().unwrap();
        assert_eq!(dacl.aces[0].ace_type, ACCESS_DENIED_ACE_TYPE);
        assert_eq!(dacl.aces[0].sid, well_known::guests());
        assert_eq!(dacl.aces[1].ace_type, ACCESS_ALLOWED_ACE_TYPE);
        assert_eq!(dacl.aces[1].sid, well_known::administrators());
        assert_eq!(dacl.aces[2].ace_type, ACCESS_ALLOWED_ACE_TYPE);
        assert_eq!(dacl.aces[2].sid, well_known::authenticated_users());

        // Verify SACL ACE content
        let sacl = parsed.sacl.as_ref().unwrap();
        assert_eq!(sacl.aces[0].ace_type, SYSTEM_MANDATORY_LABEL_ACE_TYPE);
        assert_eq!(sacl.aces[0].sid, well_known::integrity_medium());
        assert_eq!(sacl.aces[1].ace_type, SYSTEM_AUDIT_ACE_TYPE);
    }
}
