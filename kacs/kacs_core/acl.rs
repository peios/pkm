// Access Control List — ordered list of ACEs (§9.3, §9.4).
//
// Two kinds: DACL (discretionary, controls access) and SACL (system,
// controls audit/integrity/policy). Both use the same binary format.
//
// Binary layout: revision (1) + padding (1) + size (2) + ace_count (2)
//                + padding (2) + ACE data

use crate::compat::{self, AllocError, Vec};
use crate::ace::Ace;

// ACL revisions (§9.9)
pub const ACL_REVISION: u8 = 0x02;
pub const ACL_REVISION_DS: u8 = 0x04;

/// A parsed Access Control List.
#[cfg_attr(not(feature = "kernel"), derive(Clone))]
#[derive(Debug)]
pub struct Acl {
    pub revision: u8,
    pub aces: Vec<Ace>,
}

/// ACL header size in bytes.
const ACL_HEADER_SIZE: usize = 8;

impl Acl {
    /// Create an empty ACL with the given revision.
    pub fn new(revision: u8) -> Self {
        Acl {
            revision,
            aces: Vec::new(),
        }
    }

    /// Create an ACL with the given ACEs, auto-selecting the revision.
    pub fn with_aces(aces: Vec<Ace>) -> Self {
        let revision = if aces.iter().any(|a| crate::ace::is_object_type(a.ace_type)
            || crate::ace::is_callback_type(a.ace_type))
        {
            ACL_REVISION_DS
        } else {
            ACL_REVISION
        };
        Acl { revision, aces }
    }

    /// Parse an ACL from binary data (MS-DTYP §2.4.5).
    pub fn from_bytes(data: &[u8]) -> Result<Option<Self>, AllocError> {
        if data.len() < ACL_HEADER_SIZE {
            return Ok(None);
        }

        let revision = data[0];
        if revision != ACL_REVISION && revision != ACL_REVISION_DS {
            return Ok(None);
        }

        let acl_size = u16::from_le_bytes([data[2], data[3]]) as usize;
        let ace_count = u16::from_le_bytes([data[4], data[5]]) as usize;

        if acl_size < ACL_HEADER_SIZE || acl_size > data.len() {
            return Ok(None);
        }

        let ace_data = &data[ACL_HEADER_SIZE..acl_size];
        let mut aces = compat::vec_with_capacity(ace_count)?;
        let mut offset = 0;

        for _ in 0..ace_count {
            if offset >= ace_data.len() {
                return Ok(None); // claimed more ACEs than data contains
            }
            let Some((ace, consumed)) = Ace::from_bytes(&ace_data[offset..]) else {
                return Ok(None);
            };
            offset += consumed;
            compat::vec_push(&mut aces, ace)?;
        }

        Ok(Some(Acl { revision, aces }))
    }

    /// Serialize to binary representation.
    pub fn to_bytes(&self) -> Result<Vec<u8>, AllocError> {
        let mut ace_bytes = Vec::new();
        for ace in &self.aces {
            compat::vec_extend(&mut ace_bytes, &ace.to_bytes()?)?;
        }

        let acl_size = (ACL_HEADER_SIZE + ace_bytes.len()) as u16;
        let ace_count = self.aces.len() as u16;

        let mut buf = compat::vec_with_capacity(acl_size as usize)?;
        compat::vec_push(&mut buf, self.revision)?;
        compat::vec_push(&mut buf, 0)?; // padding
        compat::vec_extend(&mut buf, &acl_size.to_le_bytes())?;
        compat::vec_extend(&mut buf, &ace_count.to_le_bytes())?;
        compat::vec_extend(&mut buf, &[0, 0])?; // padding
        compat::vec_extend(&mut buf, &ace_bytes)?;
        Ok(buf)
    }

    /// Byte length of the serialized ACL.
    pub fn byte_len(&self) -> Result<usize, AllocError> {
        let mut ace_len: usize = 0;
        for ace in &self.aces {
            ace_len += ace.to_bytes()?.len();
        }
        Ok(ACL_HEADER_SIZE + ace_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ace::*;
    use crate::mask::*;
    use crate::well_known;
    use crate::guid::Guid;

    fn allow_ace(sid: &crate::sid::Sid, mask: u32) -> Ace {
        Ace {
            ace_type: ACCESS_ALLOWED_ACE_TYPE,
            flags: 0,
            mask,
            sid: sid.clone(),
            object_type: None,
            inherited_object_type: None,
            condition: None,
            application_data: None,
        }
    }

    fn deny_ace(sid: &crate::sid::Sid, mask: u32) -> Ace {
        Ace {
            ace_type: ACCESS_DENIED_ACE_TYPE,
            flags: 0,
            mask,
            sid: sid.clone(),
            object_type: None,
            inherited_object_type: None,
            condition: None,
            application_data: None,
        }
    }

    #[test]
    fn empty_acl_round_trip() {
        let acl = Acl::new(ACL_REVISION);
        let bytes = acl.to_bytes().unwrap();
        assert_eq!(bytes.len(), ACL_HEADER_SIZE);
        let parsed = Acl::from_bytes(&bytes).unwrap().unwrap();
        assert_eq!(parsed.revision, ACL_REVISION);
        assert_eq!(parsed.aces.len(), 0);
    }

    #[test]
    fn single_ace_round_trip() {
        let acl = Acl {
            revision: ACL_REVISION,
            aces: alloc::vec![allow_ace(&well_known::administrators().unwrap(), GENERIC_ALL)],
        };
        let bytes = acl.to_bytes().unwrap();
        let parsed = Acl::from_bytes(&bytes).unwrap().unwrap();
        assert_eq!(parsed.aces.len(), 1);
        assert_eq!(parsed.aces[0].ace_type, ACCESS_ALLOWED_ACE_TYPE);
        assert_eq!(parsed.aces[0].mask, GENERIC_ALL);
        assert_eq!(parsed.aces[0].sid, well_known::administrators().unwrap());
    }

    #[test]
    fn multiple_aces_round_trip() {
        let acl = Acl {
            revision: ACL_REVISION,
            aces: alloc::vec![
                deny_ace(&well_known::guests().unwrap(), GENERIC_ALL),
                allow_ace(&well_known::administrators().unwrap(), GENERIC_ALL),
                allow_ace(&well_known::authenticated_users().unwrap(), FILE_READ_DATA | READ_CONTROL),
                allow_ace(&well_known::everyone().unwrap(), FILE_READ_DATA),
            ],
        };
        let bytes = acl.to_bytes().unwrap();
        let parsed = Acl::from_bytes(&bytes).unwrap().unwrap();
        assert_eq!(parsed.aces.len(), 4);
        assert_eq!(parsed.aces[0].ace_type, ACCESS_DENIED_ACE_TYPE);
        assert_eq!(parsed.aces[0].sid, well_known::guests().unwrap());
        assert_eq!(parsed.aces[1].ace_type, ACCESS_ALLOWED_ACE_TYPE);
        assert_eq!(parsed.aces[1].sid, well_known::administrators().unwrap());
        assert_eq!(parsed.aces[2].sid, well_known::authenticated_users().unwrap());
        assert_eq!(parsed.aces[3].sid, well_known::everyone().unwrap());
    }

    #[test]
    fn ds_revision_auto_selected() {
        let object_ace = Ace {
            ace_type: ACCESS_ALLOWED_OBJECT_ACE_TYPE,
            flags: 0,
            mask: DS_READ_PROP,
            sid: well_known::authenticated_users().unwrap(),
            object_type: Some(Guid::ZERO),
            inherited_object_type: None,
            condition: None,
            application_data: None,
        };
        let acl = Acl::with_aces(alloc::vec![object_ace]);
        assert_eq!(acl.revision, ACL_REVISION_DS);
    }

    #[test]
    fn basic_revision_auto_selected() {
        let acl = Acl::with_aces(alloc::vec![
            allow_ace(&well_known::everyone().unwrap(), FILE_READ_DATA),
        ]);
        assert_eq!(acl.revision, ACL_REVISION);
    }

    #[test]
    fn byte_len_matches_serialized() {
        let acl = Acl {
            revision: ACL_REVISION,
            aces: alloc::vec![
                deny_ace(&well_known::guests().unwrap(), GENERIC_ALL),
                allow_ace(&well_known::administrators().unwrap(), GENERIC_ALL),
            ],
        };
        assert_eq!(acl.byte_len().unwrap(), acl.to_bytes().unwrap().len());
    }

    #[test]
    fn reject_truncated_header() {
        assert!(Acl::from_bytes(&[0x02, 0x00, 0x08]).unwrap().is_none());
    }

    #[test]
    fn reject_invalid_revision() {
        let mut bytes = Acl::new(ACL_REVISION).to_bytes().unwrap();
        bytes[0] = 0x03; // invalid revision
        assert!(Acl::from_bytes(&bytes).unwrap().is_none());
    }

    #[test]
    fn reject_size_too_small() {
        let mut bytes = [0u8; 8];
        bytes[0] = ACL_REVISION;
        bytes[2] = 4; // size claims 4 but minimum is 8
        assert!(Acl::from_bytes(&bytes).unwrap().is_none());
    }

    #[test]
    fn reject_size_exceeds_buffer() {
        let mut bytes = [0u8; 8];
        bytes[0] = ACL_REVISION;
        bytes[2] = 100; // claims 100 bytes but buffer is 8
        assert!(Acl::from_bytes(&bytes).unwrap().is_none());
    }

    #[test]
    fn reject_ace_count_exceeds_data() {
        let mut bytes = Acl::new(ACL_REVISION).to_bytes().unwrap();
        // Claim 1 ACE but no ACE data
        bytes[4] = 1;
        assert!(Acl::from_bytes(&bytes).unwrap().is_none());
    }

    #[test]
    fn mixed_ace_types_round_trip() {
        let mandatory_label = Ace {
            ace_type: SYSTEM_MANDATORY_LABEL_ACE_TYPE,
            flags: 0,
            mask: SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
            sid: well_known::integrity_high().unwrap(),
            object_type: None,
            inherited_object_type: None,
            condition: None,
            application_data: None,
        };
        let audit = Ace {
            ace_type: SYSTEM_AUDIT_ACE_TYPE,
            flags: SUCCESSFUL_ACCESS_ACE_FLAG | FAILED_ACCESS_ACE_FLAG,
            mask: FILE_WRITE_DATA,
            sid: well_known::everyone().unwrap(),
            object_type: None,
            inherited_object_type: None,
            condition: None,
            application_data: None,
        };
        let acl = Acl {
            revision: ACL_REVISION,
            aces: alloc::vec![mandatory_label, audit],
        };
        let bytes = acl.to_bytes().unwrap();
        let parsed = Acl::from_bytes(&bytes).unwrap().unwrap();
        assert_eq!(parsed.aces.len(), 2);
        assert_eq!(parsed.aces[0].ace_type, SYSTEM_MANDATORY_LABEL_ACE_TYPE);
        assert_eq!(parsed.aces[1].ace_type, SYSTEM_AUDIT_ACE_TYPE);
    }

    #[test]
    fn acl_with_inherited_aces() {
        let acl = Acl {
            revision: ACL_REVISION,
            aces: alloc::vec![
                // Explicit deny
                Ace {
                    ace_type: ACCESS_DENIED_ACE_TYPE,
                    flags: 0,
                    mask: FILE_WRITE_DATA,
                    sid: well_known::guests().unwrap(),
                    object_type: None,
                    inherited_object_type: None,
                    condition: None,
                    application_data: None,
                },
                // Explicit allow
                Ace {
                    ace_type: ACCESS_ALLOWED_ACE_TYPE,
                    flags: 0,
                    mask: FILE_READ_DATA,
                    sid: well_known::everyone().unwrap(),
                    object_type: None,
                    inherited_object_type: None,
                    condition: None,
                    application_data: None,
                },
                // Inherited deny
                Ace {
                    ace_type: ACCESS_DENIED_ACE_TYPE,
                    flags: INHERITED_ACE,
                    mask: FILE_EXECUTE,
                    sid: well_known::guests().unwrap(),
                    object_type: None,
                    inherited_object_type: None,
                    condition: None,
                    application_data: None,
                },
                // Inherited allow
                Ace {
                    ace_type: ACCESS_ALLOWED_ACE_TYPE,
                    flags: INHERITED_ACE,
                    mask: GENERIC_READ,
                    sid: well_known::authenticated_users().unwrap(),
                    object_type: None,
                    inherited_object_type: None,
                    condition: None,
                    application_data: None,
                },
            ],
        };
        let bytes = acl.to_bytes().unwrap();
        let parsed = Acl::from_bytes(&bytes).unwrap().unwrap();
        assert_eq!(parsed.aces.len(), 4);
        assert!(!parsed.aces[0].is_inherited());
        assert!(!parsed.aces[1].is_inherited());
        assert!(parsed.aces[2].is_inherited());
        assert!(parsed.aces[3].is_inherited());
    }

    #[test]
    fn large_acl_many_aces() {
        // Build an ACL with 50 ACEs
        let mut aces = Vec::new();
        for i in 0..50u32 {
            aces.push(allow_ace(
                &crate::sid::Sid::new(5, &[21, 1000000, 2000000, 1000 + i]).unwrap(),
                FILE_READ_DATA,
            ));
        }
        let acl = Acl {
            revision: ACL_REVISION,
            aces,
        };
        let bytes = acl.to_bytes().unwrap();
        let parsed = Acl::from_bytes(&bytes).unwrap().unwrap();
        assert_eq!(parsed.aces.len(), 50);
        for (i, ace) in parsed.aces.iter().enumerate() {
            assert_eq!(
                ace.sid.sub_authorities[3],
                1000 + i as u32,
            );
        }
    }

    #[test]
    fn revision_ds_round_trip() {
        let acl = Acl::new(ACL_REVISION_DS);
        let bytes = acl.to_bytes().unwrap();
        let parsed = Acl::from_bytes(&bytes).unwrap().unwrap();
        assert_eq!(parsed.revision, ACL_REVISION_DS);
    }
}
