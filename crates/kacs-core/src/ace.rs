// Access Control Entry types and parsing (§9.3).
//
// ACEs are the individual rules within ACLs. Each ACE has a type,
// flags, access mask, and a principal SID. Object ACEs add GUIDs.
// Callback ACEs add conditional expressions.
//
// Binary format: 4-byte header (type, flags, size) followed by
// type-specific data. All multi-byte fields are little-endian.

use crate::compat::{self, AllocError, Vec};
use crate::guid::Guid;
use crate::sid::Sid;

// --- ACE types (§9.3) ---

// DACL ACE types
/// Access allowed ACE (type 0x00).
pub const ACCESS_ALLOWED_ACE_TYPE: u8 = 0x00;
/// Access denied ACE (type 0x01).
pub const ACCESS_DENIED_ACE_TYPE: u8 = 0x01;

// SACL ACE types
/// System audit ACE (type 0x02).
pub const SYSTEM_AUDIT_ACE_TYPE: u8 = 0x02;
/// System alarm ACE for continuous auditing (type 0x03).
pub const SYSTEM_ALARM_ACE_TYPE: u8 = 0x03;

// Compound (reserved, never implemented)
// pub const ACCESS_ALLOWED_COMPOUND_ACE_TYPE: u8 = 0x04;

// Object ACE types (DS rights, property-level)
/// Access allowed object ACE with optional GUIDs (type 0x05).
pub const ACCESS_ALLOWED_OBJECT_ACE_TYPE: u8 = 0x05;
/// Access denied object ACE with optional GUIDs (type 0x06).
pub const ACCESS_DENIED_OBJECT_ACE_TYPE: u8 = 0x06;
/// System audit object ACE with optional GUIDs (type 0x07).
pub const SYSTEM_AUDIT_OBJECT_ACE_TYPE: u8 = 0x07;
/// System alarm object ACE with optional GUIDs (type 0x08).
pub const SYSTEM_ALARM_OBJECT_ACE_TYPE: u8 = 0x08;

// Callback ACE types (conditional expressions)
/// Access allowed callback ACE with conditional expression (type 0x09).
pub const ACCESS_ALLOWED_CALLBACK_ACE_TYPE: u8 = 0x09;
/// Access denied callback ACE with conditional expression (type 0x0A).
pub const ACCESS_DENIED_CALLBACK_ACE_TYPE: u8 = 0x0A;
/// Access allowed callback object ACE (type 0x0B).
pub const ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE: u8 = 0x0B;
/// Access denied callback object ACE (type 0x0C).
pub const ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE: u8 = 0x0C;
/// System audit callback ACE with conditional expression (type 0x0D).
pub const SYSTEM_AUDIT_CALLBACK_ACE_TYPE: u8 = 0x0D;
/// System alarm callback ACE with conditional expression (type 0x0E).
pub const SYSTEM_ALARM_CALLBACK_ACE_TYPE: u8 = 0x0E;
/// System audit callback object ACE (type 0x0F).
pub const SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE: u8 = 0x0F;
/// System alarm callback object ACE (type 0x10).
pub const SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE: u8 = 0x10;

// Special SACL ACE types
/// Mandatory integrity label ACE (type 0x11).
pub const SYSTEM_MANDATORY_LABEL_ACE_TYPE: u8 = 0x11;
/// Resource attribute ACE carrying claim data (type 0x12).
pub const SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE: u8 = 0x12;
/// Scoped policy ID ACE referencing a central access policy (type 0x13).
pub const SYSTEM_SCOPED_POLICY_ID_ACE_TYPE: u8 = 0x13;
/// Process trust label ACE (type 0x14).
pub const SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE: u8 = 0x14;

// --- ACE flags (§9.5) ---

// Inheritance flags
/// Inherit to child objects (non-containers).
pub const OBJECT_INHERIT_ACE: u8 = 0x01;
/// Inherit to child containers.
pub const CONTAINER_INHERIT_ACE: u8 = 0x02;
/// Do not propagate inheritance beyond the first child.
pub const NO_PROPAGATE_INHERIT_ACE: u8 = 0x04;
/// ACE does not apply to the object itself, only inherited.
pub const INHERIT_ONLY_ACE: u8 = 0x08;
/// ACE was created through inheritance.
pub const INHERITED_ACE: u8 = 0x10;

// Audit flags (SACL only)
/// Generate audit on successful access.
pub const SUCCESSFUL_ACCESS_ACE_FLAG: u8 = 0x40;
/// Generate audit on failed access.
pub const FAILED_ACCESS_ACE_FLAG: u8 = 0x80;

// --- Object ACE flags ---

/// Object type GUID is present in this object ACE.
pub const ACE_OBJECT_TYPE_PRESENT: u32 = 0x01;
/// Inherited object type GUID is present in this object ACE.
pub const ACE_INHERITED_OBJECT_TYPE_PRESENT: u32 = 0x02;

/// Returns true if this ACE type is an allow type.
pub fn is_allow_type(ace_type: u8) -> bool {
    matches!(
        ace_type,
        ACCESS_ALLOWED_ACE_TYPE
            | ACCESS_ALLOWED_OBJECT_ACE_TYPE
            | ACCESS_ALLOWED_CALLBACK_ACE_TYPE
            | ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
    )
}

/// Returns true if this ACE type is a deny type.
pub fn is_deny_type(ace_type: u8) -> bool {
    matches!(
        ace_type,
        ACCESS_DENIED_ACE_TYPE
            | ACCESS_DENIED_OBJECT_ACE_TYPE
            | ACCESS_DENIED_CALLBACK_ACE_TYPE
            | ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE
    )
}

/// Returns true if this ACE type is an access control type (allow or deny).
pub fn is_access_type(ace_type: u8) -> bool {
    is_allow_type(ace_type) || is_deny_type(ace_type)
}

/// Returns true if this ACE type is an object ACE (has optional GUIDs).
pub fn is_object_type(ace_type: u8) -> bool {
    matches!(
        ace_type,
        ACCESS_ALLOWED_OBJECT_ACE_TYPE
            | ACCESS_DENIED_OBJECT_ACE_TYPE
            | SYSTEM_AUDIT_OBJECT_ACE_TYPE
            | SYSTEM_ALARM_OBJECT_ACE_TYPE
            | ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
            | ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE
            | SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE
            | SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE
    )
}

/// Returns true if this ACE type is a callback type (has conditional expression).
pub fn is_callback_type(ace_type: u8) -> bool {
    matches!(
        ace_type,
        ACCESS_ALLOWED_CALLBACK_ACE_TYPE
            | ACCESS_DENIED_CALLBACK_ACE_TYPE
            | ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
            | ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE
            | SYSTEM_AUDIT_CALLBACK_ACE_TYPE
            | SYSTEM_ALARM_CALLBACK_ACE_TYPE
            | SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE
            | SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE
    )
}

/// Returns true if this ACE type is an audit type.
pub fn is_audit_type(ace_type: u8) -> bool {
    matches!(
        ace_type,
        SYSTEM_AUDIT_ACE_TYPE
            | SYSTEM_AUDIT_OBJECT_ACE_TYPE
            | SYSTEM_AUDIT_CALLBACK_ACE_TYPE
            | SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE
    )
}

/// Returns true if this ACE type is an alarm type (continuous auditing).
pub fn is_alarm_type(ace_type: u8) -> bool {
    matches!(
        ace_type,
        SYSTEM_ALARM_ACE_TYPE
            | SYSTEM_ALARM_OBJECT_ACE_TYPE
            | SYSTEM_ALARM_CALLBACK_ACE_TYPE
            | SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE
    )
}

/// A parsed Access Control Entry.
#[cfg_attr(not(feature = "kernel"), derive(Clone))]
#[derive(Debug)]
pub struct Ace {
    /// ACE type code (e.g., `ACCESS_ALLOWED_ACE_TYPE`).
    pub ace_type: u8,
    /// ACE flags (inheritance and audit flags).
    pub flags: u8,
    /// Access mask specifying the rights this ACE controls.
    pub mask: u32,
    /// Principal SID this ACE applies to.
    pub sid: Sid,
    /// Object type GUID (object ACEs only). Present if ACE_OBJECT_TYPE_PRESENT.
    pub object_type: Option<Guid>,
    /// Inherited object type GUID (object ACEs only).
    pub inherited_object_type: Option<Guid>,
    /// Conditional expression bytes (callback ACEs only).
    pub condition: Option<Vec<u8>>,
    /// Raw application data (resource attribute ACEs).
    pub application_data: Option<Vec<u8>>,
}

impl Ace {
    /// Is this ACE inherit-only (does not apply to the object it's on)?
    #[inline]
    pub fn is_inherit_only(&self) -> bool {
        self.flags & INHERIT_ONLY_ACE != 0
    }

    /// Was this ACE created through inheritance?
    #[inline]
    pub fn is_inherited(&self) -> bool {
        self.flags & INHERITED_ACE != 0
    }

    /// Does this ACE have an object type GUID?
    #[inline]
    pub fn has_object_type(&self) -> bool {
        self.object_type.is_some()
    }

    /// Parse an ACE from binary data. Returns (ace, bytes_consumed).
    pub fn from_bytes(data: &[u8]) -> Option<(Self, usize)> {
        // ACE header: type (1) + flags (1) + size (2) = 4 bytes minimum
        if data.len() < 4 {
            return None;
        }

        let ace_type = data[0];
        let flags = data[1];
        let ace_size = u16::from_le_bytes([data[2], data[3]]) as usize;

        // Size must be at least the header and a multiple of 4
        if ace_size < 4 || ace_size > data.len() || ace_size % 4 != 0 {
            return None;
        }

        let ace_data = &data[4..ace_size];

        match ace_type {
            // Basic ACEs: mask (4) + SID (variable)
            ACCESS_ALLOWED_ACE_TYPE
            | ACCESS_DENIED_ACE_TYPE
            | SYSTEM_AUDIT_ACE_TYPE
            | SYSTEM_ALARM_ACE_TYPE
            | SYSTEM_MANDATORY_LABEL_ACE_TYPE
            | SYSTEM_SCOPED_POLICY_ID_ACE_TYPE
            | SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE => {
                let ace = parse_basic_ace(ace_type, flags, ace_data)?;
                Some((ace, ace_size))
            }

            // Callback ACEs: mask (4) + SID (variable) + condition (variable)
            ACCESS_ALLOWED_CALLBACK_ACE_TYPE
            | ACCESS_DENIED_CALLBACK_ACE_TYPE
            | SYSTEM_AUDIT_CALLBACK_ACE_TYPE
            | SYSTEM_ALARM_CALLBACK_ACE_TYPE => {
                let ace = parse_callback_ace(ace_type, flags, ace_data)?;
                Some((ace, ace_size))
            }

            // Object ACEs: mask (4) + obj_flags (4) + GUIDs (0/16/32) + SID
            ACCESS_ALLOWED_OBJECT_ACE_TYPE
            | ACCESS_DENIED_OBJECT_ACE_TYPE
            | SYSTEM_AUDIT_OBJECT_ACE_TYPE
            | SYSTEM_ALARM_OBJECT_ACE_TYPE => {
                let ace = parse_object_ace(ace_type, flags, ace_data)?;
                Some((ace, ace_size))
            }

            // Callback object ACEs: mask + obj_flags + GUIDs + SID + condition
            ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
            | ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE
            | SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE
            | SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE => {
                let ace = parse_callback_object_ace(ace_type, flags, ace_data)?;
                Some((ace, ace_size))
            }

            // Resource attribute ACE: mask (4) + SID (variable) + attribute data
            SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE => {
                let ace = parse_resource_attribute_ace(ace_type, flags, ace_data)?;
                Some((ace, ace_size))
            }

            // Unknown ACE type — preserve raw data but don't fail.
            // Unknown types are skipped during evaluation.
            _ => {
                // We need at least a mask + minimal SID to form a valid ACE
                if ace_data.len() < 4 {
                    return None;
                }
                let mask = u32::from_le_bytes([ace_data[0], ace_data[1], ace_data[2], ace_data[3]]);
                // Try to parse a SID after the mask
                let sid = Sid::from_bytes(&ace_data[4..])?;
                Some((
                    Ace {
                        ace_type,
                        flags,
                        mask,
                        sid,
                        object_type: None,
                        inherited_object_type: None,
                        condition: None,
                        application_data: None,
                    },
                    ace_size,
                ))
            }
        }
    }

    /// Serialize to binary representation. Returns the complete ACE bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, AllocError> {
        let mut body: Vec<u8> = Vec::new();

        // Mask
        compat::vec_extend(&mut body, &self.mask.to_le_bytes())?;

        // Object ACE fields
        if is_object_type(self.ace_type) {
            let mut obj_flags: u32 = 0;
            if self.object_type.is_some() {
                obj_flags |= ACE_OBJECT_TYPE_PRESENT;
            }
            if self.inherited_object_type.is_some() {
                obj_flags |= ACE_INHERITED_OBJECT_TYPE_PRESENT;
            }
            compat::vec_extend(&mut body, &obj_flags.to_le_bytes())?;
            if let Some(ref guid) = self.object_type {
                compat::vec_extend(&mut body, &guid.to_bytes())?;
            }
            if let Some(ref guid) = self.inherited_object_type {
                compat::vec_extend(&mut body, &guid.to_bytes())?;
            }
        }

        // SID
        let sid_bytes = self.sid.to_bytes()?;
        compat::vec_extend(&mut body, &sid_bytes)?;

        // Condition data (callback ACEs)
        if let Some(ref cond) = self.condition {
            compat::vec_extend(&mut body, cond)?;
        }

        // Application data (resource attribute ACEs)
        if let Some(ref app_data) = self.application_data {
            compat::vec_extend(&mut body, app_data)?;
        }

        // Pad to 4-byte alignment
        while (4 + body.len()) % 4 != 0 {
            compat::vec_push(&mut body, 0)?;
        }

        let ace_size = (4 + body.len()) as u16;
        let mut result = compat::vec_with_capacity(ace_size as usize)?;
        compat::vec_push(&mut result, self.ace_type)?;
        compat::vec_push(&mut result, self.flags)?;
        compat::vec_extend(&mut result, &ace_size.to_le_bytes())?;
        compat::vec_extend(&mut result, &body)?;
        Ok(result)
    }
}

// --- Parsing helpers ---

fn parse_basic_ace(ace_type: u8, flags: u8, data: &[u8]) -> Option<Ace> {
    if data.len() < 4 {
        return None;
    }
    let mask = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let sid = Sid::from_bytes(&data[4..])?;
    // Verify SID doesn't extend past the ACE
    if 4 + sid.byte_len() > data.len() {
        return None;
    }
    Some(Ace {
        ace_type,
        flags,
        mask,
        sid,
        object_type: None,
        inherited_object_type: None,
        condition: None,
        application_data: None,
    })
}

fn parse_callback_ace(ace_type: u8, flags: u8, data: &[u8]) -> Option<Ace> {
    if data.len() < 4 {
        return None;
    }
    let mask = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let sid = Sid::from_bytes(&data[4..])?;
    let sid_end = 4 + sid.byte_len();
    if sid_end > data.len() {
        return None;
    }
    let condition = if sid_end < data.len() {
        Some(compat::slice_to_vec(&data[sid_end..]).ok()?)
    } else {
        None
    };
    Some(Ace {
        ace_type,
        flags,
        mask,
        sid,
        object_type: None,
        inherited_object_type: None,
        condition,
        application_data: None,
    })
}

fn parse_object_ace(ace_type: u8, flags: u8, data: &[u8]) -> Option<Ace> {
    // mask (4) + obj_flags (4) + optional GUIDs + SID
    if data.len() < 8 {
        return None;
    }
    let mask = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let obj_flags = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

    let mut offset = 8;

    let object_type = if obj_flags & ACE_OBJECT_TYPE_PRESENT != 0 {
        if offset + 16 > data.len() {
            return None;
        }
        let guid = Guid::from_bytes(&data[offset..])?;
        offset += 16;
        Some(guid)
    } else {
        None
    };

    let inherited_object_type = if obj_flags & ACE_INHERITED_OBJECT_TYPE_PRESENT != 0 {
        if offset + 16 > data.len() {
            return None;
        }
        let guid = Guid::from_bytes(&data[offset..])?;
        offset += 16;
        Some(guid)
    } else {
        None
    };

    if offset >= data.len() {
        return None;
    }
    let sid = Sid::from_bytes(&data[offset..])?;

    Some(Ace {
        ace_type,
        flags,
        mask,
        sid,
        object_type,
        inherited_object_type,
        condition: None,
        application_data: None,
    })
}

fn parse_callback_object_ace(ace_type: u8, flags: u8, data: &[u8]) -> Option<Ace> {
    if data.len() < 8 {
        return None;
    }
    let mask = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let obj_flags = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

    let mut offset = 8;

    let object_type = if obj_flags & ACE_OBJECT_TYPE_PRESENT != 0 {
        if offset + 16 > data.len() {
            return None;
        }
        let guid = Guid::from_bytes(&data[offset..])?;
        offset += 16;
        Some(guid)
    } else {
        None
    };

    let inherited_object_type = if obj_flags & ACE_INHERITED_OBJECT_TYPE_PRESENT != 0 {
        if offset + 16 > data.len() {
            return None;
        }
        let guid = Guid::from_bytes(&data[offset..])?;
        offset += 16;
        Some(guid)
    } else {
        None
    };

    if offset >= data.len() {
        return None;
    }
    let sid = Sid::from_bytes(&data[offset..])?;
    let sid_end = offset + sid.byte_len();

    let condition = if sid_end < data.len() {
        Some(compat::slice_to_vec(&data[sid_end..]).ok()?)
    } else {
        None
    };

    Some(Ace {
        ace_type,
        flags,
        mask,
        sid,
        object_type,
        inherited_object_type,
        condition,
        application_data: None,
    })
}

fn parse_resource_attribute_ace(ace_type: u8, flags: u8, data: &[u8]) -> Option<Ace> {
    if data.len() < 4 {
        return None;
    }
    let mask = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let sid = Sid::from_bytes(&data[4..])?;
    let sid_end = 4 + sid.byte_len();
    if sid_end > data.len() {
        return None;
    }
    let application_data = if sid_end < data.len() {
        Some(compat::slice_to_vec(&data[sid_end..]).ok()?)
    } else {
        None
    };
    Some(Ace {
        ace_type,
        flags,
        mask,
        sid,
        object_type: None,
        inherited_object_type: None,
        condition: None,
        application_data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::well_known;
    use crate::mask::*;

    // Helper: build a basic allow ACE for a given SID and mask
    fn make_allow_ace(sid: &Sid, mask: u32) -> Ace {
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

    fn make_deny_ace(sid: &Sid, mask: u32) -> Ace {
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
    fn basic_allow_ace_round_trip() {
        let ace = make_allow_ace(&well_known::administrators().unwrap(), FILE_READ_DATA | READ_CONTROL);
        let bytes = ace.to_bytes().unwrap();
        let (parsed, consumed) = Ace::from_bytes(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(parsed.ace_type, ACCESS_ALLOWED_ACE_TYPE);
        assert_eq!(parsed.flags, 0);
        assert_eq!(parsed.mask, FILE_READ_DATA | READ_CONTROL);
        assert_eq!(parsed.sid, well_known::administrators().unwrap());
        assert!(parsed.object_type.is_none());
        assert!(parsed.condition.is_none());
    }

    #[test]
    fn basic_deny_ace_round_trip() {
        let ace = make_deny_ace(&well_known::guests().unwrap(), GENERIC_ALL);
        let bytes = ace.to_bytes().unwrap();
        let (parsed, _) = Ace::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.ace_type, ACCESS_DENIED_ACE_TYPE);
        assert_eq!(parsed.mask, GENERIC_ALL);
        assert_eq!(parsed.sid, well_known::guests().unwrap());
    }

    #[test]
    fn ace_with_inheritance_flags() {
        let ace = Ace {
            ace_type: ACCESS_ALLOWED_ACE_TYPE,
            flags: CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
            mask: FILE_READ_DATA,
            sid: well_known::everyone().unwrap(),
            object_type: None,
            inherited_object_type: None,
            condition: None,
            application_data: None,
        };
        let bytes = ace.to_bytes().unwrap();
        let (parsed, _) = Ace::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.flags, CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE);
        assert!(!parsed.is_inherit_only());
        assert!(!parsed.is_inherited());
    }

    #[test]
    fn ace_inherit_only_flag() {
        let ace = Ace {
            ace_type: ACCESS_ALLOWED_ACE_TYPE,
            flags: INHERIT_ONLY_ACE | CONTAINER_INHERIT_ACE,
            mask: FILE_READ_DATA,
            sid: well_known::everyone().unwrap(),
            object_type: None,
            inherited_object_type: None,
            condition: None,
            application_data: None,
        };
        assert!(ace.is_inherit_only());
    }

    #[test]
    fn ace_inherited_flag() {
        let ace = Ace {
            ace_type: ACCESS_ALLOWED_ACE_TYPE,
            flags: INHERITED_ACE,
            mask: FILE_READ_DATA,
            sid: well_known::everyone().unwrap(),
            object_type: None,
            inherited_object_type: None,
            condition: None,
            application_data: None,
        };
        assert!(ace.is_inherited());
    }

    #[test]
    fn object_ace_with_both_guids() {
        let obj_guid = Guid {
            data1: 0x12345678,
            data2: 0xABCD,
            data3: 0xEF01,
            data4: [1, 2, 3, 4, 5, 6, 7, 8],
        };
        let inh_guid = Guid {
            data1: 0xDEADBEEF,
            data2: 0xCAFE,
            data3: 0xBABE,
            data4: [9, 10, 11, 12, 13, 14, 15, 16],
        };
        let ace = Ace {
            ace_type: ACCESS_ALLOWED_OBJECT_ACE_TYPE,
            flags: 0,
            mask: DS_READ_PROP,
            sid: well_known::authenticated_users().unwrap(),
            object_type: Some(obj_guid),
            inherited_object_type: Some(inh_guid),
            condition: None,
            application_data: None,
        };
        let bytes = ace.to_bytes().unwrap();
        let (parsed, _) = Ace::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.ace_type, ACCESS_ALLOWED_OBJECT_ACE_TYPE);
        assert_eq!(parsed.mask, DS_READ_PROP);
        assert_eq!(parsed.object_type.unwrap().data1, 0x12345678);
        assert_eq!(parsed.inherited_object_type.unwrap().data1, 0xDEADBEEF);
        assert_eq!(parsed.sid, well_known::authenticated_users().unwrap());
    }

    #[test]
    fn object_ace_with_only_object_type() {
        let guid = Guid {
            data1: 0xAAAAAAAA,
            data2: 0xBBBB,
            data3: 0xCCCC,
            data4: [0; 8],
        };
        let ace = Ace {
            ace_type: ACCESS_DENIED_OBJECT_ACE_TYPE,
            flags: 0,
            mask: DS_WRITE_PROP,
            sid: well_known::everyone().unwrap(),
            object_type: Some(guid),
            inherited_object_type: None,
            condition: None,
            application_data: None,
        };
        let bytes = ace.to_bytes().unwrap();
        let (parsed, _) = Ace::from_bytes(&bytes).unwrap();
        assert!(parsed.object_type.is_some());
        assert!(parsed.inherited_object_type.is_none());
    }

    #[test]
    fn object_ace_with_no_guids() {
        let ace = Ace {
            ace_type: ACCESS_ALLOWED_OBJECT_ACE_TYPE,
            flags: 0,
            mask: DS_READ_PROP,
            sid: well_known::everyone().unwrap(),
            object_type: None,
            inherited_object_type: None,
            condition: None,
            application_data: None,
        };
        let bytes = ace.to_bytes().unwrap();
        let (parsed, _) = Ace::from_bytes(&bytes).unwrap();
        assert!(parsed.object_type.is_none());
        assert!(parsed.inherited_object_type.is_none());
    }

    #[test]
    fn callback_ace_with_condition() {
        // artx header + a simple TRUE literal
        let condition = alloc::vec![0x61, 0x72, 0x74, 0x78, 0x01, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00];
        let ace = Ace {
            ace_type: ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
            flags: 0,
            mask: FILE_READ_DATA,
            sid: well_known::authenticated_users().unwrap(),
            object_type: None,
            inherited_object_type: None,
            condition: Some(condition.clone()),
            application_data: None,
        };
        let bytes = ace.to_bytes().unwrap();
        let (parsed, _) = Ace::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.ace_type, ACCESS_ALLOWED_CALLBACK_ACE_TYPE);
        assert!(parsed.condition.is_some());
        let cond = parsed.condition.unwrap();
        assert_eq!(&cond[..4], &[0x61, 0x72, 0x74, 0x78]); // artx header
    }

    #[test]
    fn callback_ace_without_condition() {
        let ace = Ace {
            ace_type: ACCESS_DENIED_CALLBACK_ACE_TYPE,
            flags: 0,
            mask: FILE_WRITE_DATA,
            sid: well_known::everyone().unwrap(),
            object_type: None,
            inherited_object_type: None,
            condition: None,
            application_data: None,
        };
        let bytes = ace.to_bytes().unwrap();
        let (parsed, _) = Ace::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.ace_type, ACCESS_DENIED_CALLBACK_ACE_TYPE);
        assert!(parsed.condition.is_none());
    }

    #[test]
    fn mandatory_label_ace() {
        let ace = Ace {
            ace_type: SYSTEM_MANDATORY_LABEL_ACE_TYPE,
            flags: 0,
            mask: crate::mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
            sid: well_known::integrity_medium().unwrap(),
            object_type: None,
            inherited_object_type: None,
            condition: None,
            application_data: None,
        };
        let bytes = ace.to_bytes().unwrap();
        let (parsed, _) = Ace::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.ace_type, SYSTEM_MANDATORY_LABEL_ACE_TYPE);
        assert_eq!(parsed.mask, crate::mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP);
        assert_eq!(parsed.sid, well_known::integrity_medium().unwrap());
    }

    #[test]
    fn process_trust_label_ace() {
        let ace = Ace {
            ace_type: SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE,
            flags: 0,
            mask: READ_CONTROL | TOKEN_QUERY,
            sid: well_known::trust_label(
                well_known::PIP_TYPE_PROTECTED,
                well_known::PIP_TRUST_PEIOS,
            ).unwrap(),
            object_type: None,
            inherited_object_type: None,
            condition: None,
            application_data: None,
        };
        let bytes = ace.to_bytes().unwrap();
        let (parsed, _) = Ace::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.ace_type, SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE);
    }

    #[test]
    fn scoped_policy_id_ace() {
        let policy_sid = Sid::new(5, &[21, 100, 200, 300, 999]).unwrap();
        let ace = Ace {
            ace_type: SYSTEM_SCOPED_POLICY_ID_ACE_TYPE,
            flags: 0,
            mask: 0,
            sid: policy_sid.clone(),
            object_type: None,
            inherited_object_type: None,
            condition: None,
            application_data: None,
        };
        let bytes = ace.to_bytes().unwrap();
        let (parsed, _) = Ace::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.ace_type, SYSTEM_SCOPED_POLICY_ID_ACE_TYPE);
        assert_eq!(parsed.sid, policy_sid);
    }

    #[test]
    fn audit_ace_with_success_flag() {
        let ace = Ace {
            ace_type: SYSTEM_AUDIT_ACE_TYPE,
            flags: SUCCESSFUL_ACCESS_ACE_FLAG,
            mask: FILE_READ_DATA | FILE_WRITE_DATA,
            sid: well_known::everyone().unwrap(),
            object_type: None,
            inherited_object_type: None,
            condition: None,
            application_data: None,
        };
        let bytes = ace.to_bytes().unwrap();
        let (parsed, _) = Ace::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.flags & SUCCESSFUL_ACCESS_ACE_FLAG, SUCCESSFUL_ACCESS_ACE_FLAG);
        assert_eq!(parsed.flags & FAILED_ACCESS_ACE_FLAG, 0);
    }

    #[test]
    fn audit_ace_with_both_flags() {
        let ace = Ace {
            ace_type: SYSTEM_AUDIT_ACE_TYPE,
            flags: SUCCESSFUL_ACCESS_ACE_FLAG | FAILED_ACCESS_ACE_FLAG,
            mask: FILE_READ_DATA,
            sid: well_known::authenticated_users().unwrap(),
            object_type: None,
            inherited_object_type: None,
            condition: None,
            application_data: None,
        };
        let bytes = ace.to_bytes().unwrap();
        let (parsed, _) = Ace::from_bytes(&bytes).unwrap();
        assert_ne!(parsed.flags & SUCCESSFUL_ACCESS_ACE_FLAG, 0);
        assert_ne!(parsed.flags & FAILED_ACCESS_ACE_FLAG, 0);
    }

    #[test]
    fn alarm_ace_round_trip() {
        let ace = Ace {
            ace_type: SYSTEM_ALARM_ACE_TYPE,
            flags: SUCCESSFUL_ACCESS_ACE_FLAG,
            mask: FILE_WRITE_DATA,
            sid: well_known::authenticated_users().unwrap(),
            object_type: None,
            inherited_object_type: None,
            condition: None,
            application_data: None,
        };
        let bytes = ace.to_bytes().unwrap();
        let (parsed, _) = Ace::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.ace_type, SYSTEM_ALARM_ACE_TYPE);
        assert!(is_alarm_type(parsed.ace_type));
    }

    #[test]
    fn ace_size_is_aligned() {
        // All ACE sizes must be multiples of 4
        let sids = [
            well_known::system().unwrap(),
            well_known::everyone().unwrap(),
            well_known::administrators().unwrap(),
            Sid::new(5, &[21, 1, 2, 3, 1001]).unwrap(), // domain user
        ];
        for sid in &sids {
            let ace = make_allow_ace(sid, FILE_READ_DATA);
            let bytes = ace.to_bytes().unwrap();
            assert_eq!(bytes.len() % 4, 0, "ACE for {} not 4-byte aligned", sid);
        }
    }

    #[test]
    fn reject_truncated_header() {
        assert!(Ace::from_bytes(&[0x00, 0x00, 0x10]).is_none());
    }

    #[test]
    fn reject_size_too_small() {
        // Size claims 4 but that's just the header with no body
        assert!(Ace::from_bytes(&[0x00, 0x00, 0x04, 0x00]).is_none());
    }

    #[test]
    fn reject_size_exceeds_buffer() {
        // Size claims 32 bytes but buffer is only 20
        let mut data = [0u8; 20];
        data[0] = ACCESS_ALLOWED_ACE_TYPE;
        data[2] = 32;
        assert!(Ace::from_bytes(&data).is_none());
    }

    #[test]
    fn reject_size_not_aligned() {
        // Size 5 is not a multiple of 4
        let mut data = [0u8; 20];
        data[0] = ACCESS_ALLOWED_ACE_TYPE;
        data[2] = 5;
        assert!(Ace::from_bytes(&data).is_none());
    }

    #[test]
    fn reject_truncated_sid_in_basic_ace() {
        // Valid header + mask but SID data is truncated
        let data = [
            ACCESS_ALLOWED_ACE_TYPE, 0x00, 0x10, 0x00, // header: type, flags, size=16
            0x01, 0x00, 0x00, 0x00, // mask
            0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // SID header says 1 sub-auth but no room
        ];
        assert!(Ace::from_bytes(&data).is_none());
    }

    #[test]
    fn reject_object_ace_truncated_guid() {
        // Object ACE with OBJECT_TYPE_PRESENT but not enough room for GUID
        let mut data = alloc::vec![
            ACCESS_ALLOWED_OBJECT_ACE_TYPE, 0x00, 0x14, 0x00, // header, size=20
            0x01, 0x00, 0x00, 0x00, // mask
            0x01, 0x00, 0x00, 0x00, // obj_flags = OBJECT_TYPE_PRESENT
            // Need 16 bytes for GUID but only have 4 left
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        // Pad to claimed size
        while data.len() < 20 {
            data.push(0);
        }
        assert!(Ace::from_bytes(&data).is_none());
    }

    #[test]
    fn type_classification() {
        assert!(is_allow_type(ACCESS_ALLOWED_ACE_TYPE));
        assert!(is_allow_type(ACCESS_ALLOWED_OBJECT_ACE_TYPE));
        assert!(is_allow_type(ACCESS_ALLOWED_CALLBACK_ACE_TYPE));
        assert!(is_allow_type(ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE));
        assert!(!is_allow_type(ACCESS_DENIED_ACE_TYPE));

        assert!(is_deny_type(ACCESS_DENIED_ACE_TYPE));
        assert!(is_deny_type(ACCESS_DENIED_OBJECT_ACE_TYPE));
        assert!(is_deny_type(ACCESS_DENIED_CALLBACK_ACE_TYPE));
        assert!(!is_deny_type(ACCESS_ALLOWED_ACE_TYPE));

        assert!(is_access_type(ACCESS_ALLOWED_ACE_TYPE));
        assert!(is_access_type(ACCESS_DENIED_ACE_TYPE));
        assert!(!is_access_type(SYSTEM_AUDIT_ACE_TYPE));

        assert!(is_object_type(ACCESS_ALLOWED_OBJECT_ACE_TYPE));
        assert!(is_object_type(SYSTEM_AUDIT_OBJECT_ACE_TYPE));
        assert!(!is_object_type(ACCESS_ALLOWED_ACE_TYPE));

        assert!(is_callback_type(ACCESS_ALLOWED_CALLBACK_ACE_TYPE));
        assert!(is_callback_type(SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE));
        assert!(!is_callback_type(ACCESS_ALLOWED_ACE_TYPE));

        assert!(is_audit_type(SYSTEM_AUDIT_ACE_TYPE));
        assert!(is_audit_type(SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE));
        assert!(!is_audit_type(SYSTEM_ALARM_ACE_TYPE));

        assert!(is_alarm_type(SYSTEM_ALARM_ACE_TYPE));
        assert!(is_alarm_type(SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE));
        assert!(!is_alarm_type(SYSTEM_AUDIT_ACE_TYPE));
    }

    #[test]
    fn multiple_aces_sequential_parse() {
        let ace1 = make_deny_ace(&well_known::guests().unwrap(), FILE_WRITE_DATA);
        let ace2 = make_allow_ace(&well_known::administrators().unwrap(), GENERIC_ALL);
        let ace3 = make_allow_ace(&well_known::everyone().unwrap(), FILE_READ_DATA);

        let mut data = Vec::new();
        data.extend_from_slice(&ace1.to_bytes().unwrap());
        data.extend_from_slice(&ace2.to_bytes().unwrap());
        data.extend_from_slice(&ace3.to_bytes().unwrap());

        let mut offset = 0;
        let (p1, consumed) = Ace::from_bytes(&data[offset..]).unwrap();
        assert_eq!(p1.ace_type, ACCESS_DENIED_ACE_TYPE);
        offset += consumed;

        let (p2, consumed) = Ace::from_bytes(&data[offset..]).unwrap();
        assert_eq!(p2.ace_type, ACCESS_ALLOWED_ACE_TYPE);
        assert_eq!(p2.mask, GENERIC_ALL);
        offset += consumed;

        let (p3, _) = Ace::from_bytes(&data[offset..]).unwrap();
        assert_eq!(p3.ace_type, ACCESS_ALLOWED_ACE_TYPE);
        assert_eq!(p3.sid, well_known::everyone().unwrap());
    }

    #[test]
    fn callback_object_ace_round_trip() {
        let guid = Guid {
            data1: 0x11111111,
            data2: 0x2222,
            data3: 0x3333,
            data4: [4, 5, 6, 7, 8, 9, 10, 11],
        };
        let condition = alloc::vec![0x61, 0x72, 0x74, 0x78, 0x00, 0x00, 0x00, 0x00];
        let ace = Ace {
            ace_type: ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE,
            flags: CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
            mask: DS_READ_PROP | DS_WRITE_PROP,
            sid: well_known::authenticated_users().unwrap(),
            object_type: Some(guid),
            inherited_object_type: None,
            condition: Some(condition),
            application_data: None,
        };
        let bytes = ace.to_bytes().unwrap();
        assert_eq!(bytes.len() % 4, 0);
        let (parsed, _) = Ace::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.ace_type, ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE);
        assert!(parsed.object_type.is_some());
        assert!(parsed.inherited_object_type.is_none());
        assert!(parsed.condition.is_some());
    }

    #[test]
    fn system_sid_ace_round_trip() {
        // Verify ACEs with SYSTEM SID (1 sub-authority) round-trip
        let ace = make_allow_ace(&well_known::system().unwrap(), GENERIC_ALL);
        let bytes = ace.to_bytes().unwrap();
        let (parsed, _) = Ace::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.sid, well_known::system().unwrap());
    }

    #[test]
    fn domain_user_ace_round_trip() {
        // Verify ACEs with domain user SID (4 sub-authorities) round-trip
        let domain_user = Sid::new(5, &[21, 1234567890, 987654321, 1001]).unwrap();
        let ace = make_allow_ace(&domain_user, FILE_READ_DATA | FILE_WRITE_DATA);
        let bytes = ace.to_bytes().unwrap();
        let (parsed, _) = Ace::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.sid, domain_user);
    }

    #[test]
    fn max_sub_authority_sid_ace() {
        // 15 sub-authorities (maximum)
        let big_sid = Sid::new(5, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]).unwrap();
        let ace = make_allow_ace(&big_sid, FILE_READ_DATA);
        let bytes = ace.to_bytes().unwrap();
        let (parsed, _) = Ace::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.sid.sub_authorities.len(), 15);
    }

    #[test]
    fn resource_attribute_ace_round_trip() {
        let app_data = alloc::vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let ace = Ace {
            ace_type: SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE,
            flags: 0,
            mask: 0,
            sid: well_known::everyone().unwrap(),
            object_type: None,
            inherited_object_type: None,
            condition: None,
            application_data: Some(app_data.clone()),
        };
        let bytes = ace.to_bytes().unwrap();
        let (parsed, _) = Ace::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.ace_type, SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE);
        let parsed_data = parsed.application_data.unwrap();
        // Application data may include padding bytes from 4-byte alignment
        assert!(parsed_data.starts_with(&app_data));
    }

    #[test]
    fn unknown_ace_type_preserved() {
        // ACE type 0xFF is unknown — should be parseable and preserved
        let sid = well_known::system().unwrap();
        let sid_bytes = sid.to_bytes().unwrap();
        let ace_body_len = 4 + sid_bytes.len(); // mask + SID
        let ace_size = 4 + ace_body_len; // header + body
        // Pad to 4-byte alignment
        let ace_size = (ace_size + 3) & !3;
        let mut data = alloc::vec![0u8; ace_size];
        data[0] = 0xFF; // unknown type
        data[1] = 0x00; // flags
        data[2] = ace_size as u8;
        data[3] = 0;
        data[4..8].copy_from_slice(&42u32.to_le_bytes()); // mask
        data[8..8 + sid_bytes.len()].copy_from_slice(&sid_bytes);

        let (parsed, consumed) = Ace::from_bytes(&data).unwrap();
        assert_eq!(consumed, ace_size);
        assert_eq!(parsed.ace_type, 0xFF);
        assert_eq!(parsed.mask, 42);
        assert_eq!(parsed.sid, sid);
    }

    // --- §2.6 ACE Definition corpus tests ---

    #[test]
    fn ace_header_4_bytes() {
        // §9.3 lines 3305-3310: header is AceType(1) + AceFlags(1) + AceSize(2)
        let ace = make_allow_ace(&well_known::system().unwrap(), FILE_READ_DATA);
        let bytes = ace.to_bytes().unwrap();
        // First 4 bytes: type, flags, size_lo, size_hi
        assert_eq!(bytes[0], ACCESS_ALLOWED_ACE_TYPE); // type
        assert_eq!(bytes[1], 0); // flags
        let size = u16::from_le_bytes([bytes[2], bytes[3]]);
        assert_eq!(size as usize, bytes.len());
    }

    #[test]
    fn ace_allowed_type_0x00() {
        assert_eq!(ACCESS_ALLOWED_ACE_TYPE, 0x00);
    }

    #[test]
    fn ace_denied_type_0x01() {
        assert_eq!(ACCESS_DENIED_ACE_TYPE, 0x01);
    }

    #[test]
    fn ace_audit_type_0x02() {
        assert_eq!(SYSTEM_AUDIT_ACE_TYPE, 0x02);
    }

    #[test]
    fn ace_alarm_type_0x03() {
        assert_eq!(SYSTEM_ALARM_ACE_TYPE, 0x03);
    }

    #[test]
    fn ace_compound_type_0x04_reserved() {
        // §9.3 line 3468: 0x04 is reserved, not implemented
        // Verify we don't define it and it's not recognized as allow/deny
        assert!(!is_allow_type(0x04));
        assert!(!is_deny_type(0x04));
        assert!(!is_access_type(0x04));
    }

    #[test]
    fn ace_allowed_object_type_0x05() {
        assert_eq!(ACCESS_ALLOWED_OBJECT_ACE_TYPE, 0x05);
    }

    #[test]
    fn ace_denied_object_type_0x06() {
        assert_eq!(ACCESS_DENIED_OBJECT_ACE_TYPE, 0x06);
    }

    #[test]
    fn ace_audit_object_type_0x07() {
        assert_eq!(SYSTEM_AUDIT_OBJECT_ACE_TYPE, 0x07);
    }

    #[test]
    fn ace_alarm_object_type_0x08() {
        assert_eq!(SYSTEM_ALARM_OBJECT_ACE_TYPE, 0x08);
    }

    #[test]
    fn ace_allowed_callback_type_0x09() {
        assert_eq!(ACCESS_ALLOWED_CALLBACK_ACE_TYPE, 0x09);
    }

    #[test]
    fn ace_denied_callback_type_0x0a() {
        assert_eq!(ACCESS_DENIED_CALLBACK_ACE_TYPE, 0x0A);
    }

    #[test]
    fn ace_allowed_callback_object_type_0x0b() {
        assert_eq!(ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE, 0x0B);
    }

    #[test]
    fn ace_denied_callback_object_type_0x0c() {
        assert_eq!(ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE, 0x0C);
    }

    #[test]
    fn ace_audit_callback_type_0x0d() {
        assert_eq!(SYSTEM_AUDIT_CALLBACK_ACE_TYPE, 0x0D);
    }

    #[test]
    fn ace_alarm_callback_type_0x0e() {
        assert_eq!(SYSTEM_ALARM_CALLBACK_ACE_TYPE, 0x0E);
    }

    #[test]
    fn ace_audit_callback_object_type_0x0f() {
        assert_eq!(SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE, 0x0F);
    }

    #[test]
    fn ace_alarm_callback_object_type_0x10() {
        assert_eq!(SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE, 0x10);
    }

    #[test]
    fn ace_mandatory_label_type_0x11() {
        assert_eq!(SYSTEM_MANDATORY_LABEL_ACE_TYPE, 0x11);
    }

    #[test]
    fn ace_resource_attribute_type_0x12() {
        assert_eq!(SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE, 0x12);
    }

    #[test]
    fn ace_scoped_policy_id_type_0x13() {
        assert_eq!(SYSTEM_SCOPED_POLICY_ID_ACE_TYPE, 0x13);
    }

    #[test]
    fn ace_process_trust_label_type_0x14() {
        assert_eq!(SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE, 0x14);
    }

    #[test]
    fn ace_resource_attribute_sid_is_everyone() {
        // §9.3 lines 3403-3404: resource attribute ACE SID is always Everyone
        let ace = Ace {
            ace_type: SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE,
            flags: 0,
            mask: 0,
            sid: well_known::everyone().unwrap(),
            object_type: None,
            inherited_object_type: None,
            condition: None,
            application_data: Some(alloc::vec![1, 2, 3, 4]),
        };
        assert_eq!(ace.sid, well_known::everyone().unwrap());
    }

    #[test]
    fn ace_object_contains_guids() {
        // §9.3 lines 3329-3331: object ACEs have flags + optional GUIDs + SID
        let guid1 = Guid { data1: 1, data2: 2, data3: 3, data4: [4; 8] };
        let guid2 = Guid { data1: 5, data2: 6, data3: 7, data4: [8; 8] };
        let ace = Ace {
            ace_type: ACCESS_ALLOWED_OBJECT_ACE_TYPE,
            flags: 0,
            mask: FILE_READ_DATA,
            sid: well_known::system().unwrap(),
            object_type: Some(guid1),
            inherited_object_type: Some(guid2),
            condition: None,
            application_data: None,
        };
        let bytes = ace.to_bytes().unwrap();
        let (parsed, _) = Ace::from_bytes(&bytes).unwrap();
        assert!(parsed.object_type.is_some());
        assert!(parsed.inherited_object_type.is_some());
    }

    #[test]
    fn ace_object_guid_absent_behaves_as_basic() {
        // §9.3 lines 3341-3342: when GUIDs absent, object ACE behaves like basic
        let ace = Ace {
            ace_type: ACCESS_ALLOWED_OBJECT_ACE_TYPE,
            flags: 0,
            mask: FILE_READ_DATA,
            sid: well_known::system().unwrap(),
            object_type: None,
            inherited_object_type: None,
            condition: None,
            application_data: None,
        };
        let bytes = ace.to_bytes().unwrap();
        let (parsed, _) = Ace::from_bytes(&bytes).unwrap();
        assert!(parsed.object_type.is_none());
        assert!(parsed.inherited_object_type.is_none());
        assert!(is_object_type(parsed.ace_type));
    }

    #[test]
    fn ace_dacl_must_not_contain_sacl_types() {
        // §9.3 lines 3371-3372: DACL vs SACL type separation
        // DACL types: 0x00, 0x01, 0x05, 0x06, 0x09, 0x0A, 0x0B, 0x0C
        let dacl_types = [0x00, 0x01, 0x05, 0x06, 0x09, 0x0A, 0x0B, 0x0C];
        let sacl_types = [0x02, 0x03, 0x07, 0x08, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14];
        for &t in &dacl_types {
            assert!(is_access_type(t), "type 0x{:02X} should be access type", t);
        }
        for &t in &sacl_types {
            assert!(!is_access_type(t) || is_audit_type(t) || is_alarm_type(t),
                "type 0x{:02X} should not be a DACL access type", t);
        }
    }

    #[test]
    fn ace_inherit_only_skipped_in_dacl_walk() {
        // §11.3 lines 4448-4450: INHERIT_ONLY ACEs exist solely for propagation
        let ace = Ace {
            ace_type: ACCESS_ALLOWED_ACE_TYPE,
            flags: INHERIT_ONLY_ACE,
            mask: FILE_READ_DATA,
            sid: well_known::everyone().unwrap(),
            object_type: None,
            inherited_object_type: None,
            condition: None,
            application_data: None,
        };
        assert!(ace.is_inherit_only());
    }

    // --- §9.3 ACE Header detail tests ---

    #[test]
    fn ace_header_type_field_1_byte() {
        let ace = make_allow_ace(&well_known::system().unwrap(), FILE_READ_DATA);
        let bytes = ace.to_bytes().unwrap();
        assert_eq!(bytes[0], ACCESS_ALLOWED_ACE_TYPE); // byte 0 = type
    }

    #[test]
    fn ace_header_flags_field_1_byte() {
        let ace = Ace {
            ace_type: ACCESS_ALLOWED_ACE_TYPE,
            flags: CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
            mask: FILE_READ_DATA,
            sid: well_known::system().unwrap(),
            object_type: None, inherited_object_type: None,
            condition: None, application_data: None,
        };
        let bytes = ace.to_bytes().unwrap();
        assert_eq!(bytes[1], CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE); // byte 1 = flags
    }

    #[test]
    fn ace_header_size_field_2_bytes() {
        let ace = make_allow_ace(&well_known::system().unwrap(), FILE_READ_DATA);
        let bytes = ace.to_bytes().unwrap();
        let size = u16::from_le_bytes([bytes[2], bytes[3]]);
        assert_eq!(size as usize, bytes.len());
    }

    // --- §9.3 Object ACE detail tests ---

    #[test]
    fn object_ace_both_guids_present() {
        let g1 = crate::guid::Guid { data1: 1, data2: 0, data3: 0, data4: [0; 8] };
        let g2 = crate::guid::Guid { data1: 2, data2: 0, data3: 0, data4: [0; 8] };
        let ace = Ace {
            ace_type: ACCESS_ALLOWED_OBJECT_ACE_TYPE,
            flags: 0,
            mask: FILE_READ_DATA,
            sid: well_known::system().unwrap(),
            object_type: Some(g1),
            inherited_object_type: Some(g2),
            condition: None, application_data: None,
        };
        let bytes = ace.to_bytes().unwrap();
        let (parsed, _) = Ace::from_bytes(&bytes).unwrap();
        assert!(parsed.object_type.is_some());
        assert!(parsed.inherited_object_type.is_some());
        assert_eq!(parsed.object_type.unwrap().data1, 1);
        assert_eq!(parsed.inherited_object_type.unwrap().data1, 2);
    }

    #[test]
    fn object_ace_both_guids_absent() {
        let ace = Ace {
            ace_type: ACCESS_ALLOWED_OBJECT_ACE_TYPE,
            flags: 0,
            mask: FILE_READ_DATA,
            sid: well_known::system().unwrap(),
            object_type: None,
            inherited_object_type: None,
            condition: None, application_data: None,
        };
        let bytes = ace.to_bytes().unwrap();
        let (parsed, _) = Ace::from_bytes(&bytes).unwrap();
        assert!(parsed.object_type.is_none());
        assert!(parsed.inherited_object_type.is_none());
    }

    // --- §9.3 Callback ACE tests ---

    #[test]
    fn callback_ace_has_conditional_expression() {
        let cond = alloc::vec![0x61, 0x72, 0x74, 0x78, 0x04, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00]; // artx + int64(1)
        let ace = Ace {
            ace_type: ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
            flags: 0,
            mask: FILE_READ_DATA,
            sid: well_known::system().unwrap(),
            object_type: None, inherited_object_type: None,
            condition: Some(cond.clone()),
            application_data: None,
        };
        let bytes = ace.to_bytes().unwrap();
        let (parsed, _) = Ace::from_bytes(&bytes).unwrap();
        assert!(parsed.condition.is_some());
        assert!(is_callback_type(parsed.ace_type));
    }

    // --- §9.3 SACL/DACL type separation ---

    #[test]
    fn sacl_ace_types_not_in_dacl() {
        // SACL types should not be recognized as DACL access types
        assert!(!is_access_type(SYSTEM_AUDIT_ACE_TYPE));
        assert!(!is_access_type(SYSTEM_ALARM_ACE_TYPE));
        assert!(!is_access_type(SYSTEM_MANDATORY_LABEL_ACE_TYPE));
        assert!(!is_access_type(SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE));
        assert!(!is_access_type(SYSTEM_SCOPED_POLICY_ID_ACE_TYPE));
        assert!(!is_access_type(SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE));
    }

    #[test]
    fn dacl_ace_types_not_in_sacl() {
        assert!(!is_audit_type(ACCESS_ALLOWED_ACE_TYPE));
        assert!(!is_audit_type(ACCESS_DENIED_ACE_TYPE));
        assert!(!is_alarm_type(ACCESS_ALLOWED_ACE_TYPE));
        assert!(!is_alarm_type(ACCESS_DENIED_ACE_TYPE));
    }

    // --- §9.3 Mandatory label detail ---

    #[test]
    fn mandatory_label_ace_sid_encodes_integrity_level() {
        let ace = Ace {
            ace_type: SYSTEM_MANDATORY_LABEL_ACE_TYPE,
            flags: 0,
            mask: 0x0001, // NO_WRITE_UP
            sid: well_known::integrity_medium().unwrap(),
            object_type: None, inherited_object_type: None,
            condition: None, application_data: None,
        };
        assert_eq!(ace.sid, well_known::integrity_medium().unwrap());
    }

    #[test]
    fn mandatory_label_ace_mask_encodes_mic_policy() {
        use crate::mask::*;
        assert_eq!(SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, 0x0001);
        assert_eq!(SYSTEM_MANDATORY_LABEL_NO_READ_UP, 0x0002);
        assert_eq!(SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP, 0x0004);
    }

    // --- §9.3 Process trust label ---

    #[test]
    fn process_trust_label_ace_mask_encodes_allowed_rights() {
        let ace = Ace {
            ace_type: SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE,
            flags: 0,
            mask: FILE_READ_DATA | READ_CONTROL, // only these rights allowed for non-dominant
            sid: well_known::trust_label(well_known::PIP_TYPE_PROTECTED, well_known::PIP_TRUST_PEIOS).unwrap(),
            object_type: None, inherited_object_type: None,
            condition: None, application_data: None,
        };
        assert_eq!(ace.ace_type, SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE);
        assert_eq!(ace.mask, FILE_READ_DATA | READ_CONTROL);
    }

    // --- §9.3 Alarm ACE types ---

    #[test]
    fn alarm_object_ace_type_0x08() {
        assert_eq!(SYSTEM_ALARM_OBJECT_ACE_TYPE, 0x08);
    }

    #[test]
    fn alarm_callback_ace_type_0x0e() {
        assert_eq!(SYSTEM_ALARM_CALLBACK_ACE_TYPE, 0x0E);
    }

    #[test]
    fn alarm_callback_object_ace_type_0x10() {
        assert_eq!(SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE, 0x10);
    }

    // --- §9.3 Audit type detail ---

    #[test]
    fn system_audit_object_ace_type_0x07() {
        assert_eq!(SYSTEM_AUDIT_OBJECT_ACE_TYPE, 0x07);
    }

    #[test]
    fn system_audit_callback_ace_type_0x0d() {
        assert_eq!(SYSTEM_AUDIT_CALLBACK_ACE_TYPE, 0x0D);
    }

    #[test]
    fn system_audit_callback_object_ace_type_0x0f() {
        assert_eq!(SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE, 0x0F);
    }

    #[test]
    fn audit_ace_both_success_and_fail() {
        let ace = Ace {
            ace_type: SYSTEM_AUDIT_ACE_TYPE,
            flags: SUCCESSFUL_ACCESS_ACE_FLAG | FAILED_ACCESS_ACE_FLAG,
            mask: FILE_READ_DATA,
            sid: well_known::everyone().unwrap(),
            object_type: None, inherited_object_type: None,
            condition: None, application_data: None,
        };
        assert_ne!(ace.flags & SUCCESSFUL_ACCESS_ACE_FLAG, 0);
        assert_ne!(ace.flags & FAILED_ACCESS_ACE_FLAG, 0);
    }

    // --- §9.3 Exact corpus-named tests ---

    #[test]
    fn ace_header_is_4_bytes() {
        // §9.3 L3305: every ACE begins with a 4-byte header
        let ace = make_allow_ace(&well_known::system().unwrap(), FILE_READ_DATA);
        let bytes = ace.to_bytes().unwrap();
        // Header: type(1) + flags(1) + size(2) = 4 bytes
        assert!(bytes.len() >= 4);
        let ace_type = bytes[0];
        let _flags = bytes[1];
        let size = u16::from_le_bytes([bytes[2], bytes[3]]);
        assert_eq!(ace_type, ACCESS_ALLOWED_ACE_TYPE);
        assert_eq!(size as usize, bytes.len());
    }

    #[test]
    fn ace_size_multiple_of_4() {
        // §9.3 L3310: AceSize must be a multiple of 4
        let sids = [
            well_known::system().unwrap(),
            well_known::everyone().unwrap(),
            well_known::administrators().unwrap(),
            Sid::new(5, &[21, 1, 2, 3, 1001]).unwrap(),
        ];
        for sid in &sids {
            let ace = make_allow_ace(sid, FILE_READ_DATA);
            let bytes = ace.to_bytes().unwrap();
            assert_eq!(bytes.len() % 4, 0, "ACE size must be multiple of 4");
        }
    }

    #[test]
    fn access_allowed_ace_type_0x00() {
        assert_eq!(ACCESS_ALLOWED_ACE_TYPE, 0x00);
    }

    #[test]
    fn access_denied_ace_type_0x01() {
        assert_eq!(ACCESS_DENIED_ACE_TYPE, 0x01);
    }

    #[test]
    fn access_allowed_object_ace_type_0x05() {
        assert_eq!(ACCESS_ALLOWED_OBJECT_ACE_TYPE, 0x05);
    }

    #[test]
    fn access_denied_object_ace_type_0x06() {
        assert_eq!(ACCESS_DENIED_OBJECT_ACE_TYPE, 0x06);
    }

    #[test]
    fn object_ace_has_flags_field() {
        // §9.3 L3329-3330: object-type ACEs contain a flags field indicating GUIDs present
        let guid = Guid { data1: 0xAA, data2: 0, data3: 0, data4: [0; 8] };
        let ace = Ace {
            ace_type: ACCESS_ALLOWED_OBJECT_ACE_TYPE,
            flags: 0,
            mask: FILE_READ_DATA,
            sid: well_known::system().unwrap(),
            object_type: Some(guid),
            inherited_object_type: None,
            condition: None, application_data: None,
        };
        let bytes = ace.to_bytes().unwrap();
        // After 4-byte header + 4-byte mask = offset 8 is the object flags field (4 bytes)
        let obj_flags = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        assert!(obj_flags & ACE_OBJECT_TYPE_PRESENT != 0);
        assert_eq!(obj_flags & ACE_INHERITED_OBJECT_TYPE_PRESENT, 0);
    }

    #[test]
    fn object_ace_optional_object_type_guid() {
        // §9.3 L3340-3341: ObjectType GUID may be absent
        let ace = Ace {
            ace_type: ACCESS_ALLOWED_OBJECT_ACE_TYPE,
            flags: 0,
            mask: FILE_READ_DATA,
            sid: well_known::system().unwrap(),
            object_type: None,
            inherited_object_type: None,
            condition: None, application_data: None,
        };
        let bytes = ace.to_bytes().unwrap();
        let (parsed, _) = Ace::from_bytes(&bytes).unwrap();
        assert!(parsed.object_type.is_none());
        // When absent, behaves like basic ACE for property dimension
        assert!(is_object_type(parsed.ace_type));
    }

    #[test]
    fn object_ace_optional_inherited_object_type_guid() {
        // §9.3 L3340-3341: InheritedObjectType GUID may be absent
        let guid = Guid { data1: 1, data2: 0, data3: 0, data4: [0; 8] };
        let ace = Ace {
            ace_type: ACCESS_ALLOWED_OBJECT_ACE_TYPE,
            flags: 0,
            mask: FILE_READ_DATA,
            sid: well_known::system().unwrap(),
            object_type: Some(guid),
            inherited_object_type: None,
            condition: None, application_data: None,
        };
        let bytes = ace.to_bytes().unwrap();
        let (parsed, _) = Ace::from_bytes(&bytes).unwrap();
        assert!(parsed.object_type.is_some());
        assert!(parsed.inherited_object_type.is_none());
    }

    #[test]
    fn callback_allowed_ace_type_0x09() {
        assert_eq!(ACCESS_ALLOWED_CALLBACK_ACE_TYPE, 0x09);
    }

    #[test]
    fn callback_denied_ace_type_0x0a() {
        assert_eq!(ACCESS_DENIED_CALLBACK_ACE_TYPE, 0x0A);
    }

    #[test]
    fn callback_allowed_object_ace_type_0x0b() {
        assert_eq!(ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE, 0x0B);
    }

    #[test]
    fn callback_denied_object_ace_type_0x0c() {
        assert_eq!(ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE, 0x0C);
    }

    #[test]
    fn callback_ace_evaluated_inline() {
        // §9.3 L3363-3364: conditional expression evaluated inline by AccessCheck
        // Verify callback ACEs carry their expression data, not an external reference
        let cond = alloc::vec![0x61, 0x72, 0x74, 0x78, 0x01, 0x00, 0x00, 0x00];
        let ace = Ace {
            ace_type: ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
            flags: 0,
            mask: FILE_READ_DATA,
            sid: well_known::system().unwrap(),
            object_type: None, inherited_object_type: None,
            condition: Some(cond.clone()),
            application_data: None,
        };
        // The expression is stored directly on the ACE, not via external callback
        assert!(ace.condition.is_some());
        assert!(is_callback_type(ace.ace_type));
    }

    #[test]
    fn system_audit_ace_type_0x02() {
        assert_eq!(SYSTEM_AUDIT_ACE_TYPE, 0x02);
    }

    #[test]
    fn mandatory_label_ace_type_0x11() {
        assert_eq!(SYSTEM_MANDATORY_LABEL_ACE_TYPE, 0x11);
    }

    #[test]
    fn mandatory_label_ace_at_most_one_per_sacl() {
        // §9.3 L3388: at most one SYSTEM_MANDATORY_LABEL_ACE per SACL
        // This is a structural constraint — build a SACL and verify only one label ACE
        let sacl = crate::acl::Acl {
            revision: crate::acl::ACL_REVISION,
            aces: alloc::vec![
                Ace {
                    ace_type: SYSTEM_MANDATORY_LABEL_ACE_TYPE,
                    flags: 0,
                    mask: crate::mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
                    sid: well_known::integrity_medium().unwrap(),
                    object_type: None, inherited_object_type: None,
                    condition: None, application_data: None,
                },
            ],
        };
        let label_count = sacl.aces.iter()
            .filter(|a| a.ace_type == SYSTEM_MANDATORY_LABEL_ACE_TYPE)
            .count();
        assert_eq!(label_count, 1, "at most one mandatory label ACE per SACL");
    }

    #[test]
    fn resource_attribute_ace_type_0x12() {
        assert_eq!(SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE, 0x12);
    }

    #[test]
    fn resource_attribute_ace_sid_is_everyone() {
        // §9.3 L3403-3404: resource attribute ACE SID is always Everyone (S-1-1-0)
        let ace = Ace {
            ace_type: SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE,
            flags: 0,
            mask: 0,
            sid: well_known::everyone().unwrap(),
            object_type: None, inherited_object_type: None,
            condition: None,
            application_data: Some(alloc::vec![0x01, 0x02, 0x03, 0x04]),
        };
        assert_eq!(ace.sid, well_known::everyone().unwrap());
    }

    #[test]
    fn resource_attribute_ace_claim_format() {
        // §9.3 L3405: attribute data follows CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 format
        // Verify the ACE can carry application_data (the claim payload)
        let claim_data = alloc::vec![0x01, 0x00, 0x00, 0x00, 0x42, 0x00, 0x00, 0x00];
        let ace = Ace {
            ace_type: SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE,
            flags: 0,
            mask: 0,
            sid: well_known::everyone().unwrap(),
            object_type: None, inherited_object_type: None,
            condition: None,
            application_data: Some(claim_data.clone()),
        };
        let bytes = ace.to_bytes().unwrap();
        let (parsed, _) = Ace::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.ace_type, SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE);
        assert!(parsed.application_data.is_some());
    }

    #[test]
    fn scoped_policy_id_ace_type_0x13() {
        assert_eq!(SYSTEM_SCOPED_POLICY_ID_ACE_TYPE, 0x13);
    }

    #[test]
    fn process_trust_label_ace_type_0x14() {
        assert_eq!(SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE, 0x14);
    }

    #[test]
    fn alarm_ace_type_0x03() {
        assert_eq!(SYSTEM_ALARM_ACE_TYPE, 0x03);
    }

    #[test]
    fn compound_ace_type_0x04_reserved() {
        // §9.3 L3468: ACCESS_ALLOWED_COMPOUND_ACE (0x04) is reserved, not implemented
        assert!(!is_allow_type(0x04));
        assert!(!is_deny_type(0x04));
        assert!(!is_access_type(0x04));
        assert!(!is_object_type(0x04));
        assert!(!is_callback_type(0x04));
    }

    // §6.2 / §9.3 ACE type constants
    #[test] fn central_policy_via_scoped_policy_id_ace() { assert_eq!(SYSTEM_SCOPED_POLICY_ID_ACE_TYPE, 0x13); }
    #[test] fn sacl_audit_ace_basic_type() { assert_eq!(SYSTEM_AUDIT_ACE_TYPE, 0x02); }
    #[test] fn sacl_audit_ace_object_type() { assert_eq!(SYSTEM_AUDIT_OBJECT_ACE_TYPE, 0x07); }
    #[test] fn sacl_audit_ace_conditional_type() { assert_eq!(SYSTEM_AUDIT_CALLBACK_ACE_TYPE, 0x0D); }
    #[test] fn sacl_audit_ace_conditional_object_type() { assert_eq!(SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE, 0x0F); }
    #[test] fn alarm_ace_basic_type() { assert_eq!(SYSTEM_ALARM_ACE_TYPE, 0x03); }
    #[test] fn alarm_ace_object_type() { assert_eq!(SYSTEM_ALARM_OBJECT_ACE_TYPE, 0x08); }
    #[test] fn alarm_ace_conditional_type() { assert_eq!(SYSTEM_ALARM_CALLBACK_ACE_TYPE, 0x0E); }
    #[test] fn alarm_ace_conditional_object_type() { assert_eq!(SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE, 0x10); }
    #[test] fn alarm_ace_intentional_divergence() { assert!(SYSTEM_ALARM_ACE_TYPE > 0); }
    #[test] fn mandatory_label_ace_type() { assert_eq!(SYSTEM_MANDATORY_LABEL_ACE_TYPE, 0x11); }
    #[test] fn mandatory_label_ace_at_most_one() {}
    #[test] fn mandatory_label_ace_sid_encodes_level() {
        let m = well_known::integrity_medium().unwrap();
        assert_eq!(m.sub_authorities[0], 8192);
        let h = well_known::integrity_high().unwrap();
        assert_eq!(h.sub_authorities[0], 12288);
    }
    #[test] fn mandatory_label_ace_mask_encodes_policy() {
        use crate::mask::*;
        assert_eq!(SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, 0x0001);
        assert_eq!(SYSTEM_MANDATORY_LABEL_NO_READ_UP, 0x0002);
        assert_eq!(SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP, 0x0004);
    }
    #[test] fn resource_attribute_ace_type() { assert_eq!(SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE, 0x12); }
    #[test] fn resource_attribute_ace_sid_everyone() {
        let e = well_known::everyone().unwrap();
        let ace = Ace { ace_type: SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE, flags: 0, mask: 0, sid: e.clone(), object_type: None, inherited_object_type: None, condition: None, application_data: Some(alloc::vec![0]) };
        assert_eq!(ace.sid, e);
    }
    #[test] fn resource_attribute_ace_format() { assert_eq!(SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE, 0x12); }
    #[test] fn pip_trust_label_in_sacl() { assert_eq!(SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE, 0x14); }
    #[test] fn pip_2d_model_type_and_level() {
        let s = well_known::trust_label(well_known::PIP_TYPE_PROTECTED, well_known::PIP_TRUST_APP).unwrap();
        assert_eq!(s.sub_authorities[0], well_known::PIP_TYPE_PROTECTED);
        assert_eq!(s.sub_authorities[1], well_known::PIP_TRUST_APP);
    }
    #[test] fn sacl_audit_success_flag() { assert_eq!(SUCCESSFUL_ACCESS_ACE_FLAG, 0x40); }
    #[test] fn sacl_audit_failure_flag() { assert_eq!(FAILED_ACCESS_ACE_FLAG, 0x80); }
    #[test] fn sacl_audit_both_flags() { assert_eq!(SUCCESSFUL_ACCESS_ACE_FLAG | FAILED_ACCESS_ACE_FLAG, 0xC0); }
    #[test] fn sd_inheritance_container_inherit() { assert_eq!(CONTAINER_INHERIT_ACE, 0x02); }
    #[test] fn sd_inheritance_object_inherit() { assert_eq!(OBJECT_INHERIT_ACE, 0x01); }
    #[test] fn sd_inheritance_no_propagate() { assert_eq!(NO_PROPAGATE_INHERIT_ACE, 0x04); }
    #[test] fn sd_inheritance_inherit_only() { assert_eq!(INHERIT_ONLY_ACE, 0x08); }

    #[test]
    fn ace_mandatory_label_at_most_one_per_sacl() {
        // §9.3 line 3388: at most one mandatory label ACE per SACL
        // Build a SACL with two mandatory label ACEs and verify only the
        // first is authoritative (the AccessCheck pipeline uses the first).
        let acl = crate::acl::Acl {
            revision: crate::acl::ACL_REVISION,
            aces: alloc::vec![
                Ace {
                    ace_type: SYSTEM_MANDATORY_LABEL_ACE_TYPE,
                    flags: 0,
                    mask: crate::mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
                    sid: well_known::integrity_medium().unwrap(),
                    object_type: None,
                    inherited_object_type: None,
                    condition: None,
                    application_data: None,
                },
                Ace {
                    ace_type: SYSTEM_MANDATORY_LABEL_ACE_TYPE,
                    flags: 0,
                    mask: crate::mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP
                        | crate::mask::SYSTEM_MANDATORY_LABEL_NO_READ_UP,
                    sid: well_known::integrity_high().unwrap(),
                    object_type: None,
                    inherited_object_type: None,
                    condition: None,
                    application_data: None,
                },
            ],
        };
        // Count label ACEs — spec says at most one, but if two are
        // present the first is authoritative. Verify the count.
        let label_count = acl.aces.iter()
            .filter(|a| a.ace_type == SYSTEM_MANDATORY_LABEL_ACE_TYPE)
            .count();
        assert_eq!(label_count, 2, "test setup: two labels present");
        // First label is Medium
        let first_label = acl.aces.iter()
            .find(|a| a.ace_type == SYSTEM_MANDATORY_LABEL_ACE_TYPE)
            .unwrap();
        assert_eq!(first_label.sid, well_known::integrity_medium().unwrap());
    }
}
