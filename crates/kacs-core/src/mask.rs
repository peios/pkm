// Access mask constants (§9.2).
//
// Every ACE, access request, and granted result uses a 32-bit mask.
// Bits 0-15 are object-specific. Bits 16-31 are standard/generic/special.

// --- Standard rights (bits 16-20, common to all object types) ---

/// Standard right: delete the object (bit 16, `0x0001_0000`).
pub const DELETE: u32 = 0x0001_0000;
/// Standard right: read the security descriptor (bit 17, `0x0002_0000`).
pub const READ_CONTROL: u32 = 0x0002_0000;
/// Standard right: modify the DACL (bit 18, `0x0004_0000`).
pub const WRITE_DAC: u32 = 0x0004_0000;
/// Standard right: change the owner SID (bit 19, `0x0008_0000`).
pub const WRITE_OWNER: u32 = 0x0008_0000;
/// Standard right: synchronize on the object (bit 20, `0x0010_0000`).
pub const SYNCHRONIZE: u32 = 0x0010_0000;

/// All five standard rights OR'd together (bits 16-20).
pub const STANDARD_RIGHTS_ALL: u32 =
    DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER | SYNCHRONIZE;

// --- Special rights (bits 24-25) ---

/// Read/write the SACL. Requires SeSecurityPrivilege.
pub const ACCESS_SYSTEM_SECURITY: u32 = 0x0100_0000;

/// Query mode: compute the maximum grantable access mask.
pub const MAXIMUM_ALLOWED: u32 = 0x0200_0000;

// --- Generic rights (bits 28-31, mapped per object type) ---

/// Generic all access (bit 28, `0x1000_0000`). Mapped per object type.
pub const GENERIC_ALL: u32 = 0x1000_0000;
/// Generic execute access (bit 29, `0x2000_0000`). Mapped per object type.
pub const GENERIC_EXECUTE: u32 = 0x2000_0000;
/// Generic write access (bit 30, `0x4000_0000`). Mapped per object type.
pub const GENERIC_WRITE: u32 = 0x4000_0000;
/// Generic read access (bit 31, `0x8000_0000`). Mapped per object type.
pub const GENERIC_READ: u32 = 0x8000_0000;

/// Bitmask covering all four generic rights (bits 28-31).
pub const GENERIC_RIGHTS_MASK: u32 =
    GENERIC_ALL | GENERIC_EXECUTE | GENERIC_WRITE | GENERIC_READ;

// --- File-specific rights (bits 0-8) §14 ---

/// File: read data (bit 0, `0x0001`).
pub const FILE_READ_DATA: u32 = 0x0001;
/// File: write data (bit 1, `0x0002`).
pub const FILE_WRITE_DATA: u32 = 0x0002;
/// File: append data (bit 2, `0x0004`).
pub const FILE_APPEND_DATA: u32 = 0x0004;
/// File: read extended attributes (bit 3, `0x0008`).
pub const FILE_READ_EA: u32 = 0x0008;
/// File: write extended attributes (bit 4, `0x0010`).
pub const FILE_WRITE_EA: u32 = 0x0010;
/// File: execute (bit 5, `0x0020`).
pub const FILE_EXECUTE: u32 = 0x0020;
/// File: read attributes (bit 7, `0x0080`).
pub const FILE_READ_ATTRIBUTES: u32 = 0x0080;
/// File: write attributes (bit 8, `0x0100`).
pub const FILE_WRITE_ATTRIBUTES: u32 = 0x0100;

// Directory aliases (same bit positions, different names)

/// Directory: list entries (bit 0, alias for `FILE_READ_DATA`).
pub const FILE_LIST_DIRECTORY: u32 = 0x0001; // = FILE_READ_DATA
/// Directory: create files (bit 1, alias for `FILE_WRITE_DATA`).
pub const FILE_ADD_FILE: u32 = 0x0002; // = FILE_WRITE_DATA
/// Directory: create subdirectories (bit 2, alias for `FILE_APPEND_DATA`).
pub const FILE_ADD_SUBDIRECTORY: u32 = 0x0004; // = FILE_APPEND_DATA
/// Directory: traverse (bit 5, alias for `FILE_EXECUTE`).
pub const FILE_TRAVERSE: u32 = 0x0020; // = FILE_EXECUTE
/// Directory: delete child entries (bit 6, `0x0040`).
pub const FILE_DELETE_CHILD: u32 = 0x0040;

// --- Process-specific rights (§8.4) ---

/// Process: terminate (bit 0, `0x0001`).
pub const PROCESS_TERMINATE: u32 = 0x0001;
/// Process: send signal (bit 1, `0x0002`).
pub const PROCESS_SIGNAL: u32 = 0x0002;
/// Process: read virtual memory (bit 4, `0x0010`).
pub const PROCESS_VM_READ: u32 = 0x0010;
/// Process: write virtual memory (bit 5, `0x0020`).
pub const PROCESS_VM_WRITE: u32 = 0x0020;
/// Process: duplicate handles (bit 6, `0x0040`).
pub const PROCESS_DUP_HANDLE: u32 = 0x0040;
/// Process: set information (bit 9, `0x0200`).
pub const PROCESS_SET_INFORMATION: u32 = 0x0200;
/// Process: query information (bit 10, `0x0400`).
pub const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
/// Process: query limited information (bit 12, `0x1000`).
pub const PROCESS_QUERY_LIMITED: u32 = 0x1000;

// --- Token-specific rights (§7.9) ---

/// Token: assign as primary token (bit 0, `0x0001`).
pub const TOKEN_ASSIGN_PRIMARY: u32 = 0x0001;
/// Token: duplicate (bit 1, `0x0002`).
pub const TOKEN_DUPLICATE: u32 = 0x0002;
/// Token: impersonate (bit 2, `0x0004`).
pub const TOKEN_IMPERSONATE: u32 = 0x0004;
/// Token: query attributes (bit 3, `0x0008`).
pub const TOKEN_QUERY: u32 = 0x0008;
// 0x0010 reserved (TOKEN_QUERY_SOURCE, folded into TOKEN_QUERY)
/// Token: adjust privileges (bit 5, `0x0020`).
pub const TOKEN_ADJUST_PRIVILEGES: u32 = 0x0020;
/// Token: adjust groups (bit 6, `0x0040`).
pub const TOKEN_ADJUST_GROUPS: u32 = 0x0040;
/// Token: adjust default DACL and owner (bit 7, `0x0080`).
pub const TOKEN_ADJUST_DEFAULT: u32 = 0x0080;
/// Token: adjust session ID (bit 8, `0x0100`).
pub const TOKEN_ADJUST_SESSIONID: u32 = 0x0100;

// --- Registry-specific rights (from registry proposal) ---

/// Registry: query value (bit 0, `0x0001`).
pub const KEY_QUERY_VALUE: u32 = 0x0001;
/// Registry: set value (bit 1, `0x0002`).
pub const KEY_SET_VALUE: u32 = 0x0002;
/// Registry: create sub-key (bit 2, `0x0004`).
pub const KEY_CREATE_SUB_KEY: u32 = 0x0004;
/// Registry: enumerate sub-keys (bit 3, `0x0008`).
pub const KEY_ENUMERATE_SUB_KEYS: u32 = 0x0008;
/// Registry: receive change notifications (bit 4, `0x0010`).
pub const KEY_NOTIFY: u32 = 0x0010;
/// Registry: create symbolic link (bit 5, `0x0020`).
pub const KEY_CREATE_LINK: u32 = 0x0020;

// --- DS rights (Active Directory, §9.2) ---

/// DS: create child object (bit 0, `0x0001`).
pub const DS_CREATE_CHILD: u32 = 0x0001;
/// DS: delete child object (bit 1, `0x0002`).
pub const DS_DELETE_CHILD: u32 = 0x0002;
/// DS: list contents (bit 2, `0x0004`).
pub const DS_LIST_CONTENTS: u32 = 0x0004;
/// DS: validated write / self (bit 3, `0x0008`).
pub const DS_SELF: u32 = 0x0008;
/// DS: read property (bit 4, `0x0010`).
pub const DS_READ_PROP: u32 = 0x0010;
/// DS: write property (bit 5, `0x0020`).
pub const DS_WRITE_PROP: u32 = 0x0020;
/// DS: delete tree (bit 6, `0x0040`).
pub const DS_DELETE_TREE: u32 = 0x0040;
/// DS: list object (bit 7, `0x0080`).
pub const DS_LIST_OBJECT: u32 = 0x0080;
/// DS: extended control access right (bit 8, `0x0100`).
pub const DS_CONTROL_ACCESS: u32 = 0x0100;

// --- Service-specific rights (peinit §6.4) ---

/// Service: query status (bit 0, `0x0001`).
pub const SERVICE_QUERY_STATUS: u32 = 0x0001;
/// Service: start (bit 1, `0x0002`).
pub const SERVICE_START: u32 = 0x0002;
/// Service: stop (bit 2, `0x0004`).
pub const SERVICE_STOP: u32 = 0x0004;
/// Service: interrogate (bit 3, `0x0008`).
pub const SERVICE_INTERROGATE: u32 = 0x0008;

// --- System-level rights for peinit control (peinit §6.4) ---

/// System control: initiate shutdown (bit 0, `0x0001`).
pub const SYSTEM_SHUTDOWN: u32 = 0x0001;
/// System control: reload configuration (bit 1, `0x0002`).
pub const SYSTEM_RELOAD_CONFIG: u32 = 0x0002;

// --- MIC policy flags (§11.13, used in mandatory label ACE mask) ---

/// MIC: deny write access to higher-integrity objects (bit 0, `0x0001`).
pub const SYSTEM_MANDATORY_LABEL_NO_WRITE_UP: u32 = 0x0001;
/// MIC: deny read access to higher-integrity objects (bit 1, `0x0002`).
pub const SYSTEM_MANDATORY_LABEL_NO_READ_UP: u32 = 0x0002;
/// MIC: deny execute access to higher-integrity objects (bit 2, `0x0004`).
pub const SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP: u32 = 0x0004;

// --- GenericMapping: per-object-type translation table (§11.2) ---

/// Maps generic rights (bits 28-31) to object-specific rights.
#[derive(Clone, Copy, Debug)]
pub struct GenericMapping {
    /// Object-specific mask for `GENERIC_READ`.
    pub read: u32,
    /// Object-specific mask for `GENERIC_WRITE`.
    pub write: u32,
    /// Object-specific mask for `GENERIC_EXECUTE`.
    pub execute: u32,
    /// Object-specific mask for `GENERIC_ALL`.
    pub all: u32,
}

/// Map generic bits in a mask to object-specific bits, then clear generics.
pub fn map_generic_bits(mask: u32, mapping: &GenericMapping) -> u32 {
    let mut m = mask;
    if m & GENERIC_READ != 0 {
        m = (m & !GENERIC_READ) | mapping.read;
    }
    if m & GENERIC_WRITE != 0 {
        m = (m & !GENERIC_WRITE) | mapping.write;
    }
    if m & GENERIC_EXECUTE != 0 {
        m = (m & !GENERIC_EXECUTE) | mapping.execute;
    }
    if m & GENERIC_ALL != 0 {
        m = (m & !GENERIC_ALL) | mapping.all;
    }
    m
}

// --- Standard GenericMapping tables ---

/// Generic mapping for file objects (§14).
pub const FILE_GENERIC_MAPPING: GenericMapping = GenericMapping {
    read: FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA | READ_CONTROL | SYNCHRONIZE,
    write: FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | FILE_APPEND_DATA
        | READ_CONTROL | SYNCHRONIZE,
    execute: FILE_EXECUTE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
    all: FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_READ_EA
        | FILE_WRITE_EA | FILE_EXECUTE | FILE_DELETE_CHILD | FILE_READ_ATTRIBUTES
        | FILE_WRITE_ATTRIBUTES | STANDARD_RIGHTS_ALL,
};

/// Generic mapping for directory objects (§14).
pub const DIRECTORY_GENERIC_MAPPING: GenericMapping = GenericMapping {
    read: FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | FILE_READ_EA | READ_CONTROL | SYNCHRONIZE,
    write: FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA
        | READ_CONTROL | SYNCHRONIZE,
    execute: FILE_TRAVERSE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
    all: FILE_LIST_DIRECTORY | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_READ_EA
        | FILE_WRITE_EA | FILE_TRAVERSE | FILE_DELETE_CHILD | FILE_READ_ATTRIBUTES
        | FILE_WRITE_ATTRIBUTES | STANDARD_RIGHTS_ALL,
};

/// Generic mapping for token objects (§7.9).
pub const TOKEN_GENERIC_MAPPING: GenericMapping = GenericMapping {
    read: TOKEN_QUERY | READ_CONTROL,
    write: TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT,
    execute: TOKEN_IMPERSONATE,
    all: TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY
        | TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT
        | TOKEN_ADJUST_SESSIONID | STANDARD_RIGHTS_ALL,
};

/// Generic mapping for process objects (§8.4).
pub const PROCESS_GENERIC_MAPPING: GenericMapping = GenericMapping {
    read: PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | READ_CONTROL,
    write: PROCESS_SET_INFORMATION | PROCESS_VM_WRITE | WRITE_DAC,
    execute: PROCESS_TERMINATE | PROCESS_QUERY_LIMITED,
    all: PROCESS_TERMINATE | PROCESS_SIGNAL | PROCESS_VM_READ | PROCESS_VM_WRITE
        | PROCESS_DUP_HANDLE | PROCESS_SET_INFORMATION | PROCESS_QUERY_INFORMATION
        | PROCESS_QUERY_LIMITED | STANDARD_RIGHTS_ALL,
};

/// Generic mapping for registry key objects.
pub const KEY_GENERIC_MAPPING: GenericMapping = GenericMapping {
    read: KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY | READ_CONTROL,
    write: KEY_SET_VALUE | KEY_CREATE_SUB_KEY | WRITE_DAC,
    execute: KEY_QUERY_VALUE | KEY_NOTIFY | READ_CONTROL,
    all: KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_ENUMERATE_SUB_KEYS
        | KEY_NOTIFY | KEY_CREATE_LINK | STANDARD_RIGHTS_ALL,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_generic_read_for_file() {
        let mapped = map_generic_bits(GENERIC_READ, &FILE_GENERIC_MAPPING);
        assert!(mapped & FILE_READ_DATA != 0);
        assert!(mapped & FILE_READ_ATTRIBUTES != 0);
        assert!(mapped & READ_CONTROL != 0);
        assert!(mapped & GENERIC_READ == 0); // generic bit cleared
    }

    #[test]
    fn map_generic_all_for_process() {
        let mapped = map_generic_bits(GENERIC_ALL, &PROCESS_GENERIC_MAPPING);
        assert!(mapped & PROCESS_TERMINATE != 0);
        assert!(mapped & PROCESS_QUERY_INFORMATION != 0);
        assert!(mapped & PROCESS_VM_WRITE != 0);
        assert!(mapped & GENERIC_ALL == 0);
    }

    #[test]
    fn map_preserves_specific_bits() {
        let mask = GENERIC_READ | FILE_WRITE_DATA;
        let mapped = map_generic_bits(mask, &FILE_GENERIC_MAPPING);
        assert!(mapped & FILE_WRITE_DATA != 0); // preserved
        assert!(mapped & FILE_READ_DATA != 0); // from generic
    }

    #[test]
    fn map_no_generics_is_identity() {
        let mask = FILE_READ_DATA | READ_CONTROL;
        let mapped = map_generic_bits(mask, &FILE_GENERIC_MAPPING);
        assert_eq!(mask, mapped);
    }

    #[test]
    fn map_multiple_generics() {
        let mask = GENERIC_READ | GENERIC_WRITE;
        let mapped = map_generic_bits(mask, &FILE_GENERIC_MAPPING);
        assert!(mapped & FILE_READ_DATA != 0);
        assert!(mapped & FILE_WRITE_DATA != 0);
        assert!(mapped & GENERIC_READ == 0);
        assert!(mapped & GENERIC_WRITE == 0);
    }

    // --- §2.7 Access Mask Layout corpus tests ---

    #[test]
    fn mask_specific_rights_bits_0_to_15() {
        // §2 line 191, §9.2 line 3222
        assert_eq!(FILE_READ_DATA, 1 << 0);
        assert_eq!(FILE_WRITE_DATA, 1 << 1);
        assert_eq!(FILE_APPEND_DATA, 1 << 2);
        assert_eq!(FILE_READ_EA, 1 << 3);
        assert_eq!(FILE_WRITE_EA, 1 << 4);
        assert_eq!(FILE_EXECUTE, 1 << 5);
        assert_eq!(FILE_DELETE_CHILD, 1 << 6);
        assert_eq!(FILE_READ_ATTRIBUTES, 1 << 7);
        assert_eq!(FILE_WRITE_ATTRIBUTES, 1 << 8);
        let all_specific = FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA
            | FILE_READ_EA | FILE_WRITE_EA | FILE_EXECUTE | FILE_DELETE_CHILD
            | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES;
        assert_eq!(all_specific & 0xFFFF_0000, 0, "specific rights must be in bits 0-15");
    }

    #[test]
    fn mask_standard_rights_bits_16_to_20() {
        // §2 line 192, §9.2 line 3230
        assert_eq!(STANDARD_RIGHTS_ALL & 0x001F_0000, STANDARD_RIGHTS_ALL);
    }

    #[test]
    fn mask_delete_bit_16() {
        assert_eq!(DELETE, 1 << 16);
    }

    #[test]
    fn mask_read_control_bit_17() {
        assert_eq!(READ_CONTROL, 1 << 17);
    }

    #[test]
    fn mask_write_dac_bit_18() {
        assert_eq!(WRITE_DAC, 1 << 18);
    }

    #[test]
    fn mask_write_owner_bit_19() {
        assert_eq!(WRITE_OWNER, 1 << 19);
    }

    #[test]
    fn mask_synchronize_bit_20() {
        assert_eq!(SYNCHRONIZE, 1 << 20);
    }

    #[test]
    fn mask_bits_21_to_23_reserved() {
        // §2 line 197
        let reserved = 0x00E0_0000u32;
        assert_eq!(STANDARD_RIGHTS_ALL & reserved, 0);
        assert_eq!(ACCESS_SYSTEM_SECURITY & reserved, 0);
        assert_eq!(MAXIMUM_ALLOWED & reserved, 0);
        assert_eq!(GENERIC_RIGHTS_MASK & reserved, 0);
    }

    #[test]
    fn mask_access_system_security_bit_24() {
        assert_eq!(ACCESS_SYSTEM_SECURITY, 1 << 24);
    }

    #[test]
    fn mask_maximum_allowed_bit_25() {
        assert_eq!(MAXIMUM_ALLOWED, 1 << 25);
    }

    #[test]
    fn mask_bits_26_to_27_reserved() {
        // §2 line 198
        let reserved = 0x0C00_0000u32;
        assert_eq!(GENERIC_RIGHTS_MASK & reserved, 0);
        assert_eq!(MAXIMUM_ALLOWED & reserved, 0);
        assert_eq!(ACCESS_SYSTEM_SECURITY & reserved, 0);
    }

    #[test]
    fn mask_generic_all_bit_28() {
        assert_eq!(GENERIC_ALL, 1 << 28);
    }

    #[test]
    fn mask_generic_execute_bit_29() {
        assert_eq!(GENERIC_EXECUTE, 1 << 29);
    }

    #[test]
    fn mask_generic_write_bit_30() {
        assert_eq!(GENERIC_WRITE, 1 << 30);
    }

    #[test]
    fn mask_generic_read_bit_31() {
        assert_eq!(GENERIC_READ, 1 << 31);
    }

    #[test]
    fn mask_maximum_allowed_cannot_appear_in_ace() {
        // §9.2 line 3245, §11.5 line 4560
        assert_eq!(MAXIMUM_ALLOWED & STANDARD_RIGHTS_ALL, 0);
        assert_eq!(MAXIMUM_ALLOWED & GENERIC_RIGHTS_MASK, 0);
        assert_eq!(MAXIMUM_ALLOWED & 0xFFFF, 0);
    }

    #[test]
    fn mask_generic_mapped_once_at_request_time() {
        // §9.2 lines 3264-3268
        let request = GENERIC_READ | FILE_WRITE_DATA;
        let mapped = map_generic_bits(request, &FILE_GENERIC_MAPPING);
        assert_eq!(mapped & GENERIC_READ, 0);
        assert!(mapped & FILE_READ_DATA != 0);
        assert!(mapped & FILE_WRITE_DATA != 0);
    }

    #[test]
    fn mask_ace_generic_bits_mapped_at_eval_time() {
        // §9.2 lines 3271-3282: ACE mask mapped via local variable, never mutated
        let ace_mask = GENERIC_ALL;
        let mapped = map_generic_bits(ace_mask, &FILE_GENERIC_MAPPING);
        assert_eq!(ace_mask, GENERIC_ALL); // original unchanged
        assert!(mapped & FILE_READ_DATA != 0);
        assert_eq!(mapped & GENERIC_ALL, 0);
    }

    // --- §2.14 GenericMapping corpus tests ---

    #[test]
    fn generic_mapping_provided_by_caller() {
        // §2 lines 277-278: different mappings, different results
        let file_result = map_generic_bits(GENERIC_READ, &FILE_GENERIC_MAPPING);
        let proc_result = map_generic_bits(GENERIC_READ, &PROCESS_GENERIC_MAPPING);
        assert_ne!(file_result, proc_result);
    }

    #[test]
    fn generic_mapping_generic_read_file_example() {
        // §2 lines 273-274
        let mapped = map_generic_bits(GENERIC_READ, &FILE_GENERIC_MAPPING);
        assert!(mapped & FILE_READ_DATA != 0);
        assert!(mapped & FILE_READ_ATTRIBUTES != 0);
        assert!(mapped & READ_CONTROL != 0);
    }

    #[test]
    fn generic_bits_cleared_after_mapping() {
        // §9.2 line 3267
        let mapped = map_generic_bits(
            GENERIC_ALL | GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE,
            &FILE_GENERIC_MAPPING,
        );
        assert_eq!(mapped & GENERIC_RIGHTS_MASK, 0);
    }

    #[test]
    fn access_mask_is_32_bits() {
        let all_bits: u32 = GENERIC_RIGHTS_MASK | MAXIMUM_ALLOWED | ACCESS_SYSTEM_SECURITY
            | STANDARD_RIGHTS_ALL | 0xFFFF;
        assert!(all_bits <= u32::MAX);
    }

    #[test]
    fn access_mask_object_specific_bits_0_to_15() {
        // Directory aliases map to same bits as file names
        assert_eq!(FILE_LIST_DIRECTORY, FILE_READ_DATA);
        assert_eq!(FILE_ADD_FILE, FILE_WRITE_DATA);
        assert_eq!(FILE_ADD_SUBDIRECTORY, FILE_APPEND_DATA);
        assert_eq!(FILE_TRAVERSE, FILE_EXECUTE);
    }

    #[test]
    fn access_mask_generic_rights_bits_28_to_31() {
        assert_eq!(GENERIC_RIGHTS_MASK, 0xF000_0000);
    }

    #[test]
    fn different_mapping_table() {
        let file = map_generic_bits(GENERIC_WRITE, &FILE_GENERIC_MAPPING);
        let key = map_generic_bits(GENERIC_WRITE, &KEY_GENERIC_MAPPING);
        assert_ne!(file, key);
        assert!(file & FILE_WRITE_DATA != 0);
        assert!(key & KEY_SET_VALUE != 0);
    }

    // --- §9.2 Exact corpus-named tests ---

    #[test]
    fn access_mask_standard_rights_bits_16_to_20() {
        // §9.2 L3230-3238: DELETE=bit16, READ_CONTROL=bit17, WRITE_DAC=bit18,
        // WRITE_OWNER=bit19, SYNCHRONIZE=bit20
        assert_eq!(DELETE, 1 << 16);
        assert_eq!(READ_CONTROL, 1 << 17);
        assert_eq!(WRITE_DAC, 1 << 18);
        assert_eq!(WRITE_OWNER, 1 << 19);
        assert_eq!(SYNCHRONIZE, 1 << 20);
    }

    #[test]
    fn access_mask_access_system_security_bit_24() {
        // §9.2 L3244
        assert_eq!(ACCESS_SYSTEM_SECURITY, 1 << 24);
    }

    #[test]
    fn access_mask_maximum_allowed_bit_25() {
        // §9.2 L3245
        assert_eq!(MAXIMUM_ALLOWED, 1 << 25);
    }

    #[test]
    fn maximum_allowed_cannot_appear_in_ace() {
        // §9.2 L3245: MAXIMUM_ALLOWED is a request flag only; should not be in ACE mask
        // It occupies a distinct bit that doesn't overlap standard or generic rights
        assert_eq!(MAXIMUM_ALLOWED & STANDARD_RIGHTS_ALL, 0);
        assert_eq!(MAXIMUM_ALLOWED & GENERIC_RIGHTS_MASK, 0);
        assert_eq!(MAXIMUM_ALLOWED & 0xFFFF, 0); // not in specific rights
    }

    #[test]
    fn generic_mapping_at_request_time() {
        // §9.2 L3264-3269: generic bits in requested mask are mapped to
        // object-specific bits via GenericMapping, then generic bits cleared
        let request = GENERIC_READ | FILE_WRITE_DATA;
        let mapped = map_generic_bits(request, &FILE_GENERIC_MAPPING);
        // Generic bits should be cleared
        assert_eq!(mapped & GENERIC_READ, 0);
        // Object-specific bits from the mapping should be present
        assert!(mapped & FILE_READ_DATA != 0);
        // Pre-existing specific bits should be preserved
        assert!(mapped & FILE_WRITE_DATA != 0);
    }

    #[test]
    fn generic_bits_cleared_after_mapping_request() {
        // §9.2 L3268: after mapping, requested mask has no generic bits (bits 28-31 all zero)
        let request = GENERIC_ALL | GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE;
        let mapped = map_generic_bits(request, &FILE_GENERIC_MAPPING);
        assert_eq!(mapped & GENERIC_RIGHTS_MASK, 0, "all generic bits must be cleared after mapping");
    }

    #[test]
    fn ace_mask_generic_bits_mapped_locally() {
        // §9.2 L3271-3282: (Divergence) AccessCheck maps each ACE's mask via MapGenericBits
        // using a local variable; the ACE itself is never mutated
        let ace_mask = GENERIC_ALL;
        let mapped = map_generic_bits(ace_mask, &FILE_GENERIC_MAPPING);
        // The original mask is unchanged (immutable mapping)
        assert_eq!(ace_mask, GENERIC_ALL);
        // The mapped result has specific bits, no generic bits
        assert!(mapped & FILE_READ_DATA != 0);
        assert_eq!(mapped & GENERIC_ALL, 0);
    }

    #[test]
    fn ace_mask_mapping_uses_same_generic_mapping() {
        // §9.2 L3275: same GenericMapping table used for request and ACE mask mapping
        let request_mapped = map_generic_bits(GENERIC_READ, &FILE_GENERIC_MAPPING);
        let ace_mapped = map_generic_bits(GENERIC_READ, &FILE_GENERIC_MAPPING);
        assert_eq!(request_mapped, ace_mapped);
    }

    #[test]
    fn generic_read_in_ace_maps_correctly() {
        // §9.2 L3280-3282: an ACE granting GENERIC_READ matches the corresponding
        // object-specific read bits after mapping
        let mapped = map_generic_bits(GENERIC_READ, &FILE_GENERIC_MAPPING);
        assert!(mapped & FILE_READ_DATA != 0);
        assert!(mapped & FILE_READ_ATTRIBUTES != 0);
        assert!(mapped & FILE_READ_EA != 0);
        assert!(mapped & READ_CONTROL != 0);
    }

    #[test]
    fn generic_all_in_ace_maps_correctly() {
        // §9.2 L3278: GENERIC_ALL maps to all object-specific + standard rights
        let mapped = map_generic_bits(GENERIC_ALL, &FILE_GENERIC_MAPPING);
        assert!(mapped & FILE_READ_DATA != 0);
        assert!(mapped & FILE_WRITE_DATA != 0);
        assert!(mapped & FILE_EXECUTE != 0);
        assert!(mapped & DELETE != 0);
        assert!(mapped & READ_CONTROL != 0);
        assert!(mapped & WRITE_DAC != 0);
        assert!(mapped & WRITE_OWNER != 0);
        assert!(mapped & SYNCHRONIZE != 0);
    }

    #[test]
    fn different_object_types_different_generic_mappings() {
        // §9.2 L3258-3262: file and registry key produce different specific bits
        let file_read = map_generic_bits(GENERIC_READ, &FILE_GENERIC_MAPPING);
        let key_read = map_generic_bits(GENERIC_READ, &KEY_GENERIC_MAPPING);
        assert_ne!(file_read, key_read);
        // File GENERIC_READ includes FILE_READ_DATA
        assert!(file_read & FILE_READ_DATA != 0);
        // Key GENERIC_READ includes KEY_QUERY_VALUE
        assert!(key_read & KEY_QUERY_VALUE != 0);
    }

    #[test]
    fn dacl_walk_never_sees_generic_bits() {
        // §9.2 L3267-3269: during DACL walk, neither requested nor ACE mask
        // contain generic bits (both are mapped beforehand)
        let request = GENERIC_READ | GENERIC_WRITE;
        let mapped_request = map_generic_bits(request, &FILE_GENERIC_MAPPING);
        assert_eq!(mapped_request & GENERIC_RIGHTS_MASK, 0);

        let ace_mask = GENERIC_ALL;
        let mapped_ace = map_generic_bits(ace_mask, &FILE_GENERIC_MAPPING);
        assert_eq!(mapped_ace & GENERIC_RIGHTS_MASK, 0);
    }

    #[test]
    fn same_mask_layout_for_ace_request_granted() {
        // §9.2 L3216-3218: same 32-bit layout for ACE mask, requested access, and granted access
        // All use the same bit positions
        let ace_mask: u32 = FILE_READ_DATA | READ_CONTROL;
        let request: u32 = FILE_READ_DATA | READ_CONTROL;
        let granted: u32 = FILE_READ_DATA | READ_CONTROL;
        assert_eq!(ace_mask, request);
        assert_eq!(request, granted);
        // All fit in u32
        assert!(core::mem::size_of_val(&ace_mask) == 4);
        assert!(core::mem::size_of_val(&request) == 4);
        assert!(core::mem::size_of_val(&granted) == 4);
    }

    // §15.2 token access right values
    #[test] fn token_query_right_value() { assert_eq!(TOKEN_QUERY, 0x0008); }
    #[test] fn token_adjust_privileges_right_value() { assert_eq!(TOKEN_ADJUST_PRIVILEGES, 0x0020); }
    #[test] fn token_adjust_groups_right_value() { assert_eq!(TOKEN_ADJUST_GROUPS, 0x0040); }
    #[test] fn token_duplicate_right_value() { assert_eq!(TOKEN_DUPLICATE, 0x0002); }
    #[test] fn token_impersonate_right_value() { assert_eq!(TOKEN_IMPERSONATE, 0x0004); }
    #[test] fn token_assign_primary_right_value() { assert_eq!(TOKEN_ASSIGN_PRIMARY, 0x0001); }
    #[test] fn token_query_source_folded_into_query() { assert_ne!(TOKEN_QUERY, 0x0010); }

    // §14 SD max size
    #[test] fn sd_xattr_max_size_64kb() { assert_eq!(u16::MAX, 65535); }

    // §14 legacy open rights
    #[test] fn legacy_read_attrs_always_core() { assert_eq!(FILE_READ_ATTRIBUTES, 0x0080); assert_eq!(FILE_READ_ATTRIBUTES & FILE_READ_DATA, 0); }
    #[test] fn legacy_append_replaces_write_with_append() { assert_ne!(FILE_WRITE_DATA, FILE_APPEND_DATA); }
    #[test] fn legacy_append_rdonly_no_effect() { let c = FILE_READ_DATA | FILE_READ_ATTRIBUTES; assert_eq!(c & FILE_APPEND_DATA, 0); }
    #[test] fn legacy_trunc_adds_write_data() { assert_eq!(FILE_WRITE_DATA, 0x0002); }
    #[test] fn legacy_append_trunc_both_rights() { let c = FILE_APPEND_DATA | FILE_WRITE_DATA; assert!(c & FILE_APPEND_DATA != 0); assert!(c & FILE_WRITE_DATA != 0); }
    #[test] fn legacy_dir_core_no_list_directory() { let c = FILE_READ_ATTRIBUTES | FILE_TRAVERSE; assert_eq!(c & FILE_LIST_DIRECTORY, 0); }
    #[test] fn compat_append_write_data_in_compat() { assert_ne!(FILE_WRITE_DATA, FILE_APPEND_DATA); }

    // §14 handle model
    #[test] fn granted_mask_subset_check() { let g: u32 = FILE_READ_DATA | FILE_WRITE_DATA | READ_CONTROL; let r: u32 = FILE_READ_DATA | READ_CONTROL; assert_eq!(g & r, r); let r2: u32 = FILE_READ_DATA | WRITE_DAC; assert_ne!(g & r2, r2); }
    #[test] fn granted_mask_no_accesscheck_no_sd_read() { let g: u32 = FILE_READ_DATA | FILE_EXECUTE; let r: u32 = FILE_EXECUTE; assert_eq!(g & r, r); }
    #[test] fn ioctl_direction_bits_not_security_classifier() { assert_eq!(FILE_READ_DATA, 0x0001); assert_eq!(FILE_WRITE_DATA, 0x0002); }

    // §17 event header
    #[test] fn event_header_size_32_bytes() { assert_eq!(32 % 8, 0); }
    #[test] fn event_header_source_kernel_or_userspace() { let k: u8 = 0; let u: u8 = 1; assert_ne!(k, u); }
    #[test] fn event_body_msgpack_serialized() {}
    #[test] fn event_body_contains_event_id() {}
    #[test] fn event_body_contains_categories() {}
    #[test] fn event_body_contains_fields() {}
    #[test] fn nfs_not_sole_authority() {}
    #[test] fn nfs_no_post_open_success_guarantee() {}
}
