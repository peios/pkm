// Access mask constants (§9.2).
//
// Every ACE, access request, and granted result uses a 32-bit mask.
// Bits 0-15 are object-specific. Bits 16-31 are standard/generic/special.

// --- Standard rights (bits 16-20, common to all object types) ---

pub const DELETE: u32 = 0x0001_0000;
pub const READ_CONTROL: u32 = 0x0002_0000;
pub const WRITE_DAC: u32 = 0x0004_0000;
pub const WRITE_OWNER: u32 = 0x0008_0000;
pub const SYNCHRONIZE: u32 = 0x0010_0000;

pub const STANDARD_RIGHTS_ALL: u32 =
    DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER | SYNCHRONIZE;

// --- Special rights (bits 24-25) ---

/// Read/write the SACL. Requires SeSecurityPrivilege.
pub const ACCESS_SYSTEM_SECURITY: u32 = 0x0100_0000;

/// Query mode: compute the maximum grantable access mask.
pub const MAXIMUM_ALLOWED: u32 = 0x0200_0000;

// --- Generic rights (bits 28-31, mapped per object type) ---

pub const GENERIC_ALL: u32 = 0x1000_0000;
pub const GENERIC_EXECUTE: u32 = 0x2000_0000;
pub const GENERIC_WRITE: u32 = 0x4000_0000;
pub const GENERIC_READ: u32 = 0x8000_0000;

pub const GENERIC_RIGHTS_MASK: u32 =
    GENERIC_ALL | GENERIC_EXECUTE | GENERIC_WRITE | GENERIC_READ;

// --- File-specific rights (bits 0-8) §14 ---

pub const FILE_READ_DATA: u32 = 0x0001;
pub const FILE_WRITE_DATA: u32 = 0x0002;
pub const FILE_APPEND_DATA: u32 = 0x0004;
pub const FILE_READ_EA: u32 = 0x0008;
pub const FILE_WRITE_EA: u32 = 0x0010;
pub const FILE_EXECUTE: u32 = 0x0020;
pub const FILE_READ_ATTRIBUTES: u32 = 0x0080;
pub const FILE_WRITE_ATTRIBUTES: u32 = 0x0100;

// Directory aliases (same bit positions, different names)
pub const FILE_LIST_DIRECTORY: u32 = 0x0001; // = FILE_READ_DATA
pub const FILE_ADD_FILE: u32 = 0x0002; // = FILE_WRITE_DATA
pub const FILE_ADD_SUBDIRECTORY: u32 = 0x0004; // = FILE_APPEND_DATA
pub const FILE_TRAVERSE: u32 = 0x0020; // = FILE_EXECUTE
pub const FILE_DELETE_CHILD: u32 = 0x0040;

// --- Process-specific rights (§8.4) ---

pub const PROCESS_TERMINATE: u32 = 0x0001;
pub const PROCESS_SIGNAL: u32 = 0x0002;
pub const PROCESS_VM_READ: u32 = 0x0010;
pub const PROCESS_VM_WRITE: u32 = 0x0020;
pub const PROCESS_DUP_HANDLE: u32 = 0x0040;
pub const PROCESS_SET_INFORMATION: u32 = 0x0200;
pub const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
pub const PROCESS_QUERY_LIMITED: u32 = 0x1000;

// --- Token-specific rights (§7.9) ---

pub const TOKEN_ASSIGN_PRIMARY: u32 = 0x0001;
pub const TOKEN_DUPLICATE: u32 = 0x0002;
pub const TOKEN_IMPERSONATE: u32 = 0x0004;
pub const TOKEN_QUERY: u32 = 0x0008;
// 0x0010 reserved (TOKEN_QUERY_SOURCE, folded into TOKEN_QUERY)
pub const TOKEN_ADJUST_PRIVILEGES: u32 = 0x0020;
pub const TOKEN_ADJUST_GROUPS: u32 = 0x0040;
pub const TOKEN_ADJUST_DEFAULT: u32 = 0x0080;
pub const TOKEN_ADJUST_SESSIONID: u32 = 0x0100;

// --- Registry-specific rights (from registry proposal) ---

pub const KEY_QUERY_VALUE: u32 = 0x0001;
pub const KEY_SET_VALUE: u32 = 0x0002;
pub const KEY_CREATE_SUB_KEY: u32 = 0x0004;
pub const KEY_ENUMERATE_SUB_KEYS: u32 = 0x0008;
pub const KEY_NOTIFY: u32 = 0x0010;
pub const KEY_CREATE_LINK: u32 = 0x0020;

// --- DS rights (Active Directory, §9.2) ---

pub const DS_CREATE_CHILD: u32 = 0x0001;
pub const DS_DELETE_CHILD: u32 = 0x0002;
pub const DS_LIST_CONTENTS: u32 = 0x0004;
pub const DS_SELF: u32 = 0x0008;
pub const DS_READ_PROP: u32 = 0x0010;
pub const DS_WRITE_PROP: u32 = 0x0020;
pub const DS_DELETE_TREE: u32 = 0x0040;
pub const DS_LIST_OBJECT: u32 = 0x0080;
pub const DS_CONTROL_ACCESS: u32 = 0x0100;

// --- Service-specific rights (peinit §6.4) ---

pub const SERVICE_QUERY_STATUS: u32 = 0x0001;
pub const SERVICE_START: u32 = 0x0002;
pub const SERVICE_STOP: u32 = 0x0004;
pub const SERVICE_INTERROGATE: u32 = 0x0008;

// --- System-level rights for peinit control (peinit §6.4) ---

pub const SYSTEM_SHUTDOWN: u32 = 0x0001;
pub const SYSTEM_RELOAD_CONFIG: u32 = 0x0002;

// --- MIC policy flags (§11.13, used in mandatory label ACE mask) ---

pub const SYSTEM_MANDATORY_LABEL_NO_WRITE_UP: u32 = 0x0001;
pub const SYSTEM_MANDATORY_LABEL_NO_READ_UP: u32 = 0x0002;
pub const SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP: u32 = 0x0004;

// --- GenericMapping: per-object-type translation table (§11.2) ---

/// Maps generic rights (bits 28-31) to object-specific rights.
#[derive(Clone, Copy, Debug)]
pub struct GenericMapping {
    pub read: u32,
    pub write: u32,
    pub execute: u32,
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

pub const FILE_GENERIC_MAPPING: GenericMapping = GenericMapping {
    read: FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA | READ_CONTROL | SYNCHRONIZE,
    write: FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | FILE_APPEND_DATA
        | READ_CONTROL | SYNCHRONIZE,
    execute: FILE_EXECUTE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
    all: FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_READ_EA
        | FILE_WRITE_EA | FILE_EXECUTE | FILE_DELETE_CHILD | FILE_READ_ATTRIBUTES
        | FILE_WRITE_ATTRIBUTES | STANDARD_RIGHTS_ALL,
};

pub const DIRECTORY_GENERIC_MAPPING: GenericMapping = GenericMapping {
    read: FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | FILE_READ_EA | READ_CONTROL | SYNCHRONIZE,
    write: FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA
        | READ_CONTROL | SYNCHRONIZE,
    execute: FILE_TRAVERSE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
    all: FILE_LIST_DIRECTORY | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_READ_EA
        | FILE_WRITE_EA | FILE_TRAVERSE | FILE_DELETE_CHILD | FILE_READ_ATTRIBUTES
        | FILE_WRITE_ATTRIBUTES | STANDARD_RIGHTS_ALL,
};

pub const TOKEN_GENERIC_MAPPING: GenericMapping = GenericMapping {
    read: TOKEN_QUERY | READ_CONTROL,
    write: TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT,
    execute: TOKEN_IMPERSONATE,
    all: TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY
        | TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT
        | TOKEN_ADJUST_SESSIONID | STANDARD_RIGHTS_ALL,
};

pub const PROCESS_GENERIC_MAPPING: GenericMapping = GenericMapping {
    read: PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | READ_CONTROL,
    write: PROCESS_SET_INFORMATION | PROCESS_VM_WRITE | WRITE_DAC,
    execute: PROCESS_TERMINATE | PROCESS_QUERY_LIMITED,
    all: PROCESS_TERMINATE | PROCESS_SIGNAL | PROCESS_VM_READ | PROCESS_VM_WRITE
        | PROCESS_DUP_HANDLE | PROCESS_SET_INFORMATION | PROCESS_QUERY_INFORMATION
        | PROCESS_QUERY_LIMITED | STANDARD_RIGHTS_ALL,
};

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
}
