//! PSD-005 registry constants used by the LCS semantic core.

/// `reg_open_key` syscall number.
pub const SYS_REG_OPEN_KEY: u32 = peios_uapi::SYS_REG_OPEN_KEY;
/// `reg_create_key` syscall number.
pub const SYS_REG_CREATE_KEY: u32 = peios_uapi::SYS_REG_CREATE_KEY;
/// `reg_begin_transaction` syscall number.
pub const SYS_REG_BEGIN_TRANSACTION: u32 = peios_uapi::SYS_REG_BEGIN_TRANSACTION;

/// Registry ioctl type byte.
pub const REG_IOC_TYPE: u8 = b'R';

pub const REG_SRC_REGISTER: u8 = peios_uapi::REG_SRC_REGISTER_NR as u8;

pub const REG_IOC_QUERY_VALUE: u8 = peios_uapi::REG_IOC_QUERY_VALUE_NR as u8;
pub const REG_IOC_SET_VALUE: u8 = peios_uapi::REG_IOC_SET_VALUE_NR as u8;
pub const REG_IOC_DELETE_VALUE: u8 = peios_uapi::REG_IOC_DELETE_VALUE_NR as u8;
pub const REG_IOC_BLANKET_TOMBSTONE: u8 = peios_uapi::REG_IOC_BLANKET_TOMBSTONE_NR as u8;
pub const REG_IOC_QUERY_VALUES_BATCH: u8 = peios_uapi::REG_IOC_QUERY_VALUES_BATCH_NR as u8;
pub const REG_IOC_ENUM_VALUES: u8 = peios_uapi::REG_IOC_ENUM_VALUES_NR as u8;
pub const REG_IOC_ENUM_SUBKEYS: u8 = peios_uapi::REG_IOC_ENUM_SUBKEYS_NR as u8;
pub const REG_IOC_QUERY_KEY_INFO: u8 = peios_uapi::REG_IOC_QUERY_KEY_INFO_NR as u8;
pub const REG_IOC_DELETE_KEY: u8 = peios_uapi::REG_IOC_DELETE_KEY_NR as u8;
pub const REG_IOC_HIDE_KEY: u8 = peios_uapi::REG_IOC_HIDE_KEY_NR as u8;
pub const REG_IOC_GET_SECURITY: u8 = peios_uapi::REG_IOC_GET_SECURITY_NR as u8;
pub const REG_IOC_SET_SECURITY: u8 = peios_uapi::REG_IOC_SET_SECURITY_NR as u8;
pub const REG_IOC_NOTIFY: u8 = peios_uapi::REG_IOC_NOTIFY_NR as u8;
pub const REG_IOC_FLUSH: u8 = peios_uapi::REG_IOC_FLUSH_NR as u8;
pub const REG_IOC_BACKUP: u8 = peios_uapi::REG_IOC_BACKUP_NR as u8;
pub const REG_IOC_RESTORE: u8 = peios_uapi::REG_IOC_RESTORE_NR as u8;
pub const REG_IOC_COMMIT: u8 = peios_uapi::REG_IOC_COMMIT_NR as u8;
pub const REG_IOC_TXN_STATUS: u8 = peios_uapi::REG_IOC_TXN_STATUS_NR as u8;

pub const REG_TXN_ACTIVE_UNBOUND: u32 = peios_uapi::REG_TXN_ACTIVE_UNBOUND;
pub const REG_TXN_ACTIVE_BOUND: u32 = peios_uapi::REG_TXN_ACTIVE_BOUND;
pub const REG_TXN_COMMITTED: u32 = peios_uapi::REG_TXN_COMMITTED;
pub const REG_TXN_ABORTED: u32 = peios_uapi::REG_TXN_ABORTED;
pub const REG_TXN_TIMED_OUT: u32 = peios_uapi::REG_TXN_TIMED_OUT;
pub const REG_TXN_SOURCE_DOWN: u32 = peios_uapi::REG_TXN_SOURCE_DOWN;

pub const REG_OPEN_LINK: u32 = peios_uapi::REG_OPEN_LINK;
pub const REG_OPTION_VOLATILE: u32 = peios_uapi::REG_OPTION_VOLATILE;
pub const REG_OPTION_CREATE_LINK: u32 = peios_uapi::REG_OPTION_CREATE_LINK;
pub const REG_CREATED_NEW: u32 = peios_uapi::REG_CREATED_NEW;
pub const REG_OPENED_EXISTING: u32 = peios_uapi::REG_OPENED_EXISTING;

pub const KEY_QUERY_VALUE: u32 = peios_uapi::KEY_QUERY_VALUE;
pub const KEY_SET_VALUE: u32 = peios_uapi::KEY_SET_VALUE;
pub const KEY_CREATE_SUB_KEY: u32 = peios_uapi::KEY_CREATE_SUB_KEY;
pub const KEY_ENUMERATE_SUB_KEYS: u32 = peios_uapi::KEY_ENUMERATE_SUB_KEYS;
pub const KEY_NOTIFY: u32 = peios_uapi::KEY_NOTIFY;
pub const KEY_CREATE_LINK: u32 = peios_uapi::KEY_CREATE_LINK;

pub const DELETE: u32 = peios_uapi::KACS_ACCESS_DELETE;
pub const READ_CONTROL: u32 = peios_uapi::KACS_ACCESS_READ_CONTROL;
pub const WRITE_DAC: u32 = peios_uapi::KACS_ACCESS_WRITE_DAC;
pub const WRITE_OWNER: u32 = peios_uapi::KACS_ACCESS_WRITE_OWNER;
pub const SYNCHRONIZE: u32 = peios_uapi::KACS_ACCESS_SYNCHRONIZE;
pub const ACCESS_SYSTEM_SECURITY: u32 = peios_uapi::KACS_ACCESS_ACCESS_SYSTEM_SECURITY;
pub const MAXIMUM_ALLOWED: u32 = peios_uapi::KACS_ACCESS_MAXIMUM_ALLOWED;

pub const GENERIC_ALL: u32 = peios_uapi::KACS_ACCESS_GENERIC_ALL;
pub const GENERIC_EXECUTE: u32 = peios_uapi::KACS_ACCESS_GENERIC_EXECUTE;
pub const GENERIC_WRITE: u32 = peios_uapi::KACS_ACCESS_GENERIC_WRITE;
pub const GENERIC_READ: u32 = peios_uapi::KACS_ACCESS_GENERIC_READ;

pub const KEY_READ: u32 = KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY | READ_CONTROL;
pub const KEY_WRITE: u32 = KEY_SET_VALUE | KEY_CREATE_SUB_KEY | READ_CONTROL;
pub const KEY_ALL_ACCESS: u32 = KEY_QUERY_VALUE
    | KEY_SET_VALUE
    | KEY_CREATE_SUB_KEY
    | KEY_ENUMERATE_SUB_KEYS
    | KEY_NOTIFY
    | KEY_CREATE_LINK
    | DELETE
    | READ_CONTROL
    | WRITE_DAC
    | WRITE_OWNER;

pub const REG_VALID_DESIRED_ACCESS_MASK: u32 = peios_uapi::REG_VALID_DESIRED_ACCESS_MASK;
pub const REG_VALID_MAPPED_ACCESS_MASK: u32 = peios_uapi::REG_VALID_MAPPED_ACCESS_MASK;
pub const REG_VALID_ACE_ACCESS_MASK: u32 = peios_uapi::REG_VALID_ACE_ACCESS_MASK;

pub const OWNER_SECURITY_INFORMATION: u32 = peios_uapi::OWNER_SECURITY_INFORMATION;
pub const GROUP_SECURITY_INFORMATION: u32 = peios_uapi::GROUP_SECURITY_INFORMATION;
pub const DACL_SECURITY_INFORMATION: u32 = peios_uapi::DACL_SECURITY_INFORMATION;
pub const SACL_SECURITY_INFORMATION: u32 = peios_uapi::SACL_SECURITY_INFORMATION;
pub const REG_VALID_SECURITY_INFORMATION: u32 = OWNER_SECURITY_INFORMATION
    | GROUP_SECURITY_INFORMATION
    | DACL_SECURITY_INFORMATION
    | SACL_SECURITY_INFORMATION;

pub const REG_NONE: u32 = peios_uapi::REG_NONE;
pub const REG_SZ: u32 = peios_uapi::REG_SZ;
pub const REG_EXPAND_SZ: u32 = peios_uapi::REG_EXPAND_SZ;
pub const REG_BINARY: u32 = peios_uapi::REG_BINARY;
pub const REG_DWORD: u32 = peios_uapi::REG_DWORD;
pub const REG_DWORD_BIG_ENDIAN: u32 = peios_uapi::REG_DWORD_BIG_ENDIAN;
pub const REG_LINK: u32 = peios_uapi::REG_LINK;
pub const REG_MULTI_SZ: u32 = peios_uapi::REG_MULTI_SZ;
pub const REG_RESOURCE_LIST: u32 = peios_uapi::REG_RESOURCE_LIST;
pub const REG_FULL_RESOURCE_DESCRIPTOR: u32 = peios_uapi::REG_FULL_RESOURCE_DESCRIPTOR;
pub const REG_RESOURCE_REQUIREMENTS_LIST: u32 = peios_uapi::REG_RESOURCE_REQUIREMENTS_LIST;
pub const REG_QWORD: u32 = peios_uapi::REG_QWORD;
pub const REG_TOMBSTONE: u32 = peios_uapi::REG_TOMBSTONE;

pub const REG_WATCH_VALUE_SET: u32 = peios_uapi::REG_WATCH_VALUE_SET;
pub const REG_WATCH_VALUE_DELETED: u32 = peios_uapi::REG_WATCH_VALUE_DELETED;
pub const REG_WATCH_SUBKEY_CREATED: u32 = peios_uapi::REG_WATCH_SUBKEY_CREATED;
pub const REG_WATCH_SUBKEY_DELETED: u32 = peios_uapi::REG_WATCH_SUBKEY_DELETED;
pub const REG_WATCH_SD_CHANGED: u32 = peios_uapi::REG_WATCH_SD_CHANGED;
pub const REG_WATCH_KEY_DELETED: u32 = peios_uapi::REG_WATCH_KEY_DELETED;
pub const REG_WATCH_OVERFLOW: u32 = peios_uapi::REG_WATCH_OVERFLOW;

pub const REG_NOTIFY_VALUE: u32 = peios_uapi::REG_NOTIFY_VALUE;
pub const REG_NOTIFY_SUBKEY: u32 = peios_uapi::REG_NOTIFY_SUBKEY;
pub const REG_NOTIFY_SD: u32 = peios_uapi::REG_NOTIFY_SD;
pub const REG_NOTIFY_ALL: u32 = peios_uapi::REG_NOTIFY_ALL;

pub const RSI_LOOKUP: u16 = peios_uapi::RSI_LOOKUP as u16;
pub const RSI_CREATE_ENTRY: u16 = peios_uapi::RSI_CREATE_ENTRY as u16;
pub const RSI_HIDE_ENTRY: u16 = peios_uapi::RSI_HIDE_ENTRY as u16;
pub const RSI_DELETE_ENTRY: u16 = peios_uapi::RSI_DELETE_ENTRY as u16;
pub const RSI_ENUM_CHILDREN: u16 = peios_uapi::RSI_ENUM_CHILDREN as u16;
pub const RSI_CREATE_KEY: u16 = peios_uapi::RSI_CREATE_KEY as u16;
pub const RSI_READ_KEY: u16 = peios_uapi::RSI_READ_KEY as u16;
pub const RSI_WRITE_KEY: u16 = peios_uapi::RSI_WRITE_KEY as u16;
pub const RSI_DROP_KEY: u16 = peios_uapi::RSI_DROP_KEY as u16;
pub const RSI_QUERY_VALUES: u16 = peios_uapi::RSI_QUERY_VALUES as u16;
pub const RSI_SET_VALUE: u16 = peios_uapi::RSI_SET_VALUE as u16;
pub const RSI_DELETE_VALUE_ENTRY: u16 = peios_uapi::RSI_DELETE_VALUE_ENTRY as u16;
pub const RSI_SET_BLANKET_TOMBSTONE: u16 = peios_uapi::RSI_SET_BLANKET_TOMBSTONE as u16;
pub const RSI_BEGIN_TRANSACTION: u16 = peios_uapi::RSI_BEGIN_TRANSACTION as u16;
pub const RSI_COMMIT_TRANSACTION: u16 = peios_uapi::RSI_COMMIT_TRANSACTION as u16;
pub const RSI_ABORT_TRANSACTION: u16 = peios_uapi::RSI_ABORT_TRANSACTION as u16;
pub const RSI_FLUSH: u16 = peios_uapi::RSI_FLUSH as u16;
pub const RSI_DELETE_LAYER: u16 = peios_uapi::RSI_DELETE_LAYER as u16;

pub const RSI_RESPONSE_BIT: u16 = peios_uapi::RSI_RESPONSE_BIT as u16;
pub const RSI_REQUEST_HEADER_LEN: usize = peios_uapi::RSI_REQUEST_HEADER_SIZE as usize;
pub const RSI_RESPONSE_HEADER_LEN: usize = peios_uapi::RSI_RESPONSE_HEADER_SIZE as usize;
pub const RSI_STATUS_LEN: usize = peios_uapi::RSI_STATUS_SIZE as usize;
pub const RSI_MIN_RESPONSE_LEN: usize = RSI_RESPONSE_HEADER_LEN + RSI_STATUS_LEN;

pub const RSI_OK: u32 = peios_uapi::RSI_OK;
pub const RSI_NOT_FOUND: u32 = peios_uapi::RSI_NOT_FOUND;
pub const RSI_ALREADY_EXISTS: u32 = peios_uapi::RSI_ALREADY_EXISTS;
pub const RSI_STORAGE_ERROR: u32 = peios_uapi::RSI_STORAGE_ERROR;
pub const RSI_NOT_EMPTY: u32 = peios_uapi::RSI_NOT_EMPTY;
pub const RSI_TOO_LARGE: u32 = peios_uapi::RSI_TOO_LARGE;
pub const RSI_TXN_BUSY: u32 = peios_uapi::RSI_TXN_BUSY;
pub const RSI_INVALID: u32 = peios_uapi::RSI_INVALID;
pub const RSI_CAS_FAILED: u32 = peios_uapi::RSI_CAS_FAILED;
pub const RSI_TXN_NOT_SUPPORTED: u32 = peios_uapi::RSI_TXN_NOT_SUPPORTED;

pub const RSI_TXN_READ_WRITE: u32 = peios_uapi::RSI_TXN_READ_WRITE;
pub const RSI_TXN_READ_ONLY: u32 = peios_uapi::RSI_TXN_READ_ONLY;
pub const RSI_HIVE_PRIVATE: u32 = peios_uapi::RSI_HIVE_PRIVATE;

pub const REG_BACKUP_HEADER: u8 = peios_uapi::REG_BACKUP_HEADER as u8;
pub const REG_BACKUP_LAYER: u8 = peios_uapi::REG_BACKUP_LAYER as u8;
pub const REG_BACKUP_KEY: u8 = peios_uapi::REG_BACKUP_KEY as u8;
pub const REG_BACKUP_PATH_ENTRY: u8 = peios_uapi::REG_BACKUP_PATH_ENTRY as u8;
pub const REG_BACKUP_VALUE: u8 = peios_uapi::REG_BACKUP_VALUE as u8;
pub const REG_BACKUP_BLANKET_TOMBSTONE: u8 = peios_uapi::REG_BACKUP_BLANKET_TOMBSTONE as u8;
pub const REG_BACKUP_TRAILER: u8 = peios_uapi::REG_BACKUP_TRAILER as u8;

pub const REG_BACKUP_MAGIC: [u8; 8] = *b"PEIOSREG";
pub const BASE_LAYER_NAME: &str = "base";
