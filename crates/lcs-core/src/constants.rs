//! PSD-005 registry constants used by the LCS semantic core.

/// `reg_open_key` syscall number.
pub const SYS_REG_OPEN_KEY: u32 = 1100;
/// `reg_create_key` syscall number.
pub const SYS_REG_CREATE_KEY: u32 = 1101;
/// `reg_begin_transaction` syscall number.
pub const SYS_REG_BEGIN_TRANSACTION: u32 = 1102;

/// Registry ioctl type byte.
pub const REG_IOC_TYPE: u8 = b'R';

pub const REG_SRC_REGISTER: u8 = 0;

pub const REG_IOC_QUERY_VALUE: u8 = 0;
pub const REG_IOC_SET_VALUE: u8 = 1;
pub const REG_IOC_DELETE_VALUE: u8 = 2;
pub const REG_IOC_BLANKET_TOMBSTONE: u8 = 3;
pub const REG_IOC_QUERY_VALUES_BATCH: u8 = 4;
pub const REG_IOC_ENUM_VALUES: u8 = 5;
pub const REG_IOC_ENUM_SUBKEYS: u8 = 6;
pub const REG_IOC_QUERY_KEY_INFO: u8 = 7;
pub const REG_IOC_DELETE_KEY: u8 = 8;
pub const REG_IOC_HIDE_KEY: u8 = 9;
pub const REG_IOC_GET_SECURITY: u8 = 10;
pub const REG_IOC_SET_SECURITY: u8 = 11;
pub const REG_IOC_NOTIFY: u8 = 12;
pub const REG_IOC_FLUSH: u8 = 13;
pub const REG_IOC_BACKUP: u8 = 14;
pub const REG_IOC_RESTORE: u8 = 15;
pub const REG_IOC_COMMIT: u8 = 16;
pub const REG_IOC_TXN_STATUS: u8 = 17;

pub const REG_TXN_ACTIVE_UNBOUND: u32 = 0;
pub const REG_TXN_ACTIVE_BOUND: u32 = 1;
pub const REG_TXN_COMMITTED: u32 = 2;
pub const REG_TXN_ABORTED: u32 = 3;
pub const REG_TXN_TIMED_OUT: u32 = 4;
pub const REG_TXN_SOURCE_DOWN: u32 = 5;

pub const REG_OPEN_LINK: u32 = 0x01;
pub const REG_OPTION_VOLATILE: u32 = 0x01;
pub const REG_OPTION_CREATE_LINK: u32 = 0x02;
pub const REG_CREATED_NEW: u32 = 1;
pub const REG_OPENED_EXISTING: u32 = 2;

pub const KEY_QUERY_VALUE: u32 = 0x0000_0001;
pub const KEY_SET_VALUE: u32 = 0x0000_0002;
pub const KEY_CREATE_SUB_KEY: u32 = 0x0000_0004;
pub const KEY_ENUMERATE_SUB_KEYS: u32 = 0x0000_0008;
pub const KEY_NOTIFY: u32 = 0x0000_0010;
pub const KEY_CREATE_LINK: u32 = 0x0000_0020;

pub const DELETE: u32 = 0x0001_0000;
pub const READ_CONTROL: u32 = 0x0002_0000;
pub const WRITE_DAC: u32 = 0x0004_0000;
pub const WRITE_OWNER: u32 = 0x0008_0000;
pub const SYNCHRONIZE: u32 = 0x0010_0000;
pub const ACCESS_SYSTEM_SECURITY: u32 = 0x0100_0000;
pub const MAXIMUM_ALLOWED: u32 = 0x0200_0000;

pub const GENERIC_ALL: u32 = 0x1000_0000;
pub const GENERIC_EXECUTE: u32 = 0x2000_0000;
pub const GENERIC_WRITE: u32 = 0x4000_0000;
pub const GENERIC_READ: u32 = 0x8000_0000;

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

pub const REG_VALID_DESIRED_ACCESS_MASK: u32 = 0xf30f_003f;
pub const REG_VALID_MAPPED_ACCESS_MASK: u32 = 0x010f_003f;
pub const REG_VALID_ACE_ACCESS_MASK: u32 = 0xf10f_003f;

pub const OWNER_SECURITY_INFORMATION: u32 = 0x0000_0001;
pub const GROUP_SECURITY_INFORMATION: u32 = 0x0000_0002;
pub const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
pub const SACL_SECURITY_INFORMATION: u32 = 0x0000_0008;
pub const REG_VALID_SECURITY_INFORMATION: u32 = OWNER_SECURITY_INFORMATION
    | GROUP_SECURITY_INFORMATION
    | DACL_SECURITY_INFORMATION
    | SACL_SECURITY_INFORMATION;

pub const REG_NONE: u32 = 0;
pub const REG_SZ: u32 = 1;
pub const REG_EXPAND_SZ: u32 = 2;
pub const REG_BINARY: u32 = 3;
pub const REG_DWORD: u32 = 4;
pub const REG_DWORD_BIG_ENDIAN: u32 = 5;
pub const REG_LINK: u32 = 6;
pub const REG_MULTI_SZ: u32 = 7;
pub const REG_RESOURCE_LIST: u32 = 8;
pub const REG_FULL_RESOURCE_DESCRIPTOR: u32 = 9;
pub const REG_RESOURCE_REQUIREMENTS_LIST: u32 = 10;
pub const REG_QWORD: u32 = 11;
pub const REG_TOMBSTONE: u32 = 0xffff;

pub const REG_WATCH_VALUE_SET: u32 = 1;
pub const REG_WATCH_VALUE_DELETED: u32 = 2;
pub const REG_WATCH_SUBKEY_CREATED: u32 = 3;
pub const REG_WATCH_SUBKEY_DELETED: u32 = 4;
pub const REG_WATCH_SD_CHANGED: u32 = 5;
pub const REG_WATCH_KEY_DELETED: u32 = 6;
pub const REG_WATCH_OVERFLOW: u32 = 7;

pub const REG_NOTIFY_VALUE: u32 = 0x01;
pub const REG_NOTIFY_SUBKEY: u32 = 0x02;
pub const REG_NOTIFY_SD: u32 = 0x04;
pub const REG_NOTIFY_ALL: u32 = 0x07;

pub const RSI_LOOKUP: u16 = 0x01;
pub const RSI_CREATE_ENTRY: u16 = 0x02;
pub const RSI_HIDE_ENTRY: u16 = 0x03;
pub const RSI_DELETE_ENTRY: u16 = 0x04;
pub const RSI_ENUM_CHILDREN: u16 = 0x05;
pub const RSI_CREATE_KEY: u16 = 0x10;
pub const RSI_READ_KEY: u16 = 0x11;
pub const RSI_WRITE_KEY: u16 = 0x12;
pub const RSI_DROP_KEY: u16 = 0x13;
pub const RSI_QUERY_VALUES: u16 = 0x20;
pub const RSI_SET_VALUE: u16 = 0x21;
pub const RSI_DELETE_VALUE_ENTRY: u16 = 0x22;
pub const RSI_SET_BLANKET_TOMBSTONE: u16 = 0x23;
pub const RSI_BEGIN_TRANSACTION: u16 = 0x30;
pub const RSI_COMMIT_TRANSACTION: u16 = 0x31;
pub const RSI_ABORT_TRANSACTION: u16 = 0x32;
pub const RSI_FLUSH: u16 = 0x40;
pub const RSI_DELETE_LAYER: u16 = 0x50;

pub const RSI_RESPONSE_BIT: u16 = 0x8000;

pub const RSI_OK: u32 = 0;
pub const RSI_NOT_FOUND: u32 = 1;
pub const RSI_ALREADY_EXISTS: u32 = 2;
pub const RSI_STORAGE_ERROR: u32 = 3;
pub const RSI_NOT_EMPTY: u32 = 4;
pub const RSI_TOO_LARGE: u32 = 5;
pub const RSI_TXN_BUSY: u32 = 6;
pub const RSI_INVALID: u32 = 7;
pub const RSI_CAS_FAILED: u32 = 8;
pub const RSI_TXN_NOT_SUPPORTED: u32 = 9;

pub const RSI_TXN_READ_WRITE: u32 = 0;
pub const RSI_TXN_READ_ONLY: u32 = 1;
pub const RSI_HIVE_PRIVATE: u32 = 0x01;

pub const REG_BACKUP_HEADER: u8 = 0x01;
pub const REG_BACKUP_LAYER: u8 = 0x02;
pub const REG_BACKUP_KEY: u8 = 0x03;
pub const REG_BACKUP_PATH_ENTRY: u8 = 0x04;
pub const REG_BACKUP_VALUE: u8 = 0x05;
pub const REG_BACKUP_BLANKET_TOMBSTONE: u8 = 0x06;
pub const REG_BACKUP_TRAILER: u8 = 0xff;

pub const REG_BACKUP_MAGIC: [u8; 8] = *b"PEIOSREG";
pub const BASE_LAYER_NAME: &str = "base";
