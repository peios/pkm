// KACS process-object, PIP, and process-security-boundary ABI constants.

// ---------------------------------------------------------------------------
// kacs_set_psb mitigation bits (syscall 1005).
// ---------------------------------------------------------------------------

pub const KACS_MIT_WXP: u32 = 0x001;
pub const KACS_MIT_TLP: u32 = 0x002;
pub const KACS_MIT_LSV: u32 = 0x004;
pub const KACS_MIT_CFI: u32 = 0x008;
pub const KACS_MIT_UI_ACCESS: u32 = 0x010;
pub const KACS_MIT_NO_CHILD: u32 = 0x020;
pub const KACS_MIT_CFIF: u32 = 0x040;
pub const KACS_MIT_CFIB: u32 = 0x080;
pub const KACS_MIT_PIE: u32 = 0x100;
pub const KACS_MIT_SML: u32 = 0x200;
pub const KACS_MIT_ALL: u32 = 0x3FF;

// ---------------------------------------------------------------------------
// PIP type axis constants.
// ---------------------------------------------------------------------------

pub const PIP_TYPE_NONE: u32 = 0;
pub const PIP_TYPE_PROTECTED: u32 = 512;
pub const PIP_TYPE_ISOLATED: u32 = 1024;

// ---------------------------------------------------------------------------
// Process access rights.
// ---------------------------------------------------------------------------

pub const PROCESS_TERMINATE: u32 = 0x0000_0001;
pub const PROCESS_SIGNAL: u32 = 0x0000_0002;
pub const PROCESS_VM_READ: u32 = 0x0000_0010;
pub const PROCESS_VM_WRITE: u32 = 0x0000_0020;
pub const PROCESS_DUP_HANDLE: u32 = 0x0000_0040;
pub const PROCESS_SET_INFORMATION: u32 = 0x0000_0200;
pub const PROCESS_QUERY_INFORMATION: u32 = 0x0000_0400;
pub const PROCESS_SUSPEND_RESUME: u32 = 0x0000_0800;
pub const PROCESS_QUERY_LIMITED: u32 = 0x0000_1000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mitigation_bits_match_psd_004() {
        assert_eq!(KACS_MIT_WXP, 0x001);
        assert_eq!(KACS_MIT_TLP, 0x002);
        assert_eq!(KACS_MIT_LSV, 0x004);
        assert_eq!(KACS_MIT_CFI, 0x008);
        assert_eq!(KACS_MIT_UI_ACCESS, 0x010);
        assert_eq!(KACS_MIT_NO_CHILD, 0x020);
        assert_eq!(KACS_MIT_CFIF, 0x040);
        assert_eq!(KACS_MIT_CFIB, 0x080);
        assert_eq!(KACS_MIT_PIE, 0x100);
        assert_eq!(KACS_MIT_SML, 0x200);
        assert_eq!(
            KACS_MIT_ALL,
            KACS_MIT_WXP
                | KACS_MIT_TLP
                | KACS_MIT_LSV
                | KACS_MIT_CFI
                | KACS_MIT_UI_ACCESS
                | KACS_MIT_NO_CHILD
                | KACS_MIT_CFIF
                | KACS_MIT_CFIB
                | KACS_MIT_PIE
                | KACS_MIT_SML
        );
    }

    #[test]
    fn pip_type_constants_match_psd_004() {
        assert_eq!(PIP_TYPE_NONE, 0);
        assert_eq!(PIP_TYPE_PROTECTED, 512);
        assert_eq!(PIP_TYPE_ISOLATED, 1024);
    }

    #[test]
    fn process_rights_match_psd_004() {
        assert_eq!(PROCESS_TERMINATE, 0x0001);
        assert_eq!(PROCESS_SIGNAL, 0x0002);
        assert_eq!(PROCESS_VM_READ, 0x0010);
        assert_eq!(PROCESS_VM_WRITE, 0x0020);
        assert_eq!(PROCESS_DUP_HANDLE, 0x0040);
        assert_eq!(PROCESS_SET_INFORMATION, 0x0200);
        assert_eq!(PROCESS_QUERY_INFORMATION, 0x0400);
        assert_eq!(PROCESS_SUSPEND_RESUME, 0x0800);
        assert_eq!(PROCESS_QUERY_LIMITED, 0x1000);
    }
}
