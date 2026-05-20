use crate::fd::KeyFdOrphanOperationErrno;
use crate::hives::HiveRouteErrno;
use crate::ioctl::RegistryIoctlFdAccessErrno;
use crate::key_path::KeyPathMutationErrno;
use crate::layers::{LayerCreationAdmissionErrno, LayerTargetAdmissionErrno};
use crate::open::RegistryOpenPreResolutionErrno;
use crate::output_buffer::OutputBufferAggregate;
use crate::rsi::{RsiMappedErrno, RsiRequestTimeoutErrno};
use crate::source::SourceRegistrationErrno;
use crate::symlink::SymlinkResolutionErrno;
use crate::transaction::{TransactionTerminalErrno, TransactionTimeoutErrno};
use crate::value::{ValueLayerAdmissionErrno, ValueTypeValidationErrno};

/// Linux errno values used by PSD-005 LCS syscall/ioctl contracts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinuxErrno {
    Eperm,
    Enoent,
    Eio,
    Ebadf,
    Eagain,
    Enomem,
    Eacces,
    Efault,
    Ebusy,
    Eexist,
    Exdev,
    Einval,
    Enospc,
    Erange,
    Enametoolong,
    Enotempty,
    Eloop,
    Emsgsize,
    Eoverflow,
    Enotsup,
    Etimedout,
    Estale,
}

impl LinuxErrno {
    /// Positive Linux errno value.
    pub const fn raw(self) -> i32 {
        match self {
            Self::Eperm => 1,
            Self::Enoent => 2,
            Self::Eio => 5,
            Self::Ebadf => 9,
            Self::Eagain => 11,
            Self::Enomem => 12,
            Self::Eacces => 13,
            Self::Efault => 14,
            Self::Ebusy => 16,
            Self::Eexist => 17,
            Self::Exdev => 18,
            Self::Einval => 22,
            Self::Enospc => 28,
            Self::Erange => 34,
            Self::Enametoolong => 36,
            Self::Enotempty => 39,
            Self::Eloop => 40,
            Self::Emsgsize => 90,
            Self::Eoverflow => 75,
            Self::Enotsup => 95,
            Self::Etimedout => 110,
            Self::Estale => 116,
        }
    }

    /// Kernel-style negative return value for paths that return `-errno`.
    pub const fn negated_return(self) -> i32 {
        -self.raw()
    }
}

impl From<RsiMappedErrno> for LinuxErrno {
    fn from(errno: RsiMappedErrno) -> Self {
        match errno {
            RsiMappedErrno::Enoent => Self::Enoent,
            RsiMappedErrno::Eexist => Self::Eexist,
            RsiMappedErrno::Eio => Self::Eio,
            RsiMappedErrno::Enotempty => Self::Enotempty,
            RsiMappedErrno::Enospc => Self::Enospc,
            RsiMappedErrno::Ebusy => Self::Ebusy,
            RsiMappedErrno::Einval => Self::Einval,
            RsiMappedErrno::Eagain => Self::Eagain,
            RsiMappedErrno::Enotsup => Self::Enotsup,
            RsiMappedErrno::Etimedout => Self::Etimedout,
            RsiMappedErrno::Exdev => Self::Exdev,
        }
    }
}

impl From<RsiRequestTimeoutErrno> for LinuxErrno {
    fn from(errno: RsiRequestTimeoutErrno) -> Self {
        match errno {
            RsiRequestTimeoutErrno::Etimedout => Self::Etimedout,
        }
    }
}

impl From<SourceRegistrationErrno> for LinuxErrno {
    fn from(errno: SourceRegistrationErrno) -> Self {
        match errno {
            SourceRegistrationErrno::Eperm => Self::Eperm,
            SourceRegistrationErrno::Eexist => Self::Eexist,
            SourceRegistrationErrno::Einval => Self::Einval,
            SourceRegistrationErrno::Enospc => Self::Enospc,
            SourceRegistrationErrno::Eoverflow => Self::Eoverflow,
            SourceRegistrationErrno::Estale => Self::Estale,
        }
    }
}

impl From<TransactionTimeoutErrno> for LinuxErrno {
    fn from(errno: TransactionTimeoutErrno) -> Self {
        match errno {
            TransactionTimeoutErrno::Etimedout => Self::Etimedout,
        }
    }
}

impl From<HiveRouteErrno> for LinuxErrno {
    fn from(errno: HiveRouteErrno) -> Self {
        match errno {
            HiveRouteErrno::Enoent => Self::Enoent,
            HiveRouteErrno::Eio => Self::Eio,
        }
    }
}

impl From<SymlinkResolutionErrno> for LinuxErrno {
    fn from(errno: SymlinkResolutionErrno) -> Self {
        match errno {
            SymlinkResolutionErrno::Einval => Self::Einval,
            SymlinkResolutionErrno::Eloop => Self::Eloop,
        }
    }
}

impl From<ValueTypeValidationErrno> for LinuxErrno {
    fn from(errno: ValueTypeValidationErrno) -> Self {
        match errno {
            ValueTypeValidationErrno::Einval => Self::Einval,
        }
    }
}

impl From<ValueLayerAdmissionErrno> for LinuxErrno {
    fn from(errno: ValueLayerAdmissionErrno) -> Self {
        match errno {
            ValueLayerAdmissionErrno::Enospc => Self::Enospc,
        }
    }
}

impl From<LayerCreationAdmissionErrno> for LinuxErrno {
    fn from(errno: LayerCreationAdmissionErrno) -> Self {
        match errno {
            LayerCreationAdmissionErrno::Enospc => Self::Enospc,
        }
    }
}

impl From<LayerTargetAdmissionErrno> for LinuxErrno {
    fn from(errno: LayerTargetAdmissionErrno) -> Self {
        match errno {
            LayerTargetAdmissionErrno::Enoent => Self::Enoent,
        }
    }
}

impl From<KeyPathMutationErrno> for LinuxErrno {
    fn from(errno: KeyPathMutationErrno) -> Self {
        match errno {
            KeyPathMutationErrno::Einval => Self::Einval,
            KeyPathMutationErrno::Enoent => Self::Enoent,
            KeyPathMutationErrno::Enotempty => Self::Enotempty,
        }
    }
}

impl From<KeyFdOrphanOperationErrno> for LinuxErrno {
    fn from(errno: KeyFdOrphanOperationErrno) -> Self {
        match errno {
            KeyFdOrphanOperationErrno::Enoent => Self::Enoent,
        }
    }
}

impl From<RegistryIoctlFdAccessErrno> for LinuxErrno {
    fn from(errno: RegistryIoctlFdAccessErrno) -> Self {
        match errno {
            RegistryIoctlFdAccessErrno::Eacces => Self::Eacces,
        }
    }
}

impl From<RegistryOpenPreResolutionErrno> for LinuxErrno {
    fn from(errno: RegistryOpenPreResolutionErrno) -> Self {
        match errno {
            RegistryOpenPreResolutionErrno::Einval => Self::Einval,
        }
    }
}

/// Projects `REG_IOC_TXN_STATUS.terminal_errno` to its ABI integer value.
pub fn transaction_terminal_errno_raw(errno: TransactionTerminalErrno) -> i32 {
    match errno {
        TransactionTerminalErrno::None => 0,
        TransactionTerminalErrno::Invalid => LinuxErrno::Einval.raw(),
        TransactionTerminalErrno::TimedOut => LinuxErrno::Etimedout.raw(),
        TransactionTerminalErrno::Io => LinuxErrno::Eio.raw(),
    }
}

/// Projects output-buffer aggregate state to the syscall/ioctl errno, if any.
pub fn output_buffer_aggregate_errno(aggregate: OutputBufferAggregate) -> Option<LinuxErrno> {
    match aggregate {
        OutputBufferAggregate::AllFit => None,
        OutputBufferAggregate::TooSmall => Some(LinuxErrno::Erange),
    }
}
