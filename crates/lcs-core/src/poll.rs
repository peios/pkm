/// Linux `POLLIN` from `include/uapi/asm-generic/poll.h`.
pub const LINUX_POLLIN: u16 = 0x0001;
/// Linux `POLLOUT` from `include/uapi/asm-generic/poll.h`.
pub const LINUX_POLLOUT: u16 = 0x0004;
/// Linux `POLLERR` from `include/uapi/asm-generic/poll.h`.
pub const LINUX_POLLERR: u16 = 0x0008;
/// Linux `POLLHUP` from `include/uapi/asm-generic/poll.h`.
pub const LINUX_POLLHUP: u16 = 0x0010;

/// Projects symbolic readiness bits to the Linux poll mask returned by fd poll hooks.
pub const fn linux_poll_mask_from_readiness(
    readable: bool,
    writable: bool,
    hangup: bool,
    error: bool,
) -> u16 {
    let mut mask = 0;
    if readable {
        mask |= LINUX_POLLIN;
    }
    if writable {
        mask |= LINUX_POLLOUT;
    }
    if error {
        mask |= LINUX_POLLERR;
    }
    if hangup {
        mask |= LINUX_POLLHUP;
    }
    mask
}
