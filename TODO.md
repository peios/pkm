# PKM — Remaining TODO (excluding FACS)

Updated 2026-03-21. Only items NOT YET DONE.

---

## FACS-dependent (blocked until file enforcement)

- [ ] NEW_PROCESS_MIN — needs executable's integrity label from file SD
- [ ] Event crash recovery — flush ring buffer to file before reboot
- [ ] Event audit_required overflow — expand buffer, signal peinit, switch policy
- [ ] kacs_open/get_sd/set_sd for files (syscalls 1020-1022)
- [ ] Inode SD caching from xattr
- [ ] Legacy open() compatibility mapping (core + compat rights)
- [ ] 16 kernel patches (do_dentry_open, current_fsuid, etc.)
- [ ] Derooting (current_fsuid patch, capability switchboard)
- [ ] Wire peios_event_emit_kernel into SACL audit results
- [ ] SeChangeNotifyPrivilege enforcement (traverse checking in path walks)
- [ ] unix_may_send hook (datagram socket gating — needs file SD)

## Deferred

- [ ] Per-CPU event buffers (no load to optimize for yet)
- [ ] /proc metadata hiding (non-trivial inode-to-task extraction)
- [ ] Per-token audit policy override bitmask (audit categories not designed)
- [ ] Windows cross-validation test corpus (needs Windows VM + generator script)
- [ ] Vec-as-Box allocation pattern (blocked on kernel Rust KBox stabilization)

## Polish (non-blocking)

- [ ] Remaining unreachable pub warnings on compat items (structural,
  can't fix without changing dual-target design)
