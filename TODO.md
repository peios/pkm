# PKM — Remaining TODO

Updated 2026-03-21. Only items NOT YET DONE.

---

## FACS — remaining implementation

- [ ] kacs_get_sd syscall (1021) — per-component SD read with
  READ_CONTROL/ACCESS_SYSTEM_SECURITY gating
- [ ] kacs_set_sd syscall (1022) — component merge, ownership
  constraints, SeRestorePrivilege bypass, xattr write, cache update
- [ ] kacs_open syscall (1020) — native open with explicit desired
  access mask, create dispositions, f_mode mapping
- [ ] Kernel patch 12: do_dentry_open integration for kacs_open
- [ ] Kernel patches 13-16: pidfd_getfd mode (done), current_fsuid
  projection, execveat AT_EMPTY_PATH FILE_EXECUTE, fchdir FILE_TRAVERSE
- [ ] Synthesize mode for foreign mounts (per-mount policy)
- [ ] Corrupt SD audit events
- [ ] Syscall registration in Dockerfile for 1020-1022

## FACS-dependent (blocked until above)

- [ ] NEW_PROCESS_MIN — needs executable's integrity label from file SD
- [ ] Event crash recovery — flush ring buffer to file before reboot
- [ ] Event audit_required overflow — expand buffer, signal peinit
- [ ] Inode SD caching from xattr — DONE (Phase A)
- [ ] Legacy open() compatibility mapping — DONE (Phase B)
- [ ] Derooting (current_fsuid patch, capability switchboard) — switchboard DONE, fsuid patch pending
- [ ] Wire peios_event_emit_kernel into SACL audit results
- [ ] SeChangeNotifyPrivilege enforcement — DONE (Phase E, inode_permission)
- [ ] unix_may_send hook (datagram socket gating — needs file SD on socket)

## Deferred

- [ ] Per-CPU event buffers (no load to optimize for yet)
- [ ] /proc metadata hiding (non-trivial inode-to-task extraction)
- [ ] Per-token audit policy override bitmask (audit categories not designed)
- [ ] Windows cross-validation test corpus (needs Windows VM)
- [ ] Vec-as-Box allocation pattern (blocked on kernel Rust KBox)

## Polish (non-blocking)

- [ ] Remaining unreachable pub warnings on compat items
