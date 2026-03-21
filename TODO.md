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

## Deferred to v2

- [ ] Per-CPU event buffers (scalability for high audit load)
- [ ] /proc metadata hiding via security_inode_permission (non-trivial
  inode-to-task extraction from procfs internals)
- [ ] InheritedObjectType GUID filtering in SD inheritance
- [ ] CAP staged DACL comparison (audit-only)
- [ ] Per-token audit policy override bitmask
- [ ] Resource attribute parsing from SYSTEM_RESOURCE_ATTRIBUTE_ACE
- [ ] Windows cross-validation test corpus
- [ ] Token spec v2 wire format (default_dacl, restricted_sids,
  device_groups, confinement fields, full token_source)

## Polish (non-blocking)

- [ ] ADJUST_PRIVS wire format: proposal says array-of-pairs, we use
  bitmasks. Functionally equivalent. Decide if worth changing.
- [ ] kacs_token_set_impersonation_level: unsafe mutable cast on
  pre-sharing clones. Safe in practice but technically UB.
- [ ] Vec-as-Box allocation pattern — fragile. Use proper KBox when
  kernel Rust stabilizes it.
- [ ] Remaining unreachable pub warnings on compat items (structural,
  can't fix without changing dual-target design)
- [ ] kacs_access_check test: needs multi-buffer syscall_buf to test
  positive case with new 4-arg struct
