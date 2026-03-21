# PKM — Remaining TODO

Updated 2026-03-21. Only items NOT YET DONE.

---

## FACS — remaining

- [ ] Kernel patches 13-16: current_fsuid projection (derooting),
  execveat AT_EMPTY_PATH FILE_EXECUTE (patch 15), fchdir
  FILE_TRAVERSE (patch 16). Patch 13 (pidfd_getfd) already done.
- [ ] FILE_SUPERSEDE disposition in kacs_open — requires atomic
  unlink + create under inode_lock (complex VFS integration)
- [ ] Synthesize mode for foreign mounts (per-mount policy)
- [ ] Corrupt SD audit event emission
- [ ] O_PATH edge case refinements (fchdir live check)
- [ ] kacs_open with creator-supplied SD (sd_buf parameter)
- [ ] Ownership constraints in kacs_set_sd (SE_GROUP_OWNER check)

## Blocked on FACS completion

- [ ] NEW_PROCESS_MIN — needs executable integrity label from file SD
- [ ] Event crash recovery — flush ring buffer to file before reboot
- [ ] Event audit_required overflow — expand buffer, signal peinit
- [ ] Derooting — current_fsuid projection patch
- [ ] Wire peios_event_emit_kernel into SACL audit results
- [ ] unix_may_send hook (datagram socket — needs file SD on socket)

## Deferred

- [ ] Per-CPU event buffers (no load to optimize for)
- [ ] /proc metadata hiding (non-trivial inode-to-task extraction)
- [ ] Per-token audit policy override bitmask (audit categories not designed)
- [ ] Windows cross-validation test corpus (needs Windows VM)
- [ ] Vec-as-Box allocation pattern (blocked on kernel Rust KBox)
- [ ] RENAME_WHITEOUT FILE_ADD_FILE check (needs flags in LSM hook)

## Polish (non-blocking)

- [ ] Remaining unreachable pub warnings on compat items
