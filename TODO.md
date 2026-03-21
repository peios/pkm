# PKM — Remaining TODO

Updated 2026-03-21. Only items NOT YET DONE.

---

## FACS — deferred items

- [ ] FILE_SUPERSEDE disposition in kacs_open (complex VFS integration —
  atomic unlink + create under inode_lock, deferred to post-v1)
- [ ] Synthesize mode for foreign mounts (per-mount policy for USB/FAT/NFS,
  deferred until foreign media mounting is needed)
- [ ] Kernel patch 15: execveat(AT_EMPTY_PATH) snapshot FILE_EXECUTE
  (currently uses live AccessCheck via kernel re-open — functionally
  correct, deferred handle-model purity refinement)

## Blocked on other subsystems

- [ ] NEW_PROCESS_MIN — needs executable integrity label from file SD
- [ ] Event crash recovery — flush ring buffer to file before reboot
- [ ] Event audit_required overflow — expand buffer, signal peinit
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
- [ ] Corrupt SD audit event payload format (TODO comment in code —
  refine when eventd is designed)
