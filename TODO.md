# PKM — Remaining TODO (excluding FACS)

Updated 2026-03-21. Items marked [DONE] were completed this session.

---

## §7 Tokens

### Token fields
- [x] `default_dacl: Option<Acl>` — added to Token struct
- [x] `security_descriptor: Option<SecurityDescriptor>` — added, auto-generated at creation

### Token SD enforcement
- [x] kacs_open_self_token: AccessCheck on token's own SD
- [x] kacs_open_process_token: AccessCheck on target token's SD
- [x] kacs_open_peer_token: AccessCheck on peer token's SD
- [x] Auto-generate token SD at creation (user + Admins + SYSTEM)

### Token lifecycle
- [x] `auth_id` set from session_id
- [x] `modified_id` bumped on ADJUST_PRIVS and ADJUST_GROUPS
- [ ] NEW_PROCESS_MIN: replace child token at exec if integrity
  mismatch (§7.4). **Requires design work.**
- [x] bprm_creds_for_exec: revert impersonation + reassert DAC caps

### Token creation
- [ ] Wire format v2: default_dacl, restricted_sids, device_groups,
  confinement_sid, confinement_capabilities, token_source.
  **Additive — v1 works, v2 adds optional sections.**
- [x] Token spec max size bumped to 64KB (3000+ groups)
- [x] Logon SID injected into groups with SE_GROUP_LOGON_ID

### Ioctls
- [x] KACS_IOC_ADJUST_GROUPS implemented
- [x] All 19 QUERY classes implemented (binary format)
- [ ] ADJUST_PRIVS wire format: bitmask vs array-of-pairs.
  **Decision needed — current bitmask API is functionally equivalent.**

---

## §8 Process Security Block

### Hooks
- [x] task_setnice, task_setscheduler, task_setioprio — PROCESS_SET_INFORMATION
- [x] task_prlimit (stub — lacks task_struct for full PIP check)

### PSB modification
- [ ] No mechanism to set PIP type/trust after creation. **Requires
  design work** — syscall on pidfd? Token field? New ioctl?

### INSTALL
- [x] Process SD regenerated when user SID changes

---

## §12 Impersonation

- [x] Restricted token divergence check (both impersonation paths)

---

## §13 PIP

- [ ] /proc metadata hiding via inode_permission — **deferred v2**.
  Documented rationale: extracting target task from procfs inode is
  non-trivial. Existing ptrace + token hooks cover sensitive entries.
- [x] pidfd_getfd: kernel patch 13 (PTRACE_MODE_GETFD) written.
  ptrace_access_check maps GETFD → PROCESS_DUP_HANDLE.
- [x] /proc/<pid>/token access gated (SD + PIP, self always allowed)
- [x] CONFIG_STRICT_DEVMEM=y in kernel config

---

## §15 Kernel Interface

- [x] kacs_access_check: full 80-byte versioned struct with self_sid,
  privilege_intent, granted_out. Object tree + local claims accepted
  but not yet passed through (v2 placeholder fields).
- [ ] kacs_get_sd / kacs_set_sd for pidfds and token fds (non-FACS
  paths). **Medium — dispatch by fd type, read/write process/token SD.**
- [x] Boot: DAC bypass caps asserted on init_cred
- [x] LSM stack verification documented (Kconfig enforcement)

---

## §10 Privileges

- [x] Atomic ordering: SeqCst on all privilege operations

---

## §17 Audit Pipeline

- [x] mmap support for zero-copy eventd drain
- [x] eventfd registration (write fd to securityfs)
- [x] Namespace reservation (reject kacs.*/kernel.* from userspace)
- [x] emitter_uid reads current_fsuid()
- [ ] audit_required overflow policy. **Requires design work** —
  pre-allocated overflow, signal peinit, switch to best_effort.
- [ ] Crash recovery (§17.4). **Requires design work** — flush to
  file, peinit AuditDrain boot mode detection.
- [ ] Per-CPU buffers. **Optimization** — single spinlock is fine for
  v1, per-CPU needed at enterprise audit rates.

### Kernel event emission
- [ ] peios_event_emit_kernel never called. Wire into: SACL audit,
  privilege use, token ops, impersonation, session create.
  **Medium — mechanical, just add calls at the right hook points.**

---

## Sessions

- [x] Logon SID injected into token groups
- [x] LINK_TOKENS verifies both tokens belong to same session
- [ ] Session cleanup/refcounting. **Requires design work** — lock on
  every token drop is a performance concern.

---

## kacs-core (deferred)

- [ ] PIP caller parameters in access_check()
- [ ] InheritedObjectType GUID filtering in SD inheritance
- [ ] CAP staged DACL comparison (audit-only)
- [ ] Per-token audit policy override bitmask
- [ ] Resource attribute parsing from SYSTEM_RESOURCE_ATTRIBUTE_ACE
- [ ] Windows cross-validation test corpus

---

## Code quality

- [x] 2 missing privilege tests restored (389 total)
- [ ] Session table: O(n) lookup. **Optimization** for enterprise.
- [ ] Linked tokens: O(n) scan. Same.
- [x] FormatBuf: replaced with dynamic compat::Vec<u8>
- [ ] kacs_token_set_impersonation_level: unsafe mutable cast.
  Safe in practice but technically UB.
- [ ] Vec-as-Box allocation pattern. Fragile but functional.
- [x] Build warnings: unused imports, prototypes, dead code fixed
- [ ] Remaining warnings: compat unreachable pub (structural),
  duplicate no_std attr, one unused assignment

---

## Summary

**Done this session:** ~45 items
**Remaining (requires design work):** 6 items
**Remaining (medium implementation):** 3 items (get_sd/set_sd for pidfds, kernel event emission wiring, session table indexing)
**Remaining (optimization):** 3 items (per-CPU buffers, session O(n), linked O(n))
**Remaining (deferred/post-v1):** 6 kacs-core items, wire format v2
**FACS:** excluded — the entire file enforcement surface
