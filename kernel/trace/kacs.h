/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * KACS static tracepoints.
 *
 * Staged by stage-sources.sh into include/trace/events/kacs.h — the canonical
 * location, so <trace/events/kacs.h> resolves with no TRACE_INCLUDE_PATH
 * override and this file's events land in the `kacs:` trace system (enable the
 * whole subsystem with `echo 1 > tracefs/events/kacs/enable`).
 *
 * Replaces the old kacs.trace=1 pr_info diagnostic. To reproduce that boot
 * firehose without userspace: `trace_event=kacs:* tp_printk` on the cmdline.
 *
 * Invariant: never records a pathname. Only inode number, superblock magic,
 * resolved mount policy, the desired-access mask, the reason code, and ret —
 * exactly the pathname-free identity set the old diagnostic used.
 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM kacs

#if !defined(_TRACE_KACS_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_KACS_H

#include <linux/tracepoint.h>
#include <linux/types.h>
#include <pkm/trace.h>

struct inode;
struct super_block;
/* Resolved in the CREATE_TRACE_POINTS TU (pkm_trace.c), which includes
 * kacs/mount_policy.h; declared here so the event probe compiles. */
u32 pkm_kacs_superblock_mount_policy(const struct super_block *sb);

#define kacs_trace_reason_symbols					\
	{ KACS_TR_DECISION,			"decision" },		\
	{ KACS_TR_BAD_ARGS,			"bad-args" },		\
	{ KACS_TR_NO_ISEC,			"no-i_security" },	\
	{ KACS_TR_UNMANAGED,			"unmanaged" },		\
	{ KACS_TR_PIP_CONTEXT,			"pip-context" },	\
	{ KACS_TR_NO_TOKEN,			"no-token" },		\
	{ KACS_TR_NO_DENTRY_ALIAS,		"no-dentry-alias" },	\
	{ KACS_TR_DELETE_ON_CLOSE_PENDING,	"delete-on-close-pending" }, \
	{ KACS_TR_NATIVE_STAMP,			"native-stamp" },	\
	{ KACS_TR_NATIVE_ARM,			"native-arm" },		\
	{ KACS_TR_STAMP,			"stamp" },		\
	{ KACS_TR_LAZY_DENTRY_RELOOKUP,		"lazy-dentry-relookup" }, \
	{ KACS_TR_NEGATIVE_AFTER_CREATE,	"negative-after-create" }, \
	{ KACS_TR_CHANGE_NOTIFY_PRIV,		"change-notify-priv" },	\
	{ KACS_TR_CHANGE_NOTIFY_PRIV_EXHAUSTED,	"change-notify-priv-exhausted" }

/*
 * One access decision. `inode` may be NULL (a bad-args path); the inode/sb
 * fields then read as zero. `ret` is the outcome (0 == allow, negative errno
 * == deny). Filter denials with `ret != 0`.
 */
DECLARE_EVENT_CLASS(kacs_access_decision,

	TP_PROTO(const struct inode *inode, u32 access, long ret, u8 reason),

	TP_ARGS(inode, access, ret, reason),

	TP_STRUCT__entry(
		__field(	unsigned long,	ino		)
		__field(	unsigned long,	sb_magic	)
		__field(	unsigned int,	mount_policy	)
		__field(	u32,		access		)
		__field(	long,		ret		)
		__field(	u8,		reason		)
	),

	TP_fast_assign(
		__entry->ino = inode ? inode->i_ino : 0;
		__entry->sb_magic = (inode && inode->i_sb) ?
			(unsigned long)inode->i_sb->s_magic : 0;
		__entry->mount_policy = (inode && inode->i_sb) ?
			pkm_kacs_superblock_mount_policy(inode->i_sb) : 0;
		__entry->access = access;
		__entry->ret = ret;
		__entry->reason = reason;
	),

	TP_printk("reason=%s verdict=%s ino=%lu sb_magic=0x%lx policy=%u access=0x%x ret=%ld",
		__print_symbolic(__entry->reason, kacs_trace_reason_symbols),
		__entry->ret ? "deny" : "allow",
		__entry->ino, __entry->sb_magic, __entry->mount_policy,
		__entry->access, __entry->ret)
);

/* live_file_access core (file_access.c) */
DEFINE_EVENT(kacs_access_decision, kacs_file_access,
	TP_PROTO(const struct inode *inode, u32 access, long ret, u8 reason),
	TP_ARGS(inode, access, ret, reason));

/* file_open hook stamp path (file_access.c) */
DEFINE_EVENT(kacs_access_decision, kacs_file_open,
	TP_PROTO(const struct inode *inode, u32 access, long ret, u8 reason),
	TP_ARGS(inode, access, ret, reason));

/* native (kacs_open) create path (native_open.c) */
DEFINE_EVENT(kacs_access_decision, kacs_native_open,
	TP_PROTO(const struct inode *inode, u32 access, long ret, u8 reason),
	TP_ARGS(inode, access, ret, reason));

/* inode_file_access authorize (namespace.c) */
DEFINE_EVENT(kacs_access_decision, kacs_inode_file_access,
	TP_PROTO(const struct inode *inode, u32 access, long ret, u8 reason),
	TP_ARGS(inode, access, ret, reason));

/* inode_permission hook (namespace.c) */
DEFINE_EVENT(kacs_access_decision, kacs_inode_permission,
	TP_PROTO(const struct inode *inode, u32 access, long ret, u8 reason),
	TP_ARGS(inode, access, ret, reason));

#define kacs_sd_cache_reason_symbols					\
	{ KACS_SDC_HIT,				"hit" },		\
	{ KACS_SDC_MISS_NONE,			"miss-none" },		\
	{ KACS_SDC_MISS_STALE_GEN,		"miss-stale-gen" },	\
	{ KACS_SDC_MISS_NEEDS_SYNTH,		"miss-needs-synth" },	\
	{ KACS_SDC_CORRUPT_EMPTY_OR_OVERSIZE,	"corrupt-empty-or-oversize" }, \
	{ KACS_SDC_CORRUPT_VALIDATE_FAIL,	"corrupt-validate-fail" }

/*
 * Inode SD-cache outcome. `aux` carries reason-specific context (the stored SD
 * length for the corrupt paths; unused/0 for lookups). No pathname.
 */
DECLARE_EVENT_CLASS(kacs_sd_cache,

	TP_PROTO(const struct inode *inode, u8 reason, u32 aux),

	TP_ARGS(inode, reason, aux),

	TP_STRUCT__entry(
		__field(	unsigned long,	ino		)
		__field(	unsigned long,	sb_magic	)
		__field(	u32,		aux		)
		__field(	u8,		reason		)
	),

	TP_fast_assign(
		__entry->ino = inode ? inode->i_ino : 0;
		__entry->sb_magic = (inode && inode->i_sb) ?
			(unsigned long)inode->i_sb->s_magic : 0;
		__entry->aux = aux;
		__entry->reason = reason;
	),

	TP_printk("reason=%s ino=%lu sb_magic=0x%lx aux=%u",
		__print_symbolic(__entry->reason, kacs_sd_cache_reason_symbols),
		__entry->ino, __entry->sb_magic, __entry->aux)
);

/* SD-cache lookup outcome — the hit/miss taxonomy (file_sd_cache.c) */
DEFINE_EVENT(kacs_sd_cache, kacs_sd_cache_lookup,
	TP_PROTO(const struct inode *inode, u8 reason, u32 aux),
	TP_ARGS(inode, reason, aux));

/* Corrupt stored SD detected — aux is the offending length (file_sd_cache.c) */
DEFINE_EVENT(kacs_sd_cache, kacs_sd_cache_corrupt,
	TP_PROTO(const struct inode *inode, u8 reason, u32 aux),
	TP_ARGS(inode, reason, aux));

#define kacs_process_access_reason_symbols				\
	{ KACS_PA_ALLOW,		"allow" },			\
	{ KACS_PA_BAD_ARGS,		"bad-args" },			\
	{ KACS_PA_NO_TARGET,		"no-target" },			\
	{ KACS_PA_NO_SD,		"no-sd" },			\
	{ KACS_PA_SD_ERROR,		"sd-error" },			\
	{ KACS_PA_PIP_DENIED,		"pip-denied" },			\
	{ KACS_PA_DEBUG_RESCUE,		"debug-rescue" },		\
	{ KACS_PA_DEBUG_DENIED,		"debug-denied" },		\
	{ KACS_PA_PIP_DOMINANCE,	"pip-dominance" }

/*
 * A cross-process access decision (signal / ptrace / scheduler / prlimit).
 * Target PIP fields are 0 when unknown at the emit site (the SD-check inner
 * path). `reason` names which of the several -EACCES paths was taken.
 */
DECLARE_EVENT_CLASS(kacs_process_access,

	TP_PROTO(u32 caller_pip_type, u32 caller_pip_trust, u32 target_pip_type,
		 u32 target_pip_trust, u32 desired_access, u8 reason, long ret),

	TP_ARGS(caller_pip_type, caller_pip_trust, target_pip_type,
		target_pip_trust, desired_access, reason, ret),

	TP_STRUCT__entry(
		__field(	u32,	caller_pip_type		)
		__field(	u32,	caller_pip_trust	)
		__field(	u32,	target_pip_type		)
		__field(	u32,	target_pip_trust	)
		__field(	u32,	desired_access		)
		__field(	long,	ret			)
		__field(	u8,	reason			)
	),

	TP_fast_assign(
		__entry->caller_pip_type = caller_pip_type;
		__entry->caller_pip_trust = caller_pip_trust;
		__entry->target_pip_type = target_pip_type;
		__entry->target_pip_trust = target_pip_trust;
		__entry->desired_access = desired_access;
		__entry->ret = ret;
		__entry->reason = reason;
	),

	TP_printk("reason=%s verdict=%s desired=0x%x caller_pip=%u:%u target_pip=%u:%u ret=%ld",
		__print_symbolic(__entry->reason,
				 kacs_process_access_reason_symbols),
		__entry->ret ? "deny" : "allow",
		__entry->desired_access,
		__entry->caller_pip_type, __entry->caller_pip_trust,
		__entry->target_pip_type, __entry->target_pip_trust,
		__entry->ret)
);

/* Cross-process access verdict (process_access.c) */
DEFINE_EVENT(kacs_process_access, kacs_process_access,
	TP_PROTO(u32 caller_pip_type, u32 caller_pip_trust, u32 target_pip_type,
		 u32 target_pip_trust, u32 desired_access, u8 reason, long ret),
	TP_ARGS(caller_pip_type, caller_pip_trust, target_pip_type,
		target_pip_trust, desired_access, reason, ret));

#define kacs_exec_reason_symbols					\
	{ KACS_EXEC_CREDS_ALLOW,		"creds-allow" },	\
	{ KACS_EXEC_BAD_ARGS,			"bad-args" },		\
	{ KACS_EXEC_ID_CHANGE_NO_TOKEN,		"id-change-no-token" },	\
	{ KACS_EXEC_ID_CHANGE_PRIV_UNSUPPORTED,	"id-change-priv-unsupported" }, \
	{ KACS_EXEC_TOKEN_NPM_DERIVED,		"token-npm-derived" },	\
	{ KACS_EXEC_TOKEN_CLONE,		"token-clone" },	\
	{ KACS_EXEC_NPM_NO_FILE,		"npm-no-file" },	\
	{ KACS_EXEC_NPM_DERIVE_FAIL,		"npm-derive-fail" },	\
	{ KACS_EXEC_TOKEN_INSTALL_FAIL,		"token-install-fail" },	\
	{ KACS_EXEC_TOKEN_CLONE_FAIL,		"token-clone-fail" },	\
	{ KACS_EXEC_INTEGRITY_NO_ISEC,		"integrity-no-i_security" }, \
	{ KACS_EXEC_INTEGRITY_NO_CACHE,		"integrity-no-cache" },	\
	{ KACS_EXEC_INTEGRITY_INVALID_SD,	"integrity-invalid-sd" }, \
	{ KACS_EXEC_IMPERSONATION_REVERT_FAIL,	"impersonation-revert-fail" }, \
	{ KACS_EXEC_PIP_COMMITTED,		"pip-committed" },	\
	{ KACS_EXEC_UMH_NOT_TCB,		"umh-not-tcb" },	\
	{ KACS_EXEC_SIGNATURE_UNVERIFIABLE,	"signature-unverifiable" }, \
	{ KACS_EXEC_PIP_CAPPED_UNSAFE,		"pip-capped-unsafe" }

/*
 * An exec/bprm credential or PIP transition. exec_pip fields are 0 when unknown
 * at the emit site. `reason` names the transition; `ret` is the outcome. No
 * pathname, no SD bytes.
 */
DECLARE_EVENT_CLASS(kacs_exec,

	TP_PROTO(bool uid_changed, bool gid_changed, u32 exec_pip_type,
		 u32 exec_pip_trust, u8 reason, long ret),

	TP_ARGS(uid_changed, gid_changed, exec_pip_type, exec_pip_trust,
		reason, ret),

	TP_STRUCT__entry(
		__field(	u32,	exec_pip_type	)
		__field(	u32,	exec_pip_trust	)
		__field(	long,	ret		)
		__field(	u8,	reason		)
		__field(	u8,	uid_changed	)
		__field(	u8,	gid_changed	)
	),

	TP_fast_assign(
		__entry->exec_pip_type = exec_pip_type;
		__entry->exec_pip_trust = exec_pip_trust;
		__entry->ret = ret;
		__entry->reason = reason;
		__entry->uid_changed = uid_changed;
		__entry->gid_changed = gid_changed;
	),

	TP_printk("reason=%s verdict=%s uid_changed=%d gid_changed=%d exec_pip=%u:%u ret=%ld",
		__print_symbolic(__entry->reason, kacs_exec_reason_symbols),
		__entry->ret ? "deny" : "allow",
		__entry->uid_changed, __entry->gid_changed,
		__entry->exec_pip_type, __entry->exec_pip_trust,
		__entry->ret)
);

/* exec/bprm credential and PIP transitions (exec.c) */
DEFINE_EVENT(kacs_exec, kacs_exec,
	TP_PROTO(bool uid_changed, bool gid_changed, u32 exec_pip_type,
		 u32 exec_pip_trust, u8 reason, long ret),
	TP_ARGS(uid_changed, gid_changed, exec_pip_type, exec_pip_trust,
		reason, ret));

#define kacs_signing_reason_symbols					\
	{ KACS_SIG_UNSIGNED,			"unsigned" },		\
	{ KACS_SIG_BAD_KEY_TABLE,		"bad-key-table" },	\
	{ KACS_SIG_NO_KEY_MATCH,		"no-key-match" },	\
	{ KACS_SIG_VERIFIED,			"verified" },		\
	{ KACS_SIG_CRYPTO_UNAVAILABLE,		"crypto-unavailable" },	\
	{ KACS_SIG_CRYPTO_MISMATCH,		"crypto-mismatch" }

/*
 * A code-signature verification outcome. `source` is 0 at the crypto-primitive
 * emit site. `verified` and pip_type/pip_trust carry the trust tier on success.
 * No key or signature bytes are recorded.
 */
DECLARE_EVENT_CLASS(kacs_signing,

	TP_PROTO(u32 source, u32 verified, u32 pip_type, u32 pip_trust,
		 u8 reason, long ret),

	TP_ARGS(source, verified, pip_type, pip_trust, reason, ret),

	TP_STRUCT__entry(
		__field(	u32,	source		)
		__field(	u32,	verified	)
		__field(	u32,	pip_type	)
		__field(	u32,	pip_trust	)
		__field(	long,	ret		)
		__field(	u8,	reason		)
	),

	TP_fast_assign(
		__entry->source = source;
		__entry->verified = verified;
		__entry->pip_type = pip_type;
		__entry->pip_trust = pip_trust;
		__entry->ret = ret;
		__entry->reason = reason;
	),

	TP_printk("reason=%s source=%u verified=%u pip=%u:%u ret=%ld",
		__print_symbolic(__entry->reason, kacs_signing_reason_symbols),
		__entry->source, __entry->verified,
		__entry->pip_type, __entry->pip_trust, __entry->ret)
);

/* Signature verification against the key table (signing.c) */
DEFINE_EVENT(kacs_signing, kacs_signing_verify,
	TP_PROTO(u32 source, u32 verified, u32 pip_type, u32 pip_trust,
		 u8 reason, long ret),
	TP_ARGS(source, verified, pip_type, pip_trust, reason, ret));

/* ML-DSA-65 crypto primitive outcome — unavailable vs mismatch (signing.c) */
DEFINE_EVENT(kacs_signing, kacs_signing_crypto,
	TP_PROTO(u32 source, u32 verified, u32 pip_type, u32 pip_trust,
		 u8 reason, long ret),
	TP_ARGS(source, verified, pip_type, pip_trust, reason, ret));

#define kacs_signing_probe_reason_symbols				\
	{ KACS_SIG_PROBE_FOUND,			"found" },		\
	{ KACS_SIG_ELF_MAGIC_READ,		"elf-magic-read" },	\
	{ KACS_SIG_ELF_SHORT_EHDR,		"elf-short-ehdr" },	\
	{ KACS_SIG_ELF_EHDR_READ,		"elf-ehdr-read" },	\
	{ KACS_SIG_ELF_BAD_IDENT,		"elf-bad-ident" },	\
	{ KACS_SIG_ELF_BAD_SHTABLE,		"elf-bad-shtable" },	\
	{ KACS_SIG_ELF_SHDRS_RANGE,		"elf-shdrs-range" },	\
	{ KACS_SIG_ELF_SHSTR_READ,		"elf-shstr-read" },	\
	{ KACS_SIG_ELF_STRTAB_RANGE,		"elf-strtab-range" },	\
	{ KACS_SIG_ELF_SHDR_READ,		"elf-shdr-read" },	\
	{ KACS_SIG_ELF_NAME_READ,		"elf-name-read" },	\
	{ KACS_SIG_ELF_BAD_SIG_SECTION,		"elf-bad-sig-section" },	\
	{ KACS_SIG_ELF_BAD_BLOB,		"elf-bad-blob" },	\
	{ KACS_SIG_ELF_HASH_FAIL,		"elf-hash-fail" },	\
	{ KACS_SIG_XATTR_BAD_BLOB,		"xattr-bad-blob" },	\
	{ KACS_SIG_XATTR_HASH_FAIL,		"xattr-hash-fail" },	\
	{ KACS_SIG_SIZE_CHANGED,		"size-changed" }

/*
 * A signing-material probe outcome. `reason` names which malformed-ELF /
 * malformed-xattr branch rejected the file (or PROBE_FOUND on success).
 * Only lengths and codes — never file, section, or signature bytes.
 */
DECLARE_EVENT_CLASS(kacs_signing_probe,

	TP_PROTO(u32 source, u64 file_len, u8 reason, long ret),

	TP_ARGS(source, file_len, reason, ret),

	TP_STRUCT__entry(
		__field(	u64,	file_len	)
		__field(	long,	ret		)
		__field(	u32,	source		)
		__field(	u8,	reason		)
	),

	TP_fast_assign(
		__entry->file_len = file_len;
		__entry->ret = ret;
		__entry->source = source;
		__entry->reason = reason;
	),

	TP_printk("reason=%s source=%u file_len=%llu ret=%ld",
		__print_symbolic(__entry->reason,
				 kacs_signing_probe_reason_symbols),
		__entry->source, __entry->file_len, __entry->ret)
);

/* Signing-material probe reject/outcome taxonomy (signing.c) */
DEFINE_EVENT(kacs_signing_probe, kacs_signing_probe,
	TP_PROTO(u32 source, u64 file_len, u8 reason, long ret),
	TP_ARGS(source, file_len, reason, ret));

#define kacs_socket_reason_symbols					\
	{ KACS_SOCK_BAD_ARGS,		"bad-args" },			\
	{ KACS_SOCK_NOT_UNIX,		"not-unix" },			\
	{ KACS_SOCK_NO_SECURITY,	"no-security" },		\
	{ KACS_SOCK_NO_TOKEN,		"no-token" },			\
	{ KACS_SOCK_BAD_LEVEL,		"bad-level" },			\
	{ KACS_SOCK_WRONG_STATE,	"wrong-state" },		\
	{ KACS_SOCK_NO_PEER_TOKEN,	"no-peer-token" },		\
	{ KACS_SOCK_PIP_CONTEXT,	"pip-context" },		\
	{ KACS_SOCK_SD_DECISION,	"sd-decision" },		\
	{ KACS_SOCK_NO_SD,		"no-sd" },			\
	{ KACS_SOCK_HAVE_SD,		"have-sd" },			\
	{ KACS_SOCK_ALREADY_BOUND,	"already-bound" },		\
	{ KACS_SOCK_BIND,		"bind" },			\
	{ KACS_SOCK_CONNECT,		"connect" },			\
	{ KACS_SOCK_LEVEL_SET,		"level-set" },			\
	{ KACS_SOCK_OPEN_TOKEN,		"open-token" },			\
	{ KACS_SOCK_ATTACH,		"attach" },			\
	{ KACS_SOCK_GATE,		"gate" },			\
	{ KACS_SOCK_REGISTER,		"register" },			\
	{ KACS_SOCK_DELIVER,		"deliver" },			\
	{ KACS_SOCK_LISTEN,		"listen" },			\
	{ KACS_SOCK_RESTAMP,		"restamp" },			\
	{ KACS_SOCK_PORT_BIND,		"port-bind" },			\
	{ KACS_SOCK_PORT_TABLE,		"port-table" }

/*
 * One AF_UNIX socket SD / impersonation decision. Socket-shape fields are 0 at
 * emit sites without a struct sock/socket in scope. `ret` is the outcome. No
 * address, pathname, or SD bytes.
 */
DECLARE_EVENT_CLASS(kacs_socket,

	TP_PROTO(u16 sock_family, u16 sock_type, u8 sock_state,
		 u32 max_impersonation, u32 desired_access, u8 reason,
		 long ret),

	TP_ARGS(sock_family, sock_type, sock_state, max_impersonation,
		desired_access, reason, ret),

	TP_STRUCT__entry(
		__field(	u16,	sock_family		)
		__field(	u16,	sock_type			)
		__field(	u8,	sock_state		)
		__field(	u32,	max_impersonation	)
		__field(	u32,	desired_access		)
		__field(	long,	ret			)
		__field(	u8,	reason			)
	),

	TP_fast_assign(
		__entry->sock_family = sock_family;
		__entry->sock_type = sock_type;
		__entry->sock_state = sock_state;
		__entry->max_impersonation = max_impersonation;
		__entry->desired_access = desired_access;
		__entry->ret = ret;
		__entry->reason = reason;
	),

	TP_printk("reason=%s verdict=%s family=%u type=%u state=%u max_imp=%u desired=0x%x ret=%ld",
		__print_symbolic(__entry->reason, kacs_socket_reason_symbols),
		__entry->ret ? "deny" : "allow",
		__entry->sock_family, __entry->sock_type, __entry->sock_state,
		__entry->max_impersonation, __entry->desired_access,
		__entry->ret)
);

/* Abstract AF_UNIX socket SD bind hook (socket.c) */
DEFINE_EVENT(kacs_socket, kacs_socket_bind,
	TP_PROTO(u16 sock_family, u16 sock_type, u8 sock_state,
		 u32 max_impersonation, u32 desired_access, u8 reason, long ret),
	TP_ARGS(sock_family, sock_type, sock_state, max_impersonation,
		desired_access, reason, ret));

/* unix_stream_connect hook (socket.c) */
DEFINE_EVENT(kacs_socket, kacs_socket_unix_connect,
	TP_PROTO(u16 sock_family, u16 sock_type, u8 sock_state,
		 u32 max_impersonation, u32 desired_access, u8 reason, long ret),
	TP_ARGS(sock_family, sock_type, sock_state, max_impersonation,
		desired_access, reason, ret));

/* unix_may_send hook (socket.c) */
DEFINE_EVENT(kacs_socket, kacs_socket_unix_may_send,
	TP_PROTO(u16 sock_family, u16 sock_type, u8 sock_state,
		 u32 max_impersonation, u32 desired_access, u8 reason, long ret),
	TP_ARGS(sock_family, sock_type, sock_state, max_impersonation,
		desired_access, reason, ret));

/* Socket-SD access authorization core (socket.c) */
DEFINE_EVENT(kacs_socket, kacs_socket_sd_authorize,
	TP_PROTO(u16 sock_family, u16 sock_type, u8 sock_state,
		 u32 max_impersonation, u32 desired_access, u8 reason, long ret),
	TP_ARGS(sock_family, sock_type, sock_state, max_impersonation,
		desired_access, reason, ret));

/* Set-impersonation-level core (socket.c) */
DEFINE_EVENT(kacs_socket, kacs_socket_set_imp_level,
	TP_PROTO(u16 sock_family, u16 sock_type, u8 sock_state,
		 u32 max_impersonation, u32 desired_access, u8 reason, long ret),
	TP_ARGS(sock_family, sock_type, sock_state, max_impersonation,
		desired_access, reason, ret));

/* Open-peer-token core (socket.c) */
DEFINE_EVENT(kacs_socket, kacs_socket_open_peer_token,
	TP_PROTO(u16 sock_family, u16 sock_type, u8 sock_state,
		 u32 max_impersonation, u32 desired_access, u8 reason, long ret),
	TP_ARGS(sock_family, sock_type, sock_state, max_impersonation,
		desired_access, reason, ret));

/* Per-message identity: attach, gate, register, deliver (socket.c) */
DEFINE_EVENT(kacs_socket, kacs_socket_token,
	TP_PROTO(u16 sock_family, u16 sock_type, u8 sock_state,
		 u32 max_impersonation, u32 desired_access, u8 reason, long ret),
	TP_ARGS(sock_family, sock_type, sock_state, max_impersonation,
		desired_access, reason, ret));

#define kacs_namespace_stage_symbols					\
	{ KACS_NS_PRIMARY,		"primary" },			\
	{ KACS_NS_PARENT_FALLBACK,	"parent-fallback" },		\
	{ KACS_NS_SOURCE,		"source" },			\
	{ KACS_NS_DEST,			"dest" },			\
	{ KACS_NS_DELETE_EXISTING,	"delete-existing" }

/*
 * One namespace-mutation decision. `parent`/`target` may each be NULL; sb_magic
 * is taken from whichever is present. `stage` disambiguates multi-stage ops.
 * Never records a pathname.
 */
DECLARE_EVENT_CLASS(kacs_namespace,

	TP_PROTO(const struct inode *parent, const struct inode *target,
		 u32 desired_access, u8 stage, long ret),

	TP_ARGS(parent, target, desired_access, stage, ret),

	TP_STRUCT__entry(
		__field(	unsigned long,	parent_ino	)
		__field(	unsigned long,	target_ino	)
		__field(	unsigned long,	sb_magic	)
		__field(	u32,		desired_access	)
		__field(	long,		ret		)
		__field(	u8,		stage		)
	),

	TP_fast_assign(
		__entry->parent_ino = parent ? parent->i_ino : 0;
		__entry->target_ino = target ? target->i_ino : 0;
		__entry->sb_magic = (parent && parent->i_sb) ?
			(unsigned long)parent->i_sb->s_magic :
			((target && target->i_sb) ?
				(unsigned long)target->i_sb->s_magic : 0);
		__entry->desired_access = desired_access;
		__entry->ret = ret;
		__entry->stage = stage;
	),

	TP_printk("stage=%s verdict=%s parent_ino=%lu target_ino=%lu sb_magic=0x%lx access=0x%x ret=%ld",
		__print_symbolic(__entry->stage, kacs_namespace_stage_symbols),
		__entry->ret ? "deny" : "allow",
		__entry->parent_ino, __entry->target_ino, __entry->sb_magic,
		__entry->desired_access, __entry->ret)
);

/* inode_create hook (namespace.c) */
DEFINE_EVENT(kacs_namespace, kacs_inode_create,
	TP_PROTO(const struct inode *parent, const struct inode *target,
		 u32 desired_access, u8 stage, long ret),
	TP_ARGS(parent, target, desired_access, stage, ret));

/* inode_mkdir hook (namespace.c) */
DEFINE_EVENT(kacs_namespace, kacs_inode_mkdir,
	TP_PROTO(const struct inode *parent, const struct inode *target,
		 u32 desired_access, u8 stage, long ret),
	TP_ARGS(parent, target, desired_access, stage, ret));

/* inode_mknod hook (namespace.c) */
DEFINE_EVENT(kacs_namespace, kacs_inode_mknod,
	TP_PROTO(const struct inode *parent, const struct inode *target,
		 u32 desired_access, u8 stage, long ret),
	TP_ARGS(parent, target, desired_access, stage, ret));

/* inode_symlink hook (namespace.c) */
DEFINE_EVENT(kacs_namespace, kacs_inode_symlink,
	TP_PROTO(const struct inode *parent, const struct inode *target,
		 u32 desired_access, u8 stage, long ret),
	TP_ARGS(parent, target, desired_access, stage, ret));

/* inode_link hook — DEST then SOURCE stages (namespace.c) */
DEFINE_EVENT(kacs_namespace, kacs_inode_link,
	TP_PROTO(const struct inode *parent, const struct inode *target,
		 u32 desired_access, u8 stage, long ret),
	TP_ARGS(parent, target, desired_access, stage, ret));

/* inode_unlink hook (namespace.c) */
DEFINE_EVENT(kacs_namespace, kacs_inode_unlink,
	TP_PROTO(const struct inode *parent, const struct inode *target,
		 u32 desired_access, u8 stage, long ret),
	TP_ARGS(parent, target, desired_access, stage, ret));

/* inode_rmdir hook (namespace.c) */
DEFINE_EVENT(kacs_namespace, kacs_inode_rmdir,
	TP_PROTO(const struct inode *parent, const struct inode *target,
		 u32 desired_access, u8 stage, long ret),
	TP_ARGS(parent, target, desired_access, stage, ret));

/* inode_rename hook — SOURCE, DEST, DELETE_EXISTING stages (namespace.c) */
DEFINE_EVENT(kacs_namespace, kacs_inode_rename,
	TP_PROTO(const struct inode *parent, const struct inode *target,
		 u32 desired_access, u8 stage, long ret),
	TP_ARGS(parent, target, desired_access, stage, ret));

/* inode_readlink hook (namespace.c) */
DEFINE_EVENT(kacs_namespace, kacs_inode_readlink,
	TP_PROTO(const struct inode *parent, const struct inode *target,
		 u32 desired_access, u8 stage, long ret),
	TP_ARGS(parent, target, desired_access, stage, ret));

/* inode_init_security SD stamp (namespace.c) */
DEFINE_EVENT(kacs_namespace, kacs_inode_init_security,
	TP_PROTO(const struct inode *parent, const struct inode *target,
		 u32 desired_access, u8 stage, long ret),
	TP_ARGS(parent, target, desired_access, stage, ret));

#define kacs_psb_reason_symbols						\
	{ KACS_PSB_APPLY_OK,		"apply-ok" },			\
	{ KACS_PSB_APPLY_NORMALIZE,	"apply-normalize" },		\
	{ KACS_PSB_APPLY_MM_ACQUIRE,	"apply-mm-acquire" },		\
	{ KACS_PSB_APPLY_CFIF,		"apply-cfif" },			\
	{ KACS_PSB_APPLY_SML,		"apply-sml" },			\
	{ KACS_PSB_APPLY_CFIB,		"apply-cfib" },			\
	{ KACS_PSB_WXP_MMAP,		"wxp-mmap" },			\
	{ KACS_PSB_WXP_MPROTECT,	"wxp-mprotect" },		\
	{ KACS_PSB_WXP_EXISTING_VMA,	"wxp-existing-vma" },		\
	{ KACS_PSB_LSV_PROBE,		"lsv-probe" },			\
	{ KACS_PSB_LSV_VERIFY,		"lsv-verify" },			\
	{ KACS_PSB_LSV_PIP_DOMINANCE,	"lsv-pip-dominance" },		\
	{ KACS_PSB_PIE_ET_EXEC,		"pie-et-exec" },		\
	{ KACS_PSB_PRCTL_SML,		"prctl-sml" },			\
	{ KACS_PSB_PRCTL_CFIB,		"prctl-cfib" },			\
	{ KACS_PSB_PRCTL_PIP,		"prctl-pip" }

/*
 * One process-security-baseline event: a mitigation-activation outcome (apply)
 * or a W^X / LSV / PIE / prctl-lock enforcement decision. Fields are reason-
 * dependent (the kacs_sd_cache precedent): `mitigation_bits` carries the
 * requested/active bits, `prot` the offending protection for wxp, pip the
 * process PIP for lsv. Only scalars; `ret` is the outcome (0 == ok/allow).
 */
DECLARE_EVENT_CLASS(kacs_psb,

	TP_PROTO(u32 mitigation_bits, u32 result_bits, u32 prot,
		 u32 pip_type, u32 pip_trust, u8 reason, long ret),

	TP_ARGS(mitigation_bits, result_bits, prot, pip_type, pip_trust,
		reason, ret),

	TP_STRUCT__entry(
		__field(	u32,	mitigation_bits	)
		__field(	u32,	result_bits	)
		__field(	u32,	prot		)
		__field(	u32,	pip_type	)
		__field(	u32,	pip_trust	)
		__field(	long,	ret		)
		__field(	u8,	reason		)
	),

	TP_fast_assign(
		__entry->mitigation_bits = mitigation_bits;
		__entry->result_bits = result_bits;
		__entry->prot = prot;
		__entry->pip_type = pip_type;
		__entry->pip_trust = pip_trust;
		__entry->ret = ret;
		__entry->reason = reason;
	),

	TP_printk("reason=%s verdict=%s mit=0x%x result=0x%x prot=0x%x pip=%u:%u ret=%ld",
		__print_symbolic(__entry->reason, kacs_psb_reason_symbols),
		__entry->ret ? "deny" : "allow",
		__entry->mitigation_bits, __entry->result_bits, __entry->prot,
		__entry->pip_type, __entry->pip_trust, __entry->ret)
);

/* PSB mitigation activation outcome (psb.c) */
DEFINE_EVENT(kacs_psb, kacs_psb_apply,
	TP_PROTO(u32 mitigation_bits, u32 result_bits, u32 prot,
		 u32 pip_type, u32 pip_trust, u8 reason, long ret),
	TP_ARGS(mitigation_bits, result_bits, prot, pip_type, pip_trust,
		reason, ret));

/* W^X mmap / mprotect / existing-vma enforcement (psb.c) */
DEFINE_EVENT(kacs_psb, kacs_psb_wxp,
	TP_PROTO(u32 mitigation_bits, u32 result_bits, u32 prot,
		 u32 pip_type, u32 pip_trust, u8 reason, long ret),
	TP_ARGS(mitigation_bits, result_bits, prot, pip_type, pip_trust,
		reason, ret));

/* Loader signature verification enforcement (psb.c) */
DEFINE_EVENT(kacs_psb, kacs_psb_lsv,
	TP_PROTO(u32 mitigation_bits, u32 result_bits, u32 prot,
		 u32 pip_type, u32 pip_trust, u8 reason, long ret),
	TP_ARGS(mitigation_bits, result_bits, prot, pip_type, pip_trust,
		reason, ret));

/* PIE (no non-PIE ET_EXEC) enforcement (psb.c) */
DEFINE_EVENT(kacs_psb, kacs_psb_pie,
	TP_PROTO(u32 mitigation_bits, u32 result_bits, u32 prot,
		 u32 pip_type, u32 pip_trust, u8 reason, long ret),
	TP_ARGS(mitigation_bits, result_bits, prot, pip_type, pip_trust,
		reason, ret));

/* prctl mitigation/PIP lock enforcement (psb.c) */
DEFINE_EVENT(kacs_psb, kacs_psb_prctl,
	TP_PROTO(u32 mitigation_bits, u32 result_bits, u32 prot,
		 u32 pip_type, u32 pip_trust, u8 reason, long ret),
	TP_ARGS(mitigation_bits, result_bits, prot, pip_type, pip_trust,
		reason, ret));

/*
 * KACS token / session tracepoints (still inside the multi-read guard,
 * before the trailing #include <trace/define_trace.h>).
 *
 * No extra kacs/lcs helper prototype is required: every TP_fast_assign stores
 * only scalars passed by the caller. The token id is passed pre-hashed as a u64
 * ((u64)(uintptr_t)token) from the .c sites; the probe never dereferences it.
 */

#define kacs_token_ioctl_cmd_symbols					\
	{ KACS_TOK_QUERY,		"query" },			\
	{ KACS_TOK_ADJUST_PRIVS,	"adjust-privs" },		\
	{ KACS_TOK_ADJUST_GROUPS,	"adjust-groups" },		\
	{ KACS_TOK_DUPLICATE,		"duplicate" },			\
	{ KACS_TOK_INSTALL,		"install" },			\
	{ KACS_TOK_RESTRICT,		"restrict" },			\
	{ KACS_TOK_LINK,		"link" },			\
	{ KACS_TOK_GET_LINKED,		"get-linked" },			\
	{ KACS_TOK_IMPERSONATE,		"impersonate" },		\
	{ KACS_TOK_ADJUST_DEFAULT,	"adjust-default" },		\
	{ KACS_TOK_ADJUST_INTERACTIVITY_SCOPE,	"adjust-sessionid" },		\
	{ KACS_TOK_UNKNOWN,		"unknown" }

/*
 * One token-fd ioctl verb outcome. `token` is an opaque numeric id (0 when
 * unavailable); `required_access` is the access-mask bit the verb's gate
 * demands; `result_fd` is the issued fd for the fd-producing verbs (-1
 * otherwise); `logon_session_id` is the link/adjust-sessionid id (0 otherwise).
 * `ret` is the outcome (0 == allow; -EACCES == access-mask-gate deny). No
 * token, SD, or key bytes.
 */
DECLARE_EVENT_CLASS(kacs_token_ioctl,

	TP_PROTO(u64 token, u8 cmd, u32 access_mask, u32 required_access,
		 s32 result_fd, u64 logon_session_id, long ret),

	TP_ARGS(token, cmd, access_mask, required_access, result_fd,
		logon_session_id, ret),

	TP_STRUCT__entry(
		__field(	u64,	token		)
		__field(	u64,	logon_session_id	)
		__field(	long,	ret		)
		__field(	u32,	access_mask	)
		__field(	u32,	required_access	)
		__field(	s32,	result_fd	)
		__field(	u8,	cmd		)
	),

	TP_fast_assign(
		__entry->token = token;
		__entry->logon_session_id = logon_session_id;
		__entry->ret = ret;
		__entry->access_mask = access_mask;
		__entry->required_access = required_access;
		__entry->result_fd = result_fd;
		__entry->cmd = cmd;
	),

	TP_printk("cmd=%s verdict=%s token=0x%llx access=0x%x required=0x%x result_fd=%d logon_session_id=%llu ret=%ld",
		__print_symbolic(__entry->cmd, kacs_token_ioctl_cmd_symbols),
		__entry->ret ? "deny" : "allow",
		__entry->token, __entry->access_mask, __entry->required_access,
		__entry->result_fd, __entry->logon_session_id, __entry->ret)
);

/* Token-fd ioctl verb outcome / access-mask gate (token_fd.c) */
DEFINE_EVENT(kacs_token_ioctl, kacs_token_ioctl,
	TP_PROTO(u64 token, u8 cmd, u32 access_mask, u32 required_access,
		 s32 result_fd, u64 logon_session_id, long ret),
	TP_ARGS(token, cmd, access_mask, required_access, result_fd,
		logon_session_id, ret));

#define kacs_token_ref_reason_symbols					\
	{ KACS_TREF_TO_FD,		"to-fd" },			\
	{ KACS_TREF_RELEASE,		"release" },			\
	{ KACS_TREF_BIND,		"bind" },			\
	{ KACS_TREF_OPEN,		"open" }

/*
 * One token-fd reference lifecycle transition. `token` is an opaque numeric id
 * (0 when unavailable); `access_mask` is the handle's granted mask. `ret` is
 * the outcome (a new fd for TO_FD, else 0/negative errno). No token bytes.
 */
DECLARE_EVENT_CLASS(kacs_token_ref,

	TP_PROTO(u64 token, u32 access_mask, u8 reason, long ret),

	TP_ARGS(token, access_mask, reason, ret),

	TP_STRUCT__entry(
		__field(	u64,	token		)
		__field(	long,	ret		)
		__field(	u32,	access_mask	)
		__field(	u8,	reason		)
	),

	TP_fast_assign(
		__entry->token = token;
		__entry->ret = ret;
		__entry->access_mask = access_mask;
		__entry->reason = reason;
	),

	TP_printk("reason=%s token=0x%llx access=0x%x ret=%ld",
		__print_symbolic(__entry->reason, kacs_token_ref_reason_symbols),
		__entry->token, __entry->access_mask, __entry->ret)
);

/* Token-fd reference create/clone/drop lifecycle (token_fd.c) */
DEFINE_EVENT(kacs_token_ref, kacs_token_ref,
	TP_PROTO(u64 token, u32 access_mask, u8 reason, long ret),
	TP_ARGS(token, access_mask, reason, ret));

#define kacs_logon_session_reason_symbols					\
	{ KACS_SES_CREATE,			"create" },		\
	{ KACS_SES_CREATE_PRIV_DENIED,		"create-priv-denied" },	\
	{ KACS_SES_DESTROY,			"destroy" },		\
	{ KACS_SES_DESTROY_PRIV_DENIED,		"destroy-priv-denied" }, \
	{ KACS_SES_CREATE_TOKEN,		"create-token" },	\
	{ KACS_SES_CREATE_TOKEN_PRIV_DENIED,	"create-token-priv-denied" }

/*
 * One session / token-creation-surface outcome. `logon_session_id` is the session id
 * (0 when not applicable, e.g. create_token). `ret` is the outcome (0 == ok;
 * the *_PRIV_DENIED reasons carry the gate errno). No token or spec bytes.
 */
DECLARE_EVENT_CLASS(kacs_logon_session,

	TP_PROTO(u64 logon_session_id, u8 reason, long ret),

	TP_ARGS(logon_session_id, reason, ret),

	TP_STRUCT__entry(
		__field(	u64,	logon_session_id	)
		__field(	long,	ret		)
		__field(	u8,	reason		)
	),

	TP_fast_assign(
		__entry->logon_session_id = logon_session_id;
		__entry->ret = ret;
		__entry->reason = reason;
	),

	TP_printk("reason=%s logon_session_id=%llu ret=%ld",
		__print_symbolic(__entry->reason, kacs_logon_session_reason_symbols),
		__entry->logon_session_id, __entry->ret)
);

/* LogonSession create/destroy + create_token privilege gates (token_logon_session.c) */
DEFINE_EVENT(kacs_logon_session, kacs_logon_session,
	TP_PROTO(u64 logon_session_id, u8 reason, long ret),
	TP_ARGS(logon_session_id, reason, ret));

/*
 * ==== Credential / setid / task lifecycle events ====
 *
 * HARD INVARIANT: never dereference or record token / SD / process_state
 * bytes — old_token/new_token/process_state are opaque pointer ids (or 0);
 * only enums, flags, ids, and ret are recorded.
 */

#define kacs_cred_reason_symbols					\
	{ KACS_CRED_PREPARE,			"prepare" },		\
	{ KACS_CRED_TRANSFER,			"transfer" },		\
	{ KACS_CRED_ALLOC_BLANK,		"alloc-blank" },	\
	{ KACS_CRED_FREE,			"free" },		\
	{ KACS_CRED_INSTALL_TOKEN_REF,		"install-token-ref" },	\
	{ KACS_CRED_CLONE_THREAD_SHARE,		"clone-thread-share" },	\
	{ KACS_CRED_CLONE_FORK_COPY,		"clone-fork-copy" },	\
	{ KACS_CRED_PROJECT_UID0_BLOCKED,	"project-uid0-blocked" }, \
	{ KACS_CRED_PROJECT_GROUPS_ALLOC_FAIL,	"project-groups-alloc-fail" }, \
	{ KACS_CRED_PROJECT_E2BIG,		"project-e2big" }

/*
 * One credential-security lifecycle transition. old_token / new_token are
 * opaque token pointer ids (0 when absent); clone_flags is set only on the
 * clone paths. `ret` is the outcome (0 == ok, negative errno == fail). Never
 * dereferences a token.
 */
DECLARE_EVENT_CLASS(kacs_cred,

	TP_PROTO(u64 old_token, u64 new_token, u64 clone_flags, u8 reason,
		 long ret),

	TP_ARGS(old_token, new_token, clone_flags, reason, ret),

	TP_STRUCT__entry(
		__field(	u64,	old_token	)
		__field(	u64,	new_token	)
		__field(	u64,	clone_flags	)
		__field(	long,	ret		)
		__field(	u8,	reason		)
	),

	TP_fast_assign(
		__entry->old_token = old_token;
		__entry->new_token = new_token;
		__entry->clone_flags = clone_flags;
		__entry->ret = ret;
		__entry->reason = reason;
	),

	TP_printk("reason=%s outcome=%s old_token=0x%llx new_token=0x%llx clone_flags=0x%llx ret=%ld",
		__print_symbolic(__entry->reason, kacs_cred_reason_symbols),
		__entry->ret ? "fail" : "ok",
		__entry->old_token, __entry->new_token, __entry->clone_flags,
		__entry->ret)
);

/* Credential-security lifecycle transitions (cred_lifecycle.c) */
DEFINE_EVENT(kacs_cred, kacs_cred,
	TP_PROTO(u64 old_token, u64 new_token, u64 clone_flags, u8 reason,
		 long ret),
	TP_ARGS(old_token, new_token, clone_flags, reason, ret));

#define kacs_setid_reason_symbols					\
	{ KACS_SETID_SETUID_NO_TOKEN,		"setuid-no-token" },	\
	{ KACS_SETID_SETUID_PRIV_GATE,		"setuid-priv-gate" },	\
	{ KACS_SETID_SETGID_NO_TOKEN,		"setgid-no-token" },	\
	{ KACS_SETID_SETGID_PRIV_GATE,		"setgid-priv-gate" },	\
	{ KACS_SETID_SETGROUPS_NO_TOKEN,	"setgroups-no-token" },	\
	{ KACS_SETID_SETGROUPS_PRIV_GATE,	"setgroups-priv-gate" }

/*
 * One KACS setid-projection gate decision. subject_token is an opaque token
 * pointer id (0 when absent); `flags` is the LSM_SETID_* mask (0 for
 * setgroups). `ret` is the denial errno. Never dereferences a token.
 */
DECLARE_EVENT_CLASS(kacs_setid,

	TP_PROTO(u64 subject_token, u32 flags, u8 reason, long ret),

	TP_ARGS(subject_token, flags, reason, ret),

	TP_STRUCT__entry(
		__field(	u64,	subject_token	)
		__field(	long,	ret		)
		__field(	u32,	flags		)
		__field(	u8,	reason		)
	),

	TP_fast_assign(
		__entry->subject_token = subject_token;
		__entry->ret = ret;
		__entry->flags = flags;
		__entry->reason = reason;
	),

	TP_printk("reason=%s subject_token=0x%llx flags=0x%x ret=%ld",
		__print_symbolic(__entry->reason, kacs_setid_reason_symbols),
		__entry->subject_token, __entry->flags, __entry->ret)
);

/* Setid-projection gate decisions (cred_projection.c) */
DEFINE_EVENT(kacs_setid, kacs_setid,
	TP_PROTO(u64 subject_token, u32 flags, u8 reason, long ret),
	TP_ARGS(subject_token, flags, reason, ret));

#define kacs_task_reason_symbols					\
	{ KACS_TASK_ALLOC_NO_CHILD_BLOCKED,	"alloc-no-child-blocked" }, \
	{ KACS_TASK_ALLOC_INHERIT_ENOMEM,	"alloc-inherit-enomem" }, \
	{ KACS_TASK_ALLOC,			"alloc" },		\
	{ KACS_TASK_FREE,			"free" }

/*
 * One task-security lifecycle transition. process_state is an opaque
 * process-state pointer id (0 when absent); clone_flags is set on the alloc
 * paths. `ret` is the outcome. Never dereferences the process state.
 */
DECLARE_EVENT_CLASS(kacs_task,

	TP_PROTO(u64 clone_flags, u64 process_state, u8 reason, long ret),

	TP_ARGS(clone_flags, process_state, reason, ret),

	TP_STRUCT__entry(
		__field(	u64,	clone_flags	)
		__field(	u64,	process_state	)
		__field(	long,	ret		)
		__field(	u8,	reason		)
	),

	TP_fast_assign(
		__entry->clone_flags = clone_flags;
		__entry->process_state = process_state;
		__entry->ret = ret;
		__entry->reason = reason;
	),

	TP_printk("reason=%s outcome=%s clone_flags=0x%llx process_state=0x%llx ret=%ld",
		__print_symbolic(__entry->reason, kacs_task_reason_symbols),
		__entry->ret ? "fail" : "ok",
		__entry->clone_flags, __entry->process_state, __entry->ret)
);

/* Task-security lifecycle transitions (task_lifecycle.c) */
DEFINE_EVENT(kacs_task, kacs_task,
	TP_PROTO(u64 clone_flags, u64 process_state, u8 reason, long ret),
	TP_ARGS(clone_flags, process_state, reason, ret));

/*
 * ==== Primary-token / process-token-open / process-state events ====
 *
 * Invariant: never records a token or SD byte — only opaque object ids, PIP
 * tiers, access masks, reason codes and ret.
 */

#define kacs_primary_install_reason_symbols				\
	{ KACS_PRIM_INSTALL_OK,			"install-ok" },		\
	{ KACS_PRIM_SD_REALLOC,			"sd-realloc" },		\
	{ KACS_PRIM_SD_ALLOC_FAIL,		"sd-alloc-fail" },	\
	{ KACS_PRIM_APPLY_COMMIT,		"apply-commit" },	\
	{ KACS_PRIM_IMPERSONATE_INSTALL,	"impersonate-install" },\
	{ KACS_PRIM_IMPERSONATE_REVERT,		"impersonate-revert" },	\
	{ KACS_PRIM_SIBLING_REQUEUE,		"sibling-requeue" },	\
	{ KACS_PRIM_SIBLING_FAILED,		"sibling-failed" }

/*
 * One primary-token / impersonation credential transition. old_primary and
 * new_primary are opaque token identity ids (0 when not applicable at the emit
 * site); never a token byte. `ret` is the outcome (0 == ok).
 */
DECLARE_EVENT_CLASS(kacs_primary_install,

	TP_PROTO(u64 old_primary, u64 new_primary, u8 reason, long ret),

	TP_ARGS(old_primary, new_primary, reason, ret),

	TP_STRUCT__entry(
		__field(	u64,	old_primary	)
		__field(	u64,	new_primary	)
		__field(	long,	ret		)
		__field(	u8,	reason		)
	),

	TP_fast_assign(
		__entry->old_primary = old_primary;
		__entry->new_primary = new_primary;
		__entry->ret = ret;
		__entry->reason = reason;
	),

	TP_printk("reason=%s verdict=%s old=0x%llx new=0x%llx ret=%ld",
		__print_symbolic(__entry->reason,
				 kacs_primary_install_reason_symbols),
		__entry->ret ? "err" : "ok",
		__entry->old_primary, __entry->new_primary, __entry->ret)
);

/* Primary-token install / impersonation / sibling-taskwork transition
 * (primary_token.c) */
DEFINE_EVENT(kacs_primary_install, kacs_primary_install,
	TP_PROTO(u64 old_primary, u64 new_primary, u8 reason, long ret),
	TP_ARGS(old_primary, new_primary, reason, ret));

#define kacs_process_token_open_reason_symbols				\
	{ KACS_PTO_OPEN_OK,		"open-ok" },			\
	{ KACS_PTO_BAD_ARGS,		"bad-args" },			\
	{ KACS_PTO_NO_TARGET,		"no-target" },			\
	{ KACS_PTO_BAD_ACCESS,		"bad-access" },			\
	{ KACS_PTO_ACCESS_DENIED,	"access-denied" },		\
	{ KACS_PTO_SELF,		"self" },			\
	{ KACS_PTO_CROSS,		"cross" }

/*
 * One process/thread token-open decision. subject_token/target_token are opaque
 * token identity ids (0 when unknown at the emit site); access_mask is the
 * requested mask. `ret` is the outcome (>=0 fd == allow). No token bytes.
 */
DECLARE_EVENT_CLASS(kacs_process_token_open,

	TP_PROTO(u64 subject_token, u64 target_token, u32 access_mask,
		 u8 reason, long ret),

	TP_ARGS(subject_token, target_token, access_mask, reason, ret),

	TP_STRUCT__entry(
		__field(	u64,	subject_token	)
		__field(	u64,	target_token	)
		__field(	u32,	access_mask	)
		__field(	long,	ret		)
		__field(	u8,	reason		)
	),

	TP_fast_assign(
		__entry->subject_token = subject_token;
		__entry->target_token = target_token;
		__entry->access_mask = access_mask;
		__entry->ret = ret;
		__entry->reason = reason;
	),

	TP_printk("reason=%s verdict=%s subject=0x%llx target=0x%llx access=0x%x ret=%ld",
		__print_symbolic(__entry->reason,
				 kacs_process_token_open_reason_symbols),
		__entry->ret < 0 ? "deny" : "allow",
		__entry->subject_token, __entry->target_token,
		__entry->access_mask, __entry->ret)
);

/* Process/thread token open + inspection verdicts (process_token.c) */
DEFINE_EVENT(kacs_process_token_open, kacs_process_token_open,
	TP_PROTO(u64 subject_token, u64 target_token, u32 access_mask,
		 u8 reason, long ret),
	TP_ARGS(subject_token, target_token, access_mask, reason, ret));

#define kacs_process_state_reason_symbols				\
	{ KACS_PST_ALLOC,		"alloc" },			\
	{ KACS_PST_ALLOC_FAIL,		"alloc-fail" },			\
	{ KACS_PST_FREE,		"free" },			\
	{ KACS_PST_INHERIT_SHARE,	"inherit-share" },		\
	{ KACS_PST_INHERIT_FORK,	"inherit-fork" },		\
	{ KACS_PST_EXEC_PIP_STAGE,	"exec-pip-stage" },		\
	{ KACS_PST_EXEC_PIP_COMMIT,	"exec-pip-commit" },		\
	{ KACS_PST_DUMPABLE,		"dumpable" },			\
	{ KACS_PST_CLONE_BLOCKED_NOCHILD, "clone-blocked-nochild" },	\
	{ KACS_PST_SD_ALLOC,		"sd-alloc" },			\
	{ KACS_PST_SD_ALLOC_FAIL,	"sd-alloc-fail" },		\
	{ KACS_PST_SD_WRAP_FAIL,	"sd-wrap-fail" },		\
	{ KACS_PST_SD_REPLACE,		"sd-replace" },			\
	{ KACS_PST_SOCKET_SD_ALLOC,	"socket-sd-alloc" }

/*
 * One process-state / process-SD lifecycle or PIP transition. process_state is
 * an opaque state-object id (0 when none in scope, e.g. the SD primitives);
 * pip_type/pip_trust carry the PIP tier. `ret` is the outcome (0 == ok). No
 * token or SD bytes.
 */
DECLARE_EVENT_CLASS(kacs_process_state,

	TP_PROTO(u64 process_state, u32 pip_type, u32 pip_trust, u8 reason,
		 long ret),

	TP_ARGS(process_state, pip_type, pip_trust, reason, ret),

	TP_STRUCT__entry(
		__field(	u64,	process_state	)
		__field(	u32,	pip_type	)
		__field(	u32,	pip_trust	)
		__field(	long,	ret		)
		__field(	u8,	reason		)
	),

	TP_fast_assign(
		__entry->process_state = process_state;
		__entry->pip_type = pip_type;
		__entry->pip_trust = pip_trust;
		__entry->ret = ret;
		__entry->reason = reason;
	),

	TP_printk("reason=%s state=0x%llx pip=%u:%u ret=%ld",
		__print_symbolic(__entry->reason,
				 kacs_process_state_reason_symbols),
		__entry->process_state, __entry->pip_type, __entry->pip_trust,
		__entry->ret)
);

/* Process-state / process-SD lifecycle + PIP transitions
 * (process_state.c, process_sd.c) */
DEFINE_EVENT(kacs_process_state, kacs_process_state,
	TP_PROTO(u64 process_state, u32 pip_type, u32 pip_trust, u8 reason,
		 long ret),
	TP_ARGS(process_state, pip_type, pip_trust, reason, ret));

/*
 * ==== Mount-policy / SD query-set / AccessCheck-ingress events ====
 *
 * Invariant: never records SD bytes, token bytes, or a pathname — only
 * security_info, access masks, the target-kind enum, sd_len, sb_magic, policy
 * values, generations, reason, and ret.
 */

#define kacs_mount_policy_reason_symbols				\
	{ KACS_MP_SET_OK,		"set-ok" },			\
	{ KACS_MP_BAD_ARGS,		"bad-args" },			\
	{ KACS_MP_NO_SECURITY,		"no-security" },		\
	{ KACS_MP_UNMANAGED,		"unmanaged" },			\
	{ KACS_MP_VALIDATE,		"validate" },			\
	{ KACS_MP_TEMPLATE_INVALID,	"template-invalid" },		\
	{ KACS_MP_TCB_DENIED,		"tcb-denied" },			\
	{ KACS_MP_GET_OK,		"get-ok" },			\
	{ KACS_MP_GET_NO_SECURITY,	"get-no-security" },		\
	{ KACS_MP_FIXED_POLICY,		"fixed-policy" }

/*
 * One mount-policy set or get decision. `old_*` are 0 on the guard/reject paths
 * (captured only for a committed set); `new_policy` is the requested/resolved
 * policy. Never records the template SD bytes — only its magic, policy values,
 * and generations.
 */
DECLARE_EVENT_CLASS(kacs_mount_policy,

	TP_PROTO(unsigned long sb_magic, u32 old_policy, u32 new_policy,
		 u32 old_generation, u32 new_generation, u8 reason, long ret),

	TP_ARGS(sb_magic, old_policy, new_policy, old_generation,
		new_generation, reason, ret),

	TP_STRUCT__entry(
		__field(	unsigned long,	sb_magic	)
		__field(	u32,		old_policy	)
		__field(	u32,		new_policy	)
		__field(	u32,		old_generation	)
		__field(	u32,		new_generation	)
		__field(	long,		ret		)
		__field(	u8,		reason		)
	),

	TP_fast_assign(
		__entry->sb_magic = sb_magic;
		__entry->old_policy = old_policy;
		__entry->new_policy = new_policy;
		__entry->old_generation = old_generation;
		__entry->new_generation = new_generation;
		__entry->ret = ret;
		__entry->reason = reason;
	),

	TP_printk("reason=%s verdict=%s sb_magic=0x%lx old_policy=%u new_policy=%u old_gen=%u new_gen=%u ret=%ld",
		__print_symbolic(__entry->reason, kacs_mount_policy_reason_symbols),
		__entry->ret ? "fail" : "ok",
		__entry->sb_magic, __entry->old_policy, __entry->new_policy,
		__entry->old_generation, __entry->new_generation, __entry->ret)
);

/* set_mount_policy_core: TCB-gated policy commit / reject (mount_policy.c) */
DEFINE_EVENT(kacs_mount_policy, kacs_mount_policy_set,
	TP_PROTO(unsigned long sb_magic, u32 old_policy, u32 new_policy,
		 u32 old_generation, u32 new_generation, u8 reason, long ret),
	TP_ARGS(sb_magic, old_policy, new_policy, old_generation,
		new_generation, reason, ret));

/* get_mount_policy_snapshot: policy read-back (mount_policy.c) */
DEFINE_EVENT(kacs_mount_policy, kacs_mount_policy_get,
	TP_PROTO(unsigned long sb_magic, u32 old_policy, u32 new_policy,
		 u32 old_generation, u32 new_generation, u8 reason, long ret),
	TP_ARGS(sb_magic, old_policy, new_policy, old_generation,
		new_generation, reason, ret));

#define kacs_sd_syscall_kind_symbols					\
	{ KACS_SDS_KIND_TOKEN,		"token" },			\
	{ KACS_SDS_KIND_FILE,		"file" },			\
	{ KACS_SDS_KIND_PROCESS,	"process" },			\
	{ KACS_SDS_KIND_PATH,		"path" },			\
	{ KACS_SDS_KIND_ACCESS_CHECK,	"access-check" }

#define kacs_sd_syscall_reason_symbols					\
	{ KACS_SDS_QUERY_OK,		"query-ok" },			\
	{ KACS_SDS_SET_OK,		"set-ok" },			\
	{ KACS_SDS_BAD_ARGS,		"bad-args" },			\
	{ KACS_SDS_UNMANAGED,		"unmanaged" },			\
	{ KACS_SDS_ACCESS_DENIED,	"access-denied" },		\
	{ KACS_SDS_NO_SD,		"no-sd" },			\
	{ KACS_SDS_RESTORE_BYPASS,	"restore-bypass" },		\
	{ KACS_SDS_QUERY_FAIL,		"query-fail" }

/*
 * One SD query/set syscall-core decision. `target_kind` names the SD-bearing
 * object (token / file / process / path); `granted` is the mask the SD check
 * yielded (0 where not tracked); `sd_len` is the returned/merged SD length.
 * Never records the SD bytes themselves. Verdict is also in `ret`.
 */
DECLARE_EVENT_CLASS(kacs_sd_syscall,

	TP_PROTO(u32 security_info, u32 desired_access, u32 granted,
		 u8 target_kind, u32 sd_len, u8 reason, long ret),

	TP_ARGS(security_info, desired_access, granted, target_kind, sd_len,
		reason, ret),

	TP_STRUCT__entry(
		__field(	u32,	security_info	)
		__field(	u32,	desired_access	)
		__field(	u32,	granted		)
		__field(	u32,	sd_len		)
		__field(	long,	ret		)
		__field(	u8,	target_kind	)
		__field(	u8,	reason		)
	),

	TP_fast_assign(
		__entry->security_info = security_info;
		__entry->desired_access = desired_access;
		__entry->granted = granted;
		__entry->sd_len = sd_len;
		__entry->ret = ret;
		__entry->target_kind = target_kind;
		__entry->reason = reason;
	),

	TP_printk("kind=%s reason=%s verdict=%s secinfo=0x%x desired=0x%x granted=0x%x sd_len=%u ret=%ld",
		__print_symbolic(__entry->target_kind, kacs_sd_syscall_kind_symbols),
		__print_symbolic(__entry->reason, kacs_sd_syscall_reason_symbols),
		__entry->ret ? "deny" : "allow",
		__entry->security_info, __entry->desired_access,
		__entry->granted, __entry->sd_len, __entry->ret)
);

/* get_sd query cores — token/file/process/path (sd_access.c) */
DEFINE_EVENT(kacs_sd_syscall, kacs_sd_query,
	TP_PROTO(u32 security_info, u32 desired_access, u32 granted,
		 u8 target_kind, u32 sd_len, u8 reason, long ret),
	TP_ARGS(security_info, desired_access, granted, target_kind, sd_len,
		reason, ret));

/* set_sd cores — token/file/process/path, incl. restore-bypass (sd_access.c) */
DEFINE_EVENT(kacs_sd_syscall, kacs_sd_set,
	TP_PROTO(u32 security_info, u32 desired_access, u32 granted,
		 u8 target_kind, u32 sd_len, u8 reason, long ret),
	TP_ARGS(security_info, desired_access, granted, target_kind, sd_len,
		reason, ret));

#define kacs_access_check_reason_symbols				\
	{ KACS_ACK_OK,			"ok" },				\
	{ KACS_ACK_EVAL_CONTEXT,	"eval-context" },		\
	{ KACS_ACK_TOKEN_RESOLVE,	"token-resolve" },		\
	{ KACS_ACK_CAAP_LOCK_FAIL,	"caap-lock-fail" }

/*
 * One AccessCheck kernel-ingress decision (above the closed Slice 15 ABI
 * bridge). Shares the kacs_sd_syscall field shape (target_kind is fixed to
 * ACCESS_CHECK; secinfo/desired/granted are 0 at the ingress boundary; sd_len
 * carries the list node count for the _list event, 0 for scalar); `reason` and
 * `ret` are the meaningful signals. No SD/token bytes.
 */
DECLARE_EVENT_CLASS(kacs_access_check,

	TP_PROTO(u32 security_info, u32 desired_access, u32 granted,
		 u8 target_kind, u32 sd_len, u8 reason, long ret),

	TP_ARGS(security_info, desired_access, granted, target_kind, sd_len,
		reason, ret),

	TP_STRUCT__entry(
		__field(	u32,	security_info	)
		__field(	u32,	desired_access	)
		__field(	u32,	granted		)
		__field(	u32,	sd_len		)
		__field(	long,	ret		)
		__field(	u8,	target_kind	)
		__field(	u8,	reason		)
	),

	TP_fast_assign(
		__entry->security_info = security_info;
		__entry->desired_access = desired_access;
		__entry->granted = granted;
		__entry->sd_len = sd_len;
		__entry->ret = ret;
		__entry->target_kind = target_kind;
		__entry->reason = reason;
	),

	TP_printk("reason=%s verdict=%s kind=%s ret=%ld",
		__print_symbolic(__entry->reason, kacs_access_check_reason_symbols),
		__entry->ret ? "deny" : "allow",
		__print_symbolic(__entry->target_kind, kacs_sd_syscall_kind_symbols),
		__entry->ret)
);

/* kacs_access_check scalar-ingress (access_check.c) */
DEFINE_EVENT(kacs_access_check, kacs_access_check,
	TP_PROTO(u32 security_info, u32 desired_access, u32 granted,
		 u8 target_kind, u32 sd_len, u8 reason, long ret),
	TP_ARGS(security_info, desired_access, granted, target_kind, sd_len,
		reason, ret));

/* kacs_access_check_list list-ingress (access_check.c) */
DEFINE_EVENT(kacs_access_check, kacs_access_check_list,
	TP_PROTO(u32 security_info, u32 desired_access, u32 granted,
		 u8 target_kind, u32 sd_len, u8 reason, long ret),
	TP_ARGS(security_info, desired_access, granted, target_kind, sd_len,
		reason, ret));

/*
 * ==== File-snapshot / metadata / native-open-widening events ====
 *
 * The inode-bearing classes below (kacs_file_snapshot, kacs_metadata) read
 * i_ino / i_sb->s_magic directly in TP_fast_assign via the forward decls at
 * the top of this header, exactly like kacs_access_decision.
 * kacs_native_open_ext carries no inode.
 */

/* ==== kacs_file_snapshot — snapshot-grant file operation decisions ==== */

#define kacs_file_snapshot_op_symbols					\
	{ KACS_FSOP_ACCESS,		"access" },			\
	{ KACS_FSOP_PERMISSION,		"permission" },			\
	{ KACS_FSOP_IOCTL,		"ioctl" },			\
	{ KACS_FSOP_LOCK,		"lock" },			\
	{ KACS_FSOP_FCNTL,		"fcntl" },			\
	{ KACS_FSOP_TRUNCATE,		"truncate" },			\
	{ KACS_FSOP_FALLOCATE,		"fallocate" },			\
	{ KACS_FSOP_MMAP,		"mmap" },			\
	{ KACS_FSOP_MPROTECT,		"mprotect" },			\
	{ KACS_FSOP_WRITE_INTENT,	"write-intent" },		\
	{ KACS_FSOP_SYSFS_WRITE_GATE,	"sysfs-write-gate" }

#define kacs_file_snapshot_reason_symbols				\
	{ KACS_FSR_DECISION,		"decision" },			\
	{ KACS_FSR_SIGNED_EXEC,		"signed-exec" },		\
	{ KACS_FSR_GRANT_DENY,		"grant-deny" },			\
	{ KACS_FSR_APPEND_DENY,		"append-deny" },		\
	{ KACS_FSR_UNMANAGED_SYSFS,	"unmanaged-sysfs" },		\
	{ KACS_FSR_AUDIT_EMIT_FAIL,	"audit-emit-fail" }

/*
 * One snapshot-grant file operation decision on an already-open fd. `inode` may
 * be NULL (a guard path); ino/sb_magic then read as zero. `op` names the
 * operation, `reason` the deny cause, `ret` the verdict (0 == allow). `managed`
 * is the fd's KACS-managed flag; granted_access is the fd's snapshot grant mask.
 * Never records a pathname or SD bytes.
 */
DECLARE_EVENT_CLASS(kacs_file_snapshot,

	TP_PROTO(const struct inode *inode, u8 op, u8 managed,
		 u32 granted_access, u32 required_access, u8 reason, long ret),

	TP_ARGS(inode, op, managed, granted_access, required_access, reason, ret),

	TP_STRUCT__entry(
		__field(	unsigned long,	ino		)
		__field(	unsigned long,	sb_magic	)
		__field(	u32,		granted_access	)
		__field(	u32,		required_access	)
		__field(	long,		ret		)
		__field(	u8,		op		)
		__field(	u8,		managed		)
		__field(	u8,		reason		)
	),

	TP_fast_assign(
		__entry->ino = inode ? inode->i_ino : 0;
		__entry->sb_magic = (inode && inode->i_sb) ?
			(unsigned long)inode->i_sb->s_magic : 0;
		__entry->granted_access = granted_access;
		__entry->required_access = required_access;
		__entry->ret = ret;
		__entry->op = op;
		__entry->managed = managed;
		__entry->reason = reason;
	),

	TP_printk("op=%s reason=%s verdict=%s ino=%lu sb_magic=0x%lx managed=%u granted=0x%x required=0x%x ret=%ld",
		__print_symbolic(__entry->op, kacs_file_snapshot_op_symbols),
		__print_symbolic(__entry->reason, kacs_file_snapshot_reason_symbols),
		__entry->ret ? "deny" : "allow",
		__entry->ino, __entry->sb_magic, __entry->managed,
		__entry->granted_access, __entry->required_access, __entry->ret)
);

/* Snapshot-grant file operation decision (file_access.c) */
DEFINE_EVENT(kacs_file_snapshot, kacs_file_snapshot,
	TP_PROTO(const struct inode *inode, u8 op, u8 managed,
		 u32 granted_access, u32 required_access, u8 reason, long ret),
	TP_ARGS(inode, op, managed, granted_access, required_access, reason, ret));

/* ==== kacs_metadata — file-metadata (getattr/setattr/xattr/getsecurity) ==== */

#define kacs_metadata_reason_symbols					\
	{ KACS_META_DECISION,		"decision" },			\
	{ KACS_META_CONSUME_HIT,	"consume-hit" },		\
	{ KACS_META_BEGIN_BUSY,		"begin-busy" },			\
	{ KACS_META_CANONICAL_SD,	"canonical-sd" },		\
	{ KACS_META_CAPS_XATTR,		"caps-xattr" },			\
	{ KACS_META_ACL,		"acl" },			\
	{ KACS_META_SIGNED_EXEC,	"signed-exec" },		\
	{ KACS_META_BAD_ARGS,		"bad-args" },			\
	{ KACS_META_INTERNAL_SD,	"internal-sd" },		\
	{ KACS_META_GETSECURITY,	"getsecurity" }

/*
 * One file-metadata hook decision. `inode` may be NULL (a guard path); ino then
 * reads as zero. `op_class` is the internal PKM_KACS_METADATA_OP_* class value,
 * `matched` the consume match flag, `reason` names the branch, `ret` the outcome
 * (0 == allow). No sb_magic is recorded (the metadata hooks are inode-local).
 * Never records a pathname, xattr name, or SD bytes.
 */
DECLARE_EVENT_CLASS(kacs_metadata,

	TP_PROTO(const struct inode *inode, u8 op_class, u8 matched, u8 reason,
		 long ret),

	TP_ARGS(inode, op_class, matched, reason, ret),

	TP_STRUCT__entry(
		__field(	unsigned long,	ino		)
		__field(	long,		ret		)
		__field(	u8,		op_class	)
		__field(	u8,		matched		)
		__field(	u8,		reason		)
	),

	TP_fast_assign(
		__entry->ino = inode ? inode->i_ino : 0;
		__entry->ret = ret;
		__entry->op_class = op_class;
		__entry->matched = matched;
		__entry->reason = reason;
	),

	TP_printk("reason=%s verdict=%s op_class=%u matched=%u ino=%lu ret=%ld",
		__print_symbolic(__entry->reason, kacs_metadata_reason_symbols),
		__entry->ret ? "deny" : "allow",
		__entry->op_class, __entry->matched, __entry->ino, __entry->ret)
);

/* File-metadata hook decision (file_metadata.c) */
DEFINE_EVENT(kacs_metadata, kacs_metadata,
	TP_PROTO(const struct inode *inode, u8 op_class, u8 matched, u8 reason,
		 long ret),
	TP_ARGS(inode, op_class, matched, reason, ret));

/* ==== kacs_native_open_ext — native (kacs_open) widening decisions ==== */

#define kacs_native_open_ext_reason_symbols				\
	{ KACS_NOX_PREPARE_OK,			"prepare-ok" },		\
	{ KACS_NOX_PREPARE_BAD_FLAGS,		"prepare-bad-flags" },	\
	{ KACS_NOX_PREPARE_BAD_SD_ARGS,		"prepare-bad-sd-args" }, \
	{ KACS_NOX_PREPARE_BAD_DISPOSITION,	"prepare-bad-disposition" }, \
	{ KACS_NOX_PREPARE_BAD_ACCESS,		"prepare-bad-access" },	\
	{ KACS_NOX_PREPARE_UNSUPPORTED,		"prepare-unsupported" },	\
	{ KACS_NOX_RESOLVE,			"resolve" },		\
	{ KACS_NOX_BUILD_CREATED_SD,		"build-created-sd" },	\
	{ KACS_NOX_DELETE_ON_CLOSE_ARM,		"delete-on-close-arm" }

/*
 * One native-open widening decision. Carries no inode — only the create
 * `disposition`, the mapped `desired_access` mask, the `reason` (which prepare
 * reject bucket or which later stage), and `ret` (0 == ok/allow). Never records
 * a pathname or SD bytes.
 */
DECLARE_EVENT_CLASS(kacs_native_open_ext,

	TP_PROTO(u32 disposition, u32 desired_access, u8 reason, long ret),

	TP_ARGS(disposition, desired_access, reason, ret),

	TP_STRUCT__entry(
		__field(	u32,	disposition	)
		__field(	u32,	desired_access	)
		__field(	long,	ret		)
		__field(	u8,	reason		)
	),

	TP_fast_assign(
		__entry->disposition = disposition;
		__entry->desired_access = desired_access;
		__entry->ret = ret;
		__entry->reason = reason;
	),

	TP_printk("reason=%s verdict=%s disposition=%u desired=0x%x ret=%ld",
		__print_symbolic(__entry->reason,
				 kacs_native_open_ext_reason_symbols),
		__entry->ret ? "deny" : "allow",
		__entry->disposition, __entry->desired_access, __entry->ret)
);

/* Native (kacs_open) prepare/resolve/build/arm widening (native_open.c) */
DEFINE_EVENT(kacs_native_open_ext, kacs_native_open_ext,
	TP_PROTO(u32 disposition, u32 desired_access, u8 reason, long ret),
	TP_ARGS(disposition, desired_access, reason, ret));

/* ==== Object-lifecycle / securityfs / CAAP / capability / privilege / TLP ==== */

#define kacs_object_reason_symbols					\
	{ KACS_OBJ_DELETE_ON_CLOSE_UNLINK,	"delete-on-close-unlink" }, \
	{ KACS_OBJ_SIGNED_EXEC_PIN,		"signed-exec-pin" },	\
	{ KACS_OBJ_SIGNED_EXEC_MUTATION_BLOCKED, "signed-exec-mutation-blocked" }

/*
 * One high-value object-lifecycle verdict. `inode` may be NULL; ino then reads
 * as zero. `ret` is the outcome (0 == ok). No pathname.
 */
DECLARE_EVENT_CLASS(kacs_object,

	TP_PROTO(const struct inode *inode, u8 reason, long ret),

	TP_ARGS(inode, reason, ret),

	TP_STRUCT__entry(
		__field(	unsigned long,	ino	)
		__field(	long,		ret	)
		__field(	u8,		reason	)
	),

	TP_fast_assign(
		__entry->ino = inode ? inode->i_ino : 0;
		__entry->ret = ret;
		__entry->reason = reason;
	),

	TP_printk("reason=%s verdict=%s ino=%lu ret=%ld",
		__print_symbolic(__entry->reason, kacs_object_reason_symbols),
		__entry->ret ? "deny" : "allow",
		__entry->ino, __entry->ret)
);

/* Object lifecycle verdicts (object_lifecycle.c) */
DEFINE_EVENT(kacs_object, kacs_object,
	TP_PROTO(const struct inode *inode, u8 reason, long ret),
	TP_ARGS(inode, reason, ret));

#define kacs_securityfs_reason_symbols					\
	{ KACS_SFS_LOGON_SESSIONS_NO_TOKEN,		"sessions-no-token" },	\
	{ KACS_SFS_LOGON_SESSIONS_PIP_CONTEXT,	"sessions-pip-context" }, \
	{ KACS_SFS_LOGON_SESSIONS_ACCESS_CHECK,	"sessions-access-check" }, \
	{ KACS_SFS_OPEN_SELF,			"open-self" },		\
	{ KACS_SFS_INIT,			"init" }

/*
 * One securityfs endpoint outcome. `ret` is the outcome (0 == ok). No token or
 * session bytes.
 */
DECLARE_EVENT_CLASS(kacs_securityfs,

	TP_PROTO(u8 reason, long ret),

	TP_ARGS(reason, ret),

	TP_STRUCT__entry(
		__field(	long,	ret	)
		__field(	u8,	reason	)
	),

	TP_fast_assign(
		__entry->ret = ret;
		__entry->reason = reason;
	),

	TP_printk("reason=%s verdict=%s ret=%ld",
		__print_symbolic(__entry->reason, kacs_securityfs_reason_symbols),
		__entry->ret ? "deny" : "allow",
		__entry->ret)
);

/* securityfs kacs/ endpoint outcomes (securityfs.c) */
DEFINE_EVENT(kacs_securityfs, kacs_securityfs,
	TP_PROTO(u8 reason, long ret),
	TP_ARGS(reason, ret));

#define kacs_caap_reason_symbols					\
	{ KACS_CAAP_TCB_GATE,	"tcb-gate" },				\
	{ KACS_CAAP_SET,	"set" },				\
	{ KACS_CAAP_INIT,	"init" },				\
	{ KACS_CAAP_DESTROY,	"destroy" }

/*
 * One CAAP policy-cache event. sid_len/spec_len are the set inputs (0 for
 * lifecycle/gate paths); cache_len is the post-set entry count. `ret` is the
 * outcome. No SID or spec bytes — lengths and count only.
 */
DECLARE_EVENT_CLASS(kacs_caap,

	TP_PROTO(u32 sid_len, u32 spec_len, u32 cache_len, u8 reason, long ret),

	TP_ARGS(sid_len, spec_len, cache_len, reason, ret),

	TP_STRUCT__entry(
		__field(	u32,	sid_len		)
		__field(	u32,	spec_len	)
		__field(	u32,	cache_len	)
		__field(	long,	ret		)
		__field(	u8,	reason		)
	),

	TP_fast_assign(
		__entry->sid_len = sid_len;
		__entry->spec_len = spec_len;
		__entry->cache_len = cache_len;
		__entry->ret = ret;
		__entry->reason = reason;
	),

	TP_printk("reason=%s verdict=%s sid_len=%u spec_len=%u cache_len=%u ret=%ld",
		__print_symbolic(__entry->reason, kacs_caap_reason_symbols),
		__entry->ret ? "deny" : "allow",
		__entry->sid_len, __entry->spec_len, __entry->cache_len,
		__entry->ret)
);

/* CAAP policy-cache set / lifecycle / TCB gate (caap_cache.c) */
DEFINE_EVENT(kacs_caap, kacs_caap,
	TP_PROTO(u32 sid_len, u32 spec_len, u32 cache_len, u8 reason, long ret),
	TP_ARGS(sid_len, spec_len, cache_len, reason, ret));

#define kacs_capability_reason_symbols					\
	{ KACS_CAP_ALLOW_GRANT,		"allow-grant" },		\
	{ KACS_CAP_HARD_DENY,		"hard-deny" },			\
	{ KACS_CAP_PRIV_NOT_ENABLED,	"priv-not-enabled" },		\
	{ KACS_CAP_USE_MARK_FAIL,	"use-mark-fail" },		\
	{ KACS_CAP_CAPSET,		"capset" },			\
	{ KACS_CAP_PRCTL_GUARD,		"prctl-guard" },		\
	{ KACS_CAP_CAPABLE,		"capable" },			\
	{ KACS_CAP_CAPGET,		"capget" }

/*
 * One capability->privilege gate or capability-hook verdict. `cap` is the POSIX
 * capability number (0 where not applicable); `privilege` is the mapped KACS
 * privilege bitmask (0 where none). `ret` is the outcome. Only scalars.
 */
DECLARE_EVENT_CLASS(kacs_capability,

	TP_PROTO(int cap, u64 privilege, u8 reason, long ret),

	TP_ARGS(cap, privilege, reason, ret),

	TP_STRUCT__entry(
		__field(	u64,	privilege	)
		__field(	long,	ret		)
		__field(	int,	cap		)
		__field(	u8,	reason		)
	),

	TP_fast_assign(
		__entry->privilege = privilege;
		__entry->ret = ret;
		__entry->cap = cap;
		__entry->reason = reason;
	),

	TP_printk("reason=%s verdict=%s cap=%d privilege=0x%llx ret=%ld",
		__print_symbolic(__entry->reason, kacs_capability_reason_symbols),
		__entry->ret ? "deny" : "allow",
		__entry->cap, __entry->privilege, __entry->ret)
);

/* Capability->privilege gate and capability hooks (capability.c) */
DEFINE_EVENT(kacs_capability, kacs_capability,
	TP_PROTO(int cap, u64 privilege, u8 reason, long ret),
	TP_ARGS(cap, privilege, reason, ret));

#define kacs_privilege_reason_symbols					\
	{ KACS_PRIV_NULL_OR_ZERO,	"null-or-zero" },		\
	{ KACS_PRIV_NOT_ENABLED,	"not-enabled" },		\
	{ KACS_PRIV_USE_MARK_FAIL,	"use-mark-fail" },		\
	{ KACS_PRIV_CHANGE_NOTIFY,	"change-notify" },		\
	{ KACS_PRIV_RCU_ENOMEM_FALLBACK, "rcu-enomem-fallback" }

/*
 * One privilege-gate or privilege-path verdict. `privilege` is the KACS
 * privilege bitmask under evaluation (0 where none). `ret` is the outcome.
 * Only scalars.
 */
DECLARE_EVENT_CLASS(kacs_privilege,

	TP_PROTO(u64 privilege, u8 reason, long ret),

	TP_ARGS(privilege, reason, ret),

	TP_STRUCT__entry(
		__field(	u64,	privilege	)
		__field(	long,	ret		)
		__field(	u8,	reason		)
	),

	TP_fast_assign(
		__entry->privilege = privilege;
		__entry->ret = ret;
		__entry->reason = reason;
	),

	TP_printk("reason=%s verdict=%s privilege=0x%llx ret=%ld",
		__print_symbolic(__entry->reason, kacs_privilege_reason_symbols),
		__entry->ret ? "deny" : "allow",
		__entry->privilege, __entry->ret)
);

/* Privilege gates and privilege-path markers (runtime.c) */
DEFINE_EVENT(kacs_privilege, kacs_privilege,
	TP_PROTO(u64 privilege, u8 reason, long ret),
	TP_ARGS(privilege, reason, ret));

#define kacs_tlp_reason_symbols						\
	{ KACS_TLP_CHECK_PATH,	"check-path" },				\
	{ KACS_TLP_REPLACE,	"replace" }

/*
 * One trusted-launch-path decision. PATH-SENSITIVE: only path_len and
 * prefix_count are recorded, NEVER path or prefix bytes. `allowed` is the
 * match result; `ret` is the outcome.
 */
DECLARE_EVENT_CLASS(kacs_tlp,

	TP_PROTO(u32 path_len, u32 prefix_count, bool allowed, u8 reason,
		 long ret),

	TP_ARGS(path_len, prefix_count, allowed, reason, ret),

	TP_STRUCT__entry(
		__field(	u32,	path_len	)
		__field(	u32,	prefix_count	)
		__field(	long,	ret		)
		__field(	u8,	allowed		)
		__field(	u8,	reason		)
	),

	TP_fast_assign(
		__entry->path_len = path_len;
		__entry->prefix_count = prefix_count;
		__entry->ret = ret;
		__entry->allowed = allowed;
		__entry->reason = reason;
	),

	TP_printk("reason=%s verdict=%s path_len=%u prefix_count=%u allowed=%d ret=%ld",
		__print_symbolic(__entry->reason, kacs_tlp_reason_symbols),
		__entry->ret ? "deny" : "allow",
		__entry->path_len, __entry->prefix_count, __entry->allowed,
		__entry->ret)
);

/* Trusted-launch-path check / prefix replace (tlp.c) */
DEFINE_EVENT(kacs_tlp, kacs_tlp,
	TP_PROTO(u32 path_len, u32 prefix_count, bool allowed, u8 reason,
		 long ret),
	TP_ARGS(path_len, prefix_count, allowed, reason, ret));

/* System V IPC object decisions (ipc.c): kind 0=sem 1=msg 2=shm (ipc_ids index) */
TRACE_EVENT(kacs_ipc,
	TP_PROTO(u32 kind, int id, u32 cmd, u32 desired, u8 reason, long ret),
	TP_ARGS(kind, id, cmd, desired, reason, ret),
	TP_STRUCT__entry(
		__field(u32, kind)
		__field(int, id)
		__field(u32, cmd)
		__field(u32, desired)
		__field(u8, reason)
		__field(long, ret)
	),
	TP_fast_assign(
		__entry->kind = kind;
		__entry->id = id;
		__entry->cmd = cmd;
		__entry->desired = desired;
		__entry->reason = reason;
		__entry->ret = ret;
	),
	TP_printk("kind=%u id=%d cmd=%u desired=0x%x reason=%u verdict=%s ret=%ld",
		__entry->kind, __entry->id, __entry->cmd, __entry->desired,
		__entry->reason, __entry->ret ? "deny" : "allow", __entry->ret)
);

#endif /* _TRACE_KACS_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
