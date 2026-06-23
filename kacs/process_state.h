/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SECURITY_PKM_KACS_PROCESS_STATE_H
#define _SECURITY_PKM_KACS_PROCESS_STATE_H

#include <linux/types.h>

struct cred;
struct pkm_kacs_process_sd;
struct pkm_kacs_process_state;

void pkm_kacs_set_cred_process_state(struct cred *cred,
				     struct pkm_kacs_process_state *state);
struct pkm_kacs_process_sd *pkm_kacs_process_state_get_sd(
	struct pkm_kacs_process_state *state);
void pkm_kacs_process_state_replace_sd_locked(
	struct pkm_kacs_process_state *state, struct pkm_kacs_process_sd *new_sd);
void pkm_kacs_process_state_replace_sd(
	struct pkm_kacs_process_state *state, struct pkm_kacs_process_sd *new_sd);
struct pkm_kacs_process_state *pkm_kacs_process_state_alloc(
	const void *primary_token, u32 pip_type, u32 pip_trust,
	u32 mitigation_bits);
struct pkm_kacs_process_state *pkm_kacs_process_state_get(
	struct pkm_kacs_process_state *state);
void pkm_kacs_process_state_put(struct pkm_kacs_process_state *state);
struct pkm_kacs_process_state *pkm_kacs_current_process_state(void);
void pkm_kacs_clear_pending_exec_pip(void);
void pkm_kacs_stage_pending_exec_pip(u32 pip_type, u32 pip_trust);
int pkm_kacs_exec_dumpable_after_pip(u32 pip_type, int current_dumpable);
void pkm_kacs_apply_pending_exec_dumpable(void);
void pkm_kacs_commit_pending_exec_pip(void);
u32 pkm_kacs_process_state_mitigation_bits(
	const struct pkm_kacs_process_state *state);
bool pkm_kacs_clone_is_blocked_by_no_child(u32 mitigation_bits,
					   u64 clone_flags);
struct pkm_kacs_process_state *pkm_kacs_inherit_process_state(
	u64 clone_flags);

#endif /* _SECURITY_PKM_KACS_PROCESS_STATE_H */
