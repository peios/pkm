// SPDX-License-Identifier: GPL-2.0-only

#include <linux/binfmts.h>
#include <linux/elf.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/mmap_lock.h>
#include <linux/mman.h>
#include <linux/pid.h>
#include <linux/pidfd.h>
#include <linux/prctl.h>
#include <linux/sched.h>
#include <linux/sched/coredump.h>
#include <linux/sched/mm.h>
#include <linux/syscalls.h>
#include <linux/types.h>

#include <asm/cpufeatures.h>
#include <asm/prctl.h>
#include <asm/shstk.h>

#include <pkm/psb.h>
#include <pkm/token.h>

#include "capability.h"
#include "copy_up.h"
#include "file_access.h"
#include "lsm_internal.h"
#include "object_lifecycle.h"
#include "process_access.h"
#include "process_state.h"
#include "psb.h"
#include "signing.h"
#include "tlp.h"
#include "token_runtime.h"

#include <trace/events/kacs.h>

static bool pkm_kacs_ibt_supported(void)
{
	return cpu_feature_enabled(X86_FEATURE_IBT);
}

static bool pkm_kacs_shstk_supported(void)
{
	return cpu_feature_enabled(X86_FEATURE_USER_SHSTK);
}

static long pkm_kacs_normalize_requested_mitigations(
	u32 requested_mitigations, bool ibt_supported, bool shstk_supported,
	u32 *normalized_out)
{
	u32 normalized = requested_mitigations;

	if (!normalized_out)
		return -EINVAL;
	if (requested_mitigations & ~KACS_MIT_ALL) {
		trace_kacs_psb_apply(requested_mitigations, 0, 0, 0, 0,
				     KACS_PSB_APPLY_NORMALIZE, -EINVAL);
		return -EINVAL;
	}

	if ((normalized & KACS_MIT_CFI) != 0)
		normalized |= KACS_MIT_CFIF | KACS_MIT_CFIB;
	normalized &= ~KACS_MIT_CFI;

	if ((normalized & KACS_MIT_CFIF) != 0 && !ibt_supported) {
		trace_kacs_psb_apply(requested_mitigations, 0, 0, 0, 0,
				     KACS_PSB_APPLY_NORMALIZE, -ENODEV);
		return -ENODEV;
	}
	if ((normalized & KACS_MIT_CFIB) != 0 && !shstk_supported) {
		trace_kacs_psb_apply(requested_mitigations, 0, 0, 0, 0,
				     KACS_PSB_APPLY_NORMALIZE, -ENODEV);
		return -ENODEV;
	}

	*normalized_out = normalized;
	return 0;
}

#define PKM_KACS_MIT_ACTIVE_ARCH (KACS_MIT_CFIF | KACS_MIT_CFIB | KACS_MIT_SML)
#define PKM_KACS_MIT_ACTIVE_MEMORY (KACS_MIT_WXP | KACS_MIT_TLP | KACS_MIT_LSV)

static int pkm_kacs_check_lsv_file_core(u32 mitigation_bits,
					struct file *file,
					bool executable_transition,
					u32 process_pip_type,
					u32 process_pip_trust);

static bool pkm_kacs_activation_offline_allowed(
	const struct pkm_kacs_psb_activation_context *activation)
{
	return activation && activation->offline_allowed && !activation->task;
}

static long pkm_kacs_kunit_fail_requested_activation(
	const struct pkm_kacs_psb_activation_context *activation, u32 new_bits)
{
	if (activation && (activation->kunit_fail_activation_bits & new_bits))
		return -EACCES;

	return 0;
}

static long pkm_kacs_activate_cfif_for_task(
	const struct pkm_kacs_psb_activation_context *activation)
{
	if (pkm_kacs_activation_offline_allowed(activation))
		return 0;

	/*
	 * Linux 6.19 exposes kernel IBT, but no userspace IBT/BTI control
	 * surface that KACS can actively enable and lock for a task.
	 */
	return -ENODEV;
}

static long pkm_kacs_activate_cfib_for_task(
	const struct pkm_kacs_psb_activation_context *activation)
{
	struct task_struct *task;
	long ret;

	if (pkm_kacs_activation_offline_allowed(activation))
		return 0;
	if (!activation || !activation->task)
		return -EACCES;

	task = activation->task;
	if (!cpu_feature_enabled(X86_FEATURE_USER_SHSTK))
		return -ENODEV;

	if ((task->thread.features & ARCH_SHSTK_SHSTK) == 0) {
		if (task != current)
			return -EACCES;

		ret = shstk_prctl(task, ARCH_SHSTK_ENABLE, ARCH_SHSTK_SHSTK);
		if (ret)
			return ret;
	}

	ret = shstk_prctl(task, ARCH_SHSTK_LOCK, ARCH_SHSTK_SHSTK);
	if (ret)
		return ret;

	if ((task->thread.features & ARCH_SHSTK_SHSTK) == 0 ||
	    (task->thread.features_locked & ARCH_SHSTK_SHSTK) == 0)
		return -EACCES;

	return 0;
}

static bool pkm_kacs_sml_ctrl_is_satisfied(unsigned long which, int state)
{
	if (state < 0)
		return false;
	if (state == PR_SPEC_NOT_AFFECTED)
		return true;

	if (which == PR_SPEC_L1D_FLUSH)
		return (state & PR_SPEC_ENABLE) != 0 ||
		       (state & PR_SPEC_FORCE_DISABLE) != 0;

	return (state & PR_SPEC_DISABLE) != 0 ||
	       (state & PR_SPEC_FORCE_DISABLE) != 0;
}

static long pkm_kacs_activate_sml_control(struct task_struct *task,
					  unsigned long which,
					  unsigned long activate_ctrl)
{
	int state;
	long ret;

	state = arch_prctl_spec_ctrl_get(task, which);
	if (pkm_kacs_sml_ctrl_is_satisfied(which, state))
		return 0;
	if (state < 0)
		return state;

	ret = arch_prctl_spec_ctrl_set(task, which, activate_ctrl);
	if (ret)
		return ret;

	state = arch_prctl_spec_ctrl_get(task, which);
	return pkm_kacs_sml_ctrl_is_satisfied(which, state) ? 0 : -EACCES;
}

static long pkm_kacs_activate_sml_for_task(
	const struct pkm_kacs_psb_activation_context *activation)
{
	struct task_struct *task;
	long ret;

	if (pkm_kacs_activation_offline_allowed(activation))
		return 0;
	if (!activation || !activation->task)
		return -EACCES;

	task = activation->task;
	ret = pkm_kacs_activate_sml_control(task, PR_SPEC_STORE_BYPASS,
					    PR_SPEC_FORCE_DISABLE);
	if (ret)
		return ret;

	ret = pkm_kacs_activate_sml_control(task, PR_SPEC_INDIRECT_BRANCH,
					    PR_SPEC_FORCE_DISABLE);
	if (ret)
		return ret;

	return pkm_kacs_activate_sml_control(task, PR_SPEC_L1D_FLUSH,
					     PR_SPEC_ENABLE);
}

static long pkm_kacs_activate_arch_mitigations(
	const struct pkm_kacs_psb_activation_context *activation, u32 new_bits)
{
	long ret;

	ret = pkm_kacs_kunit_fail_requested_activation(activation,
						      new_bits &
							      PKM_KACS_MIT_ACTIVE_ARCH);
	if (ret)
		return ret;

	if ((new_bits & KACS_MIT_CFIF) != 0) {
		ret = pkm_kacs_activate_cfif_for_task(activation);
		if (ret) {
			trace_kacs_psb_apply(KACS_MIT_CFIF, 0, 0, 0, 0,
					     KACS_PSB_APPLY_CFIF, ret);
			return ret;
		}
	}
	if ((new_bits & KACS_MIT_SML) != 0) {
		ret = pkm_kacs_activate_sml_for_task(activation);
		if (ret) {
			trace_kacs_psb_apply(KACS_MIT_SML, 0, 0, 0, 0,
					     KACS_PSB_APPLY_SML, ret);
			return ret;
		}
	}
	if ((new_bits & KACS_MIT_CFIB) != 0) {
		ret = pkm_kacs_activate_cfib_for_task(activation);
		if (ret) {
			trace_kacs_psb_apply(KACS_MIT_CFIB, 0, 0, 0, 0,
					     KACS_PSB_APPLY_CFIB, ret);
			return ret;
		}
	}

	return 0;
}

static int pkm_kacs_check_wxp_existing_vma_core(u32 mitigation_bits,
						unsigned long vm_flags)
{
	if ((mitigation_bits & KACS_MIT_WXP) == 0)
		return 0;
	if ((vm_flags & VM_WRITE) != 0 && (vm_flags & VM_EXEC) != 0) {
		trace_kacs_psb_wxp(mitigation_bits, 0, 0, 0, 0,
				   KACS_PSB_WXP_EXISTING_VMA, -EACCES);
		return -EACCES;
	}

	return 0;
}

static long pkm_kacs_validate_existing_mapping(
	u32 new_bits, struct pkm_kacs_process_state *target_state,
	struct vm_area_struct *vma)
{
	unsigned long vm_flags = vma->vm_flags;
	bool executable = (vm_flags & VM_EXEC) != 0;
	long ret;

	ret = pkm_kacs_check_wxp_existing_vma_core(new_bits, vm_flags);
	if (ret)
		return ret;

	if (!executable)
		return 0;

	if ((new_bits & KACS_MIT_TLP) != 0) {
		ret = pkm_kacs_check_tlp_file_core(KACS_MIT_TLP, vma->vm_file,
						   true);
		if (ret)
			return ret;
	}

	if ((new_bits & KACS_MIT_LSV) != 0) {
		ret = pkm_kacs_check_lsv_file_core(
			KACS_MIT_LSV, vma->vm_file, true,
			target_state->pip_type, target_state->pip_trust);
		if (ret)
			return ret;
	}

	return 0;
}

static long pkm_kacs_validate_existing_mappings_locked(
	u32 new_bits, struct pkm_kacs_process_state *target_state,
	struct mm_struct *mm)
{
	struct vm_area_struct *vma;
	VMA_ITERATOR(vmi, mm, 0);
	long ret;

	for_each_vma(vmi, vma) {
		ret = pkm_kacs_validate_existing_mapping(new_bits, target_state,
							 vma);
		if (ret)
			return ret;
	}

	return 0;
}

static long pkm_kacs_apply_psb_mitigations_core(
	const void *subject_token,
	const struct pkm_kacs_process_state *caller_state,
	struct pkm_kacs_process_state *target_state,
	const struct pkm_kacs_psb_activation_context *activation,
	bool self_target,
	u32 requested_mitigations, bool ibt_supported, bool shstk_supported,
	u32 *result_mitigation_bits_out)
{
	struct mm_struct *mm = NULL;
	unsigned long flags;
	u32 normalized_bits;
	u32 new_bits;
	u32 result_bits;
	long ret;

	if (!target_state)
		return -EACCES;

	ret = pkm_kacs_normalize_requested_mitigations(
		requested_mitigations, ibt_supported, shstk_supported,
		&normalized_bits);
	if (ret)
		return ret;

	if (!self_target) {
		ret = pkm_kacs_check_process_setinfo_core(
			subject_token, caller_state, target_state);
		if (ret)
			return ret;
	}

	spin_lock_irqsave(&target_state->mitigation_lock, flags);
	new_bits = normalized_bits & ~target_state->mitigation_bits;
	spin_unlock_irqrestore(&target_state->mitigation_lock, flags);

	ret = pkm_kacs_kunit_fail_requested_activation(activation, new_bits);
	if (ret)
		return ret;

	if ((new_bits & PKM_KACS_MIT_ACTIVE_MEMORY) != 0) {
		if (pkm_kacs_activation_offline_allowed(activation)) {
			mm = NULL;
		} else if (!activation || !activation->task) {
			trace_kacs_psb_apply(new_bits, 0, 0,
					     READ_ONCE(target_state->pip_type),
					     READ_ONCE(target_state->pip_trust),
					     KACS_PSB_APPLY_MM_ACQUIRE, -EACCES);
			return -EACCES;
		} else {
			mm = get_task_mm(activation->task);
		}
	}

	/*
	 * Validate existing mappings BEFORE applying any irreversible arch state
	 * (shadow-stack ENABLE+LOCK, spec-ctrl FORCE_DISABLE). If validation
	 * fails after activation, the syscall reports failure while the hardware
	 * mitigation stays enforced and mitigation_bits is never recorded —
	 * a state desync. Release mmap_lock before activating: enabling the
	 * shadow stack can take mmap_write_lock, which would deadlock against a
	 * held read lock.
	 */
	if (mm) {
		mmap_read_lock(mm);
		ret = pkm_kacs_validate_existing_mappings_locked(
			new_bits, target_state, mm);
		mmap_read_unlock(mm);
		if (ret) {
			mmput(mm);
			return ret;
		}
	}

	if (new_bits != 0) {
		ret = pkm_kacs_activate_arch_mitigations(activation, new_bits);
		if (ret) {
			if (mm)
				mmput(mm);
			return ret;
		}
	}

	spin_lock_irqsave(&target_state->mitigation_lock, flags);
	target_state->mitigation_bits |= normalized_bits;
	result_bits = target_state->mitigation_bits;
	spin_unlock_irqrestore(&target_state->mitigation_lock, flags);

	if (mm)
		mmput(mm);

	if (result_mitigation_bits_out)
		*result_mitigation_bits_out = result_bits;

	trace_kacs_psb_apply(normalized_bits, result_bits, 0,
			     READ_ONCE(target_state->pip_type),
			     READ_ONCE(target_state->pip_trust),
			     KACS_PSB_APPLY_OK, 0);
	return 0;
}

static int pkm_kacs_check_wxp_mmap_core(u32 mitigation_bits,
					unsigned long prot)
{
	if ((mitigation_bits & KACS_MIT_WXP) == 0)
		return 0;
	if ((prot & PROT_WRITE) != 0 && (prot & PROT_EXEC) != 0) {
		trace_kacs_psb_wxp(mitigation_bits, 0, prot, 0, 0,
				   KACS_PSB_WXP_MMAP, -EACCES);
		return -EACCES;
	}

	return 0;
}

static int pkm_kacs_check_wxp_mprotect_core(u32 mitigation_bits,
					    unsigned long vm_flags,
					    unsigned long prot)
{
	if ((mitigation_bits & KACS_MIT_WXP) == 0)
		return 0;
	if ((prot & PROT_WRITE) != 0 && (prot & PROT_EXEC) != 0) {
		trace_kacs_psb_wxp(mitigation_bits, 0, prot, 0, 0,
				   KACS_PSB_WXP_MPROTECT, -EACCES);
		return -EACCES;
	}
	if ((vm_flags & VM_WRITE) != 0 && (prot & PROT_EXEC) != 0) {
		trace_kacs_psb_wxp(mitigation_bits, 0, prot, 0, 0,
				   KACS_PSB_WXP_MPROTECT, -EACCES);
		return -EACCES;
	}
	if ((vm_flags & VM_EXEC) != 0 && (prot & PROT_WRITE) != 0) {
		trace_kacs_psb_wxp(mitigation_bits, 0, prot, 0, 0,
				   KACS_PSB_WXP_MPROTECT, -EACCES);
		return -EACCES;
	}

	return 0;
}

/*
 * Returns 0 whether or not the binary carried a usable signature; negative
 * only when verification could not be performed. A probe failure is 0: a file
 * with no signature section is unsigned, not unverifiable.
 */
int pkm_kacs_exec_pip_from_file(const struct file *file,
				u32 *pip_type_out,
				u32 *pip_trust_out)
{
	struct pkm_kacs_signing_material material;
	int ret;

	if (!pip_type_out || !pip_trust_out)
		return -EINVAL;

	*pip_type_out = 0;
	*pip_trust_out = 0;
	if (!file)
		return 0;

	ret = pkm_kacs_signing_probe_file((struct file *)file, &material);
	if (ret)
		return 0;

	ret = pkm_kacs_exec_pip_from_material(&material, pip_type_out,
					      pip_trust_out);
	if (!ret && (*pip_type_out != 0 || *pip_trust_out != 0) &&
	    pkm_kacs_mark_signed_exec_pinned_file(file)) {
		*pip_type_out = 0;
		*pip_trust_out = 0;
	}
	pkm_kacs_signing_material_release(&material);
	return ret;
}

#ifdef CONFIG_SECURITY_PKM_KUNIT
int pkm_kacs_kunit_stage_exec_pip_from_signing_material(
	const struct pkm_kacs_kunit_signing_probe *material, u32 commit,
	struct pkm_kacs_kunit_process_state_view *out)
{
	struct pkm_kacs_signing_material material_in;
	u32 pip_type = 0;
	u32 pip_trust = 0;
	int ret;

	ret = pkm_kacs_signing_material_from_kunit_probe(material, &material_in);
	if (ret)
		return ret;

	pkm_kacs_clear_pending_exec_pip();
	pkm_kacs_exec_pip_from_material(&material_in, &pip_type, &pip_trust);
	pkm_kacs_stage_pending_exec_pip(pip_type, pip_trust);
	if (commit)
		pkm_kacs_commit_pending_exec_pip();

	if (out) {
		ret = pkm_kacs_kunit_process_state_snapshot(
			pkm_kacs_kunit_current_process_state_ptr(), out);
	} else {
		ret = 0;
	}

	if (!commit)
		pkm_kacs_clear_pending_exec_pip();
	pkm_kacs_signing_material_release(&material_in);
	return ret;
}

long pkm_kacs_kunit_exec_dumpable_after_pip(u32 pip_type,
					    u32 current_dumpable)
{
	if (current_dumpable > SUID_DUMP_ROOT)
		return -EINVAL;

	return pkm_kacs_exec_dumpable_after_pip(pip_type,
						(int)current_dumpable);
}

long pkm_kacs_kunit_get_current_dumpable(void)
{
	if (!current || !current->mm)
		return -ENODEV;

	return get_dumpable(current->mm);
}

long pkm_kacs_kunit_set_current_dumpable(u32 dumpable)
{
	if (dumpable > SUID_DUMP_ROOT)
		return -EINVAL;
	if (!current || !current->mm)
		return -ENODEV;

	set_dumpable(current->mm, dumpable);
	return 0;
}

long pkm_kacs_kunit_stage_exec_dumpable_from_signing_material(
	const struct pkm_kacs_kunit_signing_probe *material,
	u32 initial_dumpable)
{
	struct pkm_kacs_signing_material material_in;
	u32 pip_type = 0;
	u32 pip_trust = 0;
	int ret;

	if (initial_dumpable > SUID_DUMP_ROOT)
		return -EINVAL;
	if (!current || !current->mm)
		return -ENODEV;

	ret = pkm_kacs_signing_material_from_kunit_probe(material, &material_in);
	if (ret)
		return ret;

	set_dumpable(current->mm, initial_dumpable);
	pkm_kacs_clear_pending_exec_pip();
	pkm_kacs_exec_pip_from_material(&material_in, &pip_type, &pip_trust);
	pkm_kacs_stage_pending_exec_pip(pip_type, pip_trust);
	pkm_kacs_apply_pending_exec_dumpable();
	pkm_kacs_clear_pending_exec_pip();
	pkm_kacs_signing_material_release(&material_in);

	return get_dumpable(current->mm);
}

#endif

static int pkm_kacs_check_task_prctl_mitigations_core(
	u32 mitigation_bits, int option, unsigned long arg2,
	unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
	(void)arg4;
	(void)arg5;

	if ((mitigation_bits & KACS_MIT_SML) != 0 &&
	    option == PR_SET_SPECULATION_CTRL) {
		if (arg2 == PR_SPEC_STORE_BYPASS ||
		    arg2 == PR_SPEC_INDIRECT_BRANCH) {
			if (arg3 == PR_SPEC_ENABLE ||
			    arg3 == PR_SPEC_DISABLE_NOEXEC) {
				trace_kacs_psb_prctl(mitigation_bits, 0, 0, 0,
						     0, KACS_PSB_PRCTL_SML,
						     -EACCES);
				return -EACCES;
			}
		} else if (arg2 == PR_SPEC_L1D_FLUSH) {
			if (arg3 != PR_SPEC_ENABLE) {
				trace_kacs_psb_prctl(mitigation_bits, 0, 0, 0,
						     0, KACS_PSB_PRCTL_SML,
						     -EACCES);
				return -EACCES;
			}
		}
	}

#ifdef PR_SET_SHADOW_STACK_STATUS
	if ((mitigation_bits & KACS_MIT_CFIB) != 0 &&
	    option == PR_SET_SHADOW_STACK_STATUS &&
	    (arg2 & PR_SHADOW_STACK_ENABLE) == 0) {
		trace_kacs_psb_prctl(mitigation_bits, 0, 0, 0, 0,
				     KACS_PSB_PRCTL_CFIB, -EACCES);
		return -EACCES;
	}
#endif

#ifndef ARCH_SHSTK_DISABLE
#define ARCH_SHSTK_DISABLE 0x5002
#endif
#ifndef ARCH_SHSTK_UNLOCK
#define ARCH_SHSTK_UNLOCK 0x5004
#endif
	if ((mitigation_bits & KACS_MIT_CFIB) != 0 &&
	    (option == ARCH_SHSTK_DISABLE || option == ARCH_SHSTK_UNLOCK)) {
		trace_kacs_psb_prctl(mitigation_bits, 0, 0, 0, 0,
				     KACS_PSB_PRCTL_CFIB, -EACCES);
		return -EACCES;
	}

	return -ENOSYS;
}

static int pkm_kacs_check_task_prctl_pip_core(u32 pip_type, int option,
					      unsigned long arg2)
{
	if (pip_type != 0 && option == PR_SET_DUMPABLE &&
	    arg2 == SUID_DUMP_USER) {
		trace_kacs_psb_prctl(0, 0, 0, pip_type, 0, KACS_PSB_PRCTL_PIP,
				     -EACCES);
		return -EACCES;
	}

	return -ENOSYS;
}

int pkm_kacs_check_pie_bprm_core(u32 mitigation_bits,
					const u8 *buf, size_t len)
{
	u16 elf_type;

	if ((mitigation_bits & KACS_MIT_PIE) == 0)
		return 0;
	if (!buf || len < 18)
		return 0;
	if (buf[0] != 0x7f || buf[1] != 'E' || buf[2] != 'L' ||
	    buf[3] != 'F')
		return 0;

	elf_type = (u16)buf[16] | ((u16)buf[17] << 8);
	if (elf_type == ET_EXEC) {
		trace_kacs_psb_pie(mitigation_bits, 0, 0, 0, 0,
				   KACS_PSB_PIE_ET_EXEC, -EACCES);
		return -EACCES;
	}

	return 0;
}

static int pkm_kacs_lsv_verify_material_trust(
	const struct pkm_kacs_signing_material *material,
	struct pkm_kacs_signing_trust_result *result)
{
	int ret;

	if (!material || !result)
		return -EACCES;

	ret = pkm_kacs_signing_verify_builtin(material, result);
	if (ret || !result->verified)
		return -EACCES;

	return 0;
}

static int pkm_kacs_check_lsv_trust_core(
	u32 mitigation_bits, bool file_backed, bool executable_transition,
	u32 process_pip_type, u32 process_pip_trust,
	const struct pkm_kacs_signing_trust_result *result)
{
	if ((mitigation_bits & KACS_MIT_LSV) == 0)
		return 0;
	if (!executable_transition)
		return 0;
	if (!file_backed)
		return 0;
	if (!result || !result->verified)
		return -EACCES;
	if (process_pip_type != 0 &&
	    !pkm_kacs_pip_dominates(result->pip_type, result->pip_trust,
				    process_pip_type, process_pip_trust)) {
		trace_kacs_psb_lsv(mitigation_bits, 0, 0, process_pip_type,
				   process_pip_trust,
				   KACS_PSB_LSV_PIP_DOMINANCE, -EACCES);
		return -EACCES;
	}

	return 0;
}

static int pkm_kacs_check_lsv_material_core(
	u32 mitigation_bits, bool file_backed, bool executable_transition,
	u32 process_pip_type, u32 process_pip_trust,
	const struct pkm_kacs_signing_material *material)
{
	struct pkm_kacs_signing_trust_result result;
	int ret;

	if ((mitigation_bits & KACS_MIT_LSV) == 0)
		return 0;
	if (!executable_transition)
		return 0;
	if (!file_backed)
		return 0;

	ret = pkm_kacs_lsv_verify_material_trust(material, &result);
	if (ret) {
		trace_kacs_psb_lsv(mitigation_bits, 0, 0, process_pip_type,
				   process_pip_trust, KACS_PSB_LSV_VERIFY, ret);
		return ret;
	}

	return pkm_kacs_check_lsv_trust_core(
		mitigation_bits, file_backed, executable_transition,
		process_pip_type, process_pip_trust, &result);
}

static int pkm_kacs_check_lsv_file_core(u32 mitigation_bits,
					struct file *file,
					bool executable_transition,
					u32 process_pip_type,
					u32 process_pip_trust)
{
	struct pkm_kacs_signing_material material;
	int ret;

	if ((mitigation_bits & KACS_MIT_LSV) == 0)
		return 0;
	if (!executable_transition)
		return 0;
	if (!file)
		return 0;

	ret = pkm_kacs_signing_probe_file(file, &material);
	if (ret) {
		ret = ret == -ENOMEM ? -ENOMEM : -EACCES;
		trace_kacs_psb_lsv(mitigation_bits, 0, 0, process_pip_type,
				   process_pip_trust, KACS_PSB_LSV_PROBE, ret);
		return ret;
	}

	ret = pkm_kacs_check_lsv_material_core(
		mitigation_bits, true, true, process_pip_type,
		process_pip_trust, &material);
	pkm_kacs_signing_material_release(&material);
	if (ret)
		return ret;

	return pkm_kacs_mark_signed_exec_pinned_file(file);
}

#ifdef CONFIG_SECURITY_PKM_KUNIT
static int pkm_kacs_kunit_check_lsv_material_common(
	u32 mitigation_bits, bool file_backed, bool executable_transition,
	u32 process_pip_type, u32 process_pip_trust,
	const struct pkm_kacs_kunit_signing_probe *material)
{
	struct pkm_kacs_signing_material material_in;
	int ret;

	if ((mitigation_bits & KACS_MIT_LSV) == 0)
		return 0;
	if (!executable_transition)
		return 0;
	if (!file_backed)
		return 0;

	ret = pkm_kacs_signing_material_from_kunit_probe(material, &material_in);
	if (ret)
		return ret;

	ret = pkm_kacs_check_lsv_material_core(
		mitigation_bits, file_backed, executable_transition,
		process_pip_type, process_pip_trust, &material_in);
	pkm_kacs_signing_material_release(&material_in);
	return ret;
}

int pkm_kacs_kunit_check_lsv_mmap_material(
	u32 mitigation_bits, unsigned long prot, u32 process_pip_type,
	u32 process_pip_trust, u32 file_backed,
	const struct pkm_kacs_kunit_signing_probe *material)
{
	return pkm_kacs_kunit_check_lsv_material_common(
		mitigation_bits, file_backed != 0, (prot & PROT_EXEC) != 0,
		process_pip_type, process_pip_trust, material);
}

int pkm_kacs_kunit_check_lsv_mprotect_material(
	u32 mitigation_bits, unsigned long vm_flags, unsigned long prot,
	u32 process_pip_type, u32 process_pip_trust, u32 file_backed,
	const struct pkm_kacs_kunit_signing_probe *material)
{
	return pkm_kacs_kunit_check_lsv_material_common(
		mitigation_bits, file_backed != 0,
		(prot & PROT_EXEC) != 0 && (vm_flags & VM_EXEC) == 0,
		process_pip_type, process_pip_trust, material);
}
#endif /* CONFIG_SECURITY_PKM_KUNIT */

int pkm_kacs_task_prctl(int option, unsigned long arg2,
			unsigned long arg3, unsigned long arg4,
			unsigned long arg5)
{
	struct pkm_kacs_process_state *state;
	long ret;

	ret = pkm_kacs_prctl_capability_guard(option, arg2, arg3, arg4,
					      arg5);
	if (ret)
		return ret;

	state = pkm_kacs_current_process_state();
	if (!state)
		return -EACCES;

	ret = pkm_kacs_check_task_prctl_pip_core(
		READ_ONCE(state->pip_type), option, arg2);
	if (ret != -ENOSYS)
		return ret;

	return pkm_kacs_check_task_prctl_mitigations_core(
		pkm_kacs_process_state_mitigation_bits(state), option, arg2,
		arg3, arg4, arg5);
}

int pkm_kacs_mmap_file(struct file *file, unsigned long reqprot,
		       unsigned long prot, unsigned long flags)
{
	struct pkm_kacs_process_state *state;
	u32 mitigation_bits;
	int ret;

	(void)reqprot;

	state = pkm_kacs_current_process_state();
	if (!state)
		return -EACCES;
	if (file && (file->f_mode & FMODE_PATH) != 0)
		return -EBADF;
	if (pkm_kacs_copy_up_file_is_internal(file))
		return -EACCES;

	mitigation_bits = pkm_kacs_process_state_mitigation_bits(state);
	ret = pkm_kacs_check_wxp_mmap_core(mitigation_bits, prot);
	if (ret)
		return ret;

	ret = pkm_kacs_check_tlp_file_core(
		mitigation_bits, file, (prot & PROT_EXEC) != 0);
	if (ret)
		return ret;

	ret = pkm_kacs_check_lsv_file_core(
		mitigation_bits, file, (prot & PROT_EXEC) != 0,
		READ_ONCE(state->pip_type), READ_ONCE(state->pip_trust));
	if (ret)
		return ret;
	/*
	 * backing_file_mmap() is reached only after the user-visible file's
	 * snapshot check.  Keep the process mitigations above, but do not
	 * authorize or continuously audit the same operation a second time
	 * against the kernel-private provider handle.
	 */
	if (pkm_kacs_backing_file_inherited(file))
		return 0;

	return pkm_kacs_check_mmap_snapshot(file, prot, flags);
}

int pkm_kacs_file_mprotect(struct vm_area_struct *vma,
			   unsigned long reqprot, unsigned long prot)
{
	struct pkm_kacs_process_state *state;
	bool executable_transition;
	u32 mitigation_bits;
	int ret;

	(void)reqprot;
	if (!vma)
		return -EACCES;

	state = pkm_kacs_current_process_state();
	if (!state)
		return -EACCES;
	if (pkm_kacs_copy_up_file_is_internal(vma->vm_file))
		return -EACCES;

	mitigation_bits = pkm_kacs_process_state_mitigation_bits(state);
	executable_transition = (prot & PROT_EXEC) != 0 &&
				(vma->vm_flags & VM_EXEC) == 0;

	ret = pkm_kacs_check_wxp_mprotect_core(mitigation_bits,
					       vma->vm_flags, prot);
	if (ret)
		return ret;

	ret = pkm_kacs_check_tlp_file_core(
		mitigation_bits, vma->vm_file, executable_transition);
	if (ret)
		return ret;

	ret = pkm_kacs_check_lsv_file_core(
		mitigation_bits, vma->vm_file, executable_transition,
		READ_ONCE(state->pip_type), READ_ONCE(state->pip_trust));
	if (ret)
		return ret;

	return pkm_kacs_check_mprotect_snapshot(vma->vm_file, vma->vm_flags,
						prot);
}

#ifdef CONFIG_SECURITY_PKM_KUNIT
long pkm_kacs_kunit_set_current_psb(u32 requested_mitigations)
{
	struct pkm_kacs_psb_activation_context activation = {
		.task = current,
	};
	struct pkm_kacs_process_state *state;

	state = pkm_kacs_current_process_state();
	if (!state)
		return -EACCES;

	return pkm_kacs_apply_psb_mitigations_core(
		pkm_kacs_current_effective_token_ptr(), state, state,
		&activation, true,
		requested_mitigations, pkm_kacs_ibt_supported(),
		pkm_kacs_shstk_supported(), NULL);
}

long pkm_kacs_kunit_set_current_psb_with_platform(
	u32 requested_mitigations, u32 ibt_supported, u32 shstk_supported,
	u32 *result_mitigation_bits_out)
{
	struct pkm_kacs_psb_activation_context activation = {
		.task = current,
	};
	struct pkm_kacs_process_state *state;

	state = pkm_kacs_current_process_state();
	if (!state)
		return -EACCES;

	return pkm_kacs_apply_psb_mitigations_core(
		pkm_kacs_current_effective_token_ptr(), state, state,
		&activation, true, requested_mitigations,
		ibt_supported != 0, shstk_supported != 0,
		result_mitigation_bits_out);
}

long pkm_kacs_kunit_set_psb_for_subject(
	const struct pkm_kacs_kunit_set_psb_args *args,
	u32 *result_mitigation_bits_out)
{
	struct pkm_kacs_psb_activation_context activation = {
		.offline_allowed = true,
	};
	struct pkm_kacs_process_sd process_sd = {};
	struct pkm_kacs_process_state caller_state = {};
	struct pkm_kacs_process_state target_state = {};

	if (!args)
		return -EINVAL;

	process_sd.bytes = args->target_process_sd_ptr;
	process_sd.len = args->target_process_sd_len;
	refcount_set(&process_sd.refs, 1);
	caller_state.pip_type = args->caller_pip_type;
	caller_state.pip_trust = args->caller_pip_trust;
	target_state.pip_type = args->target_pip_type;
	target_state.pip_trust = args->target_pip_trust;
	target_state.mitigation_bits = args->initial_mitigation_bits;
	target_state.process_sd = &process_sd;
	activation.kunit_fail_activation_bits = args->kunit_fail_activation_bits;
	spin_lock_init(&target_state.mitigation_lock);

	return pkm_kacs_apply_psb_mitigations_core(
		args->subject_token, &caller_state, &target_state,
		&activation,
		args->self_target != 0, args->requested_mitigations,
		args->ibt_supported != 0, args->shstk_supported != 0,
		result_mitigation_bits_out);
}

int pkm_kacs_kunit_check_no_child_process(u32 mitigation_bits,
					  u64 clone_flags)
{
	return pkm_kacs_clone_is_blocked_by_no_child(mitigation_bits,
						     clone_flags) ?
		       -EACCES :
		       0;
}

int pkm_kacs_kunit_check_wxp_mmap(u32 mitigation_bits, unsigned long prot)
{
	return pkm_kacs_check_wxp_mmap_core(mitigation_bits, prot);
}

int pkm_kacs_kunit_check_wxp_mprotect(u32 mitigation_bits,
				      unsigned long vm_flags,
				      unsigned long prot)
{
	return pkm_kacs_check_wxp_mprotect_core(mitigation_bits, vm_flags,
						prot);
}

int pkm_kacs_kunit_check_wxp_existing_vma(u32 mitigation_bits,
					  unsigned long vm_flags)
{
	return pkm_kacs_check_wxp_existing_vma_core(mitigation_bits,
						    vm_flags);
}
#endif /* CONFIG_SECURITY_PKM_KUNIT */

#ifdef CONFIG_SECURITY_PKM_KUNIT
int pkm_kacs_kunit_check_task_prctl_mitigations(
	u32 mitigation_bits, int option, unsigned long arg2,
	unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
	return pkm_kacs_check_task_prctl_mitigations_core(
		mitigation_bits, option, arg2, arg3, arg4, arg5);
}

int pkm_kacs_kunit_check_task_prctl_pip(u32 pip_type, int option,
					unsigned long arg2)
{
	return pkm_kacs_check_task_prctl_pip_core(pip_type, option, arg2);
}

int pkm_kacs_kunit_check_pie_bprm(u32 mitigation_bits, const u8 *buf,
				  size_t len)
{
	return pkm_kacs_check_pie_bprm_core(mitigation_bits, buf, len);
}
#endif /* CONFIG_SECURITY_PKM_KUNIT */

SYSCALL_DEFINE2(kacs_set_psb, int, pidfd, u32, mitigations)
{
	struct pkm_kacs_psb_activation_context activation = {};
	struct pkm_kacs_process_state *caller_state;
	struct pkm_kacs_process_state *target_state;
	const void *subject_token;
	struct task_struct *task = NULL;
	struct pid *pid;
	unsigned int pidfd_flags = 0;
	bool self_target;
	long ret;

	subject_token = pkm_kacs_current_effective_token_ptr();
	caller_state = pkm_kacs_current_process_state();
	if (!subject_token || !caller_state)
		return -EACCES;

	if (pidfd == -1) {
		target_state = caller_state;
		self_target = true;
		activation.task = current;
	} else {
		pid = pidfd_get_pid(pidfd, &pidfd_flags);
		if (IS_ERR(pid))
			return PTR_ERR(pid);
		(void)pidfd_flags;

		task = get_pid_task(pid, PIDTYPE_PID);
		put_pid(pid);
		if (!task)
			return -ESRCH;
		if (!task->security) {
			put_task_struct(task);
			return -EACCES;
		}

		target_state = pkm_kacs_task(task)->process_state;
		self_target = target_state == caller_state;
		activation.task = task;
	}

	ret = pkm_kacs_apply_psb_mitigations_core(
		subject_token, caller_state, target_state, &activation,
		self_target,
		mitigations, pkm_kacs_ibt_supported(),
		pkm_kacs_shstk_supported(), NULL);
	if (task)
		put_task_struct(task);

	return ret;
}
