# KACS Comprehensive Test Corpus

**Generated:** 2026-03-22
**Source:** z_proposals/KACS.md (12,564 lines, 18 sections)
**Purpose:** Every testable assertion in the KACS spec, mapped to either
Cargo (pure Rust unit tests) or Provium (kernel VM integration tests).

## Summary

| Section | Cargo | Provium | Total |
|---|---|---|---|
| §2+§10 Definitions/Privileges | 200 | 88 | 288 |
| §5+§6 Compat/Overview | 68 | 124 | 192 |
| §7+§8 Tokens/PSB | 260 | 109 | 369 |
| §9 Security Descriptors | 208 | 19 | 227 |
| §11 AccessCheck pt1 | 364 | 20 | 384 |
| §11 AccessCheck pt2 | 426 | 34 | 460 |
| §12+§13 Impersonation/PIP | 37 | 81 | 118 |
| §14 FACS pt1 | ~35 | ~223 | 258 |
| §14 FACS pt2 | 11 | 194 | 205 |
| §15+§16+§17 Interface/Deroot/Audit | 65 | 378 | 443 |
| §18 Testing Strategy | 108 | 75 | 183 |
| **Total (before dedup)** | **~1,782** | **~1,345** | **~3,127** |


---

# Section 2: Definitions + Section 10: Privileges

## KACS Test Corpus: Section 2 (Definitions) and Section 10 (Privileges)

---

### 2.1 SID Format (from Definitions)

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 1 | `sid_format_prefix_s1` | SID string format starts with `S-1-` followed by authority and sub-authorities: `S-1-{authority}-{sub1}-{sub2}-...` | §2 line 130 | Cargo |
| 2 | `sid_binary_compatible_with_windows` | SID binary representation is byte-for-byte compatible with Windows SIDs -- same bytes, same comparison rules, same well-known values | §2 line 135-136 | Cargo |
| 3 | `sid_system_is_s1_5_18` | Well-known SYSTEM SID is S-1-5-18 | §2 line 131 | Cargo |
| 4 | `sid_administrators_is_s1_5_32_544` | Well-known Administrators SID is S-1-5-32-544 | §2 line 131 | Cargo |
| 5 | `sid_domain_user_format` | Domain user SIDs follow pattern S-1-5-21-{domain sub-authorities}-{RID} | §2 line 131-132 | Cargo |
| 6 | `sid_logon_format_s1_5_5_x_y` | LogonSession SID format is S-1-5-5-{high}-{low} | §2 line 242 | Cargo |
| 7 | `sid_creator_owner_is_s1_3_0` | CREATOR OWNER SID is S-1-3-0 | §9.5 line 3584 | Cargo |
| 8 | `sid_creator_group_is_s1_3_1` | CREATOR GROUP SID is S-1-3-1 | §9.5 line 3591 | Cargo |
| 9 | `sid_owner_rights_is_s1_3_4` | OWNER RIGHTS SID is S-1-3-4 | §2 line 151, §9.7 line 3778 | Cargo |
| 10 | `sid_everyone_is_s1_1_0` | Everyone SID is S-1-1-0 | §9.3 line 3404 | Cargo |
| 11 | `sid_integrity_medium_is_s1_16_8192` | Medium integrity SID is S-1-16-8192 | §9.3 line 3389 | Cargo |
| 12 | `sid_integrity_high_is_s1_16_12288` | High integrity SID is S-1-16-12288 | §9.3 line 3389 | Cargo |
| 13 | `sid_integrity_system_is_s1_16_16384` | System integrity SID is S-1-16-16384 | §11 line 11683 | Cargo |
| 14 | `sid_comparison_is_byte_equality` | SID comparison is byte-for-byte equality (same comparison rules as Windows) | §2 line 136 | Cargo |
| 15 | `sid_parse_roundtrip` | SID string-to-binary-to-string roundtrip produces the original string | §2 line 130-136 | Cargo |
| 16 | `sid_structurally_wellformed_validation` | CreateToken validates all SIDs are structurally well-formed | §7.5 line 2341 | Cargo |

### 2.2 Token Definition (from Definitions)

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 17 | `token_contains_user_sid` | Token contains a user SID (primary identity) | §2 line 108-109 | Cargo |
| 18 | `token_contains_group_sids` | Token contains group SIDs | §2 line 109 | Cargo |
| 19 | `token_contains_privilege_bitmask` | Token contains a privilege bitmask (u64) | §2 line 110, §7.3 line 2086 | Cargo |
| 20 | `token_contains_integrity_level` | Token contains an integrity level (Untrusted, Low, Medium, High, System) | §2 line 110, §7.3 line 2079 | Cargo |
| 21 | `token_contains_impersonation_level` | Token contains an impersonation level (Anonymous, Identification, Impersonation, Delegation) | §2 line 110, §7.3 line 2073 | Cargo |
| 22 | `token_identity_immutable` | Token identity (SIDs, type, level) is immutable after creation | §2 line 112-113 | Cargo |
| 23 | `token_privileges_atomically_adjustable` | Token privilege enable/disable state is atomically adjustable at runtime | §2 line 113 | Cargo |
| 24 | `token_groups_atomically_adjustable` | Token group enabled state is atomically adjustable at runtime | §2 line 113 | Cargo |
| 25 | `token_never_null` | Every thread has a token -- there are no NULL tokens | §2 line 114 | Provium |
| 26 | `token_is_sole_identity_mechanism` | Tokens are the sole identity mechanism; UIDs and GIDs play no role in access decisions | §2 line 115-116 | Provium |

### 2.3 Primary vs Impersonation Token (from Definitions)

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 27 | `primary_token_inherited_on_fork` | Primary token is inherited by child processes on fork | §2 line 119 | Provium |
| 28 | `primary_token_set_once_at_creation` | Primary token is set once at process creation (or via SeAssignPrimaryTokenPrivilege) | §2 line 120-121 | Provium |
| 29 | `primary_token_in_real_cred` | Primary token is stored in task->real_cred | §2 line 121 | Provium |
| 30 | `impersonation_token_overrides_primary` | Impersonation token overrides primary token for access control decisions | §2 line 124 | Provium |
| 31 | `impersonation_token_per_thread` | Impersonation token only affects the thread that set it, not other threads in the process | §2 line 126-127 | Provium |
| 32 | `impersonation_token_in_cred` | Impersonation token is stored in task->cred (effective/subjective credential) | §2 line 125-126 | Provium |

### 2.4 Security Descriptor Definition (from Definitions)

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 33 | `sd_contains_owner_sid` | SD contains an owner SID | §2 line 140 | Cargo |
| 34 | `sd_contains_primary_group_sid` | SD contains a primary group SID | §2 line 141 | Cargo |
| 35 | `sd_contains_dacl` | SD contains a DACL (Discretionary Access Control List) | §2 line 141-142 | Cargo |
| 36 | `sd_contains_optional_sacl` | SD optionally contains a SACL (System Access Control List) | §2 line 142-143 | Cargo |
| 37 | `sd_binary_format_windows_compatible` | SD uses Windows self-relative binary format, byte-for-byte compatible | §2 line 147-148, §9.1 line 3136-3138 | Cargo |
| 38 | `sd_self_relative_format_header` | SD self-relative format: 20-byte header (revision, control flags, four 32-bit offsets) followed by owner SID, group SID, SACL, DACL at specified offsets | §9.1 line 3197-3202 | Cargo |
| 39 | `sd_self_relative_no_pointers` | Self-relative format packs everything into a contiguous byte buffer -- no pointers, no external references | §9.1 line 3200-3201 | Cargo |
| 40 | `sd_only_self_relative_format` | KACS uses the self-relative format exclusively; there is no absolute format | §9.1 line 3204-3205 | Cargo |
| 41 | `sd_owner_implicit_read_control_write_dac` | By default owner receives implicit READ_CONTROL + WRITE_DAC | §2 line 149-150 | Cargo |
| 42 | `sd_owner_rights_ace_overrides_implicit` | OWNER RIGHTS ACE (S-1-3-4) in the DACL overrides owner implicit grants | §2 line 151-152 | Cargo |
| 43 | `sd_attached_to_files_in_xattr` | SDs on files stored in xattr (`security.peios.sd`) | §2 line 145, §9.11 line 3896 | Provium |
| 44 | `sd_max_size_64kb` | Architectural maximum SD size is 64 KB (ACL header AclSize is u16) | §9.11 line 3907 | Cargo |

### 2.5 ACL Definition (from Definitions)

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 45 | `dacl_empty_denies_all` | Empty DACL (present but zero entries) denies all access (except owner implicit rights) | §2 line 165-166, §9.8 line 3824-3827 | Cargo |
| 46 | `dacl_null_grants_all` | NULL DACL (absent, DP flag clear) grants all access | §2 line 166-167, §9.8 line 3818-3822 | Cargo |
| 47 | `dacl_walked_sequentially` | AccessCheck walks the DACL sequentially from first ACE to last | §2 line 163-164, §11.3 line 3472-3473 | Cargo |
| 48 | `dacl_respects_order_as_given` | Evaluator respects whatever ACE order is present (does not reorder) | §2 line 167-168 | Cargo |
| 49 | `dacl_deny_before_allow_canonical` | Canonical ordering: explicit deny ACEs before explicit allow ACEs before inherited deny before inherited allow | §9.4 line 3486-3496 | Cargo |
| 50 | `dacl_non_canonical_not_rejected` | KACS does not reject non-canonical DACLs -- evaluates whatever order it receives | §9.4 line 3481-3482 | Cargo |
| 51 | `null_dacl_grants_valid_rights_not_0xffffffff` | NULL DACL grants all valid rights bounded to GenericMapping(GENERIC_ALL), not raw 0xFFFFFFFF | §11.3 line 4464-4465 | Cargo |

### 2.6 ACE Definition (from Definitions)

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 52 | `ace_header_4_bytes` | ACE header is 4 bytes: AceType (1), AceFlags (1), AceSize (2) | §9.3 line 3305-3310 | Cargo |
| 53 | `ace_size_multiple_of_4` | AceSize must be a multiple of 4 | §9.3 line 3310 | Cargo |
| 54 | `ace_allowed_type_0x00` | ACCESS_ALLOWED_ACE type value is 0x00 | §9.3 line 3323 | Cargo |
| 55 | `ace_denied_type_0x01` | ACCESS_DENIED_ACE type value is 0x01 | §9.3 line 3324 | Cargo |
| 56 | `ace_audit_type_0x02` | SYSTEM_AUDIT_ACE type value is 0x02 | §9.3 line 3382 | Cargo |
| 57 | `ace_alarm_type_0x03` | SYSTEM_ALARM_ACE type value is 0x03 | §9.3 line 3450 | Cargo |
| 58 | `ace_compound_type_0x04_reserved` | ACCESS_ALLOWED_COMPOUND_ACE (0x04) is reserved and not implemented | §9.3 line 3468 | Cargo |
| 59 | `ace_allowed_object_type_0x05` | ACCESS_ALLOWED_OBJECT_ACE type value is 0x05 | §9.3 line 3335 | Cargo |
| 60 | `ace_denied_object_type_0x06` | ACCESS_DENIED_OBJECT_ACE type value is 0x06 | §9.3 line 3336 | Cargo |
| 61 | `ace_audit_object_type_0x07` | SYSTEM_AUDIT_OBJECT_ACE type value is 0x07 | §9.3 line 3383 | Cargo |
| 62 | `ace_alarm_object_type_0x08` | SYSTEM_ALARM_OBJECT_ACE type value is 0x08 | §9.3 line 3451 | Cargo |
| 63 | `ace_allowed_callback_type_0x09` | ACCESS_ALLOWED_CALLBACK_ACE type value is 0x09 | §9.3 line 3356 | Cargo |
| 64 | `ace_denied_callback_type_0x0a` | ACCESS_DENIED_CALLBACK_ACE type value is 0x0A | §9.3 line 3357 | Cargo |
| 65 | `ace_allowed_callback_object_type_0x0b` | ACCESS_ALLOWED_CALLBACK_OBJECT_ACE type value is 0x0B | §9.3 line 3358 | Cargo |
| 66 | `ace_denied_callback_object_type_0x0c` | ACCESS_DENIED_CALLBACK_OBJECT_ACE type value is 0x0C | §9.3 line 3359 | Cargo |
| 67 | `ace_audit_callback_type_0x0d` | SYSTEM_AUDIT_CALLBACK_ACE type value is 0x0D | §9.3 line 3384 | Cargo |
| 68 | `ace_alarm_callback_type_0x0e` | SYSTEM_ALARM_CALLBACK_ACE type value is 0x0E | §9.3 line 3452 | Cargo |
| 69 | `ace_audit_callback_object_type_0x0f` | SYSTEM_AUDIT_CALLBACK_OBJECT_ACE type value is 0x0F | §9.3 line 3385 | Cargo |
| 70 | `ace_alarm_callback_object_type_0x10` | SYSTEM_ALARM_CALLBACK_OBJECT_ACE type value is 0x10 | §9.3 line 3453 | Cargo |
| 71 | `ace_mandatory_label_type_0x11` | SYSTEM_MANDATORY_LABEL_ACE type value is 0x11 | §9.3 line 3397 | Cargo |
| 72 | `ace_resource_attribute_type_0x12` | SYSTEM_RESOURCE_ATTRIBUTE_ACE type value is 0x12 | §9.3 line 3409 | Cargo |
| 73 | `ace_scoped_policy_id_type_0x13` | SYSTEM_SCOPED_POLICY_ID_ACE type value is 0x13 | §9.3 line 3422 | Cargo |
| 74 | `ace_process_trust_label_type_0x14` | SYSTEM_PROCESS_TRUST_LABEL_ACE type value is 0x14 | §9.3 line 3435 | Cargo |
| 75 | `ace_mandatory_label_at_most_one_per_sacl` | At most one mandatory label ACE per SACL | §9.3 line 3388 | Cargo |
| 76 | `ace_resource_attribute_sid_is_everyone` | Resource attribute ACE SID is always the Everyone SID (S-1-1-0) | §9.3 line 3403-3404 | Cargo |
| 77 | `ace_object_contains_guids` | Object-type ACEs contain a flags field indicating which GUIDs (ObjectType, InheritedObjectType) are present, plus up to two GUIDs and a SID | §9.3 line 3329-3331 | Cargo |
| 78 | `ace_object_guid_absent_behaves_as_basic` | When ObjectType or InheritedObjectType GUID is absent, the ACE behaves like a basic ACE for that dimension | §9.3 line 3341-3342 | Cargo |
| 79 | `ace_dacl_must_not_contain_sacl_types` | DACL must not contain SACL ACE types and vice versa -- mixing produces undefined behavior | §9.3 line 3371-3372 | Cargo |
| 80 | `ace_inherit_only_skipped_in_dacl_walk` | ACEs with INHERIT_ONLY flag are skipped during DACL walk (exist solely to propagate to children) | §11.3 line 4448-4450 | Cargo |

### 2.7 Access Mask Layout (from Definitions)

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 81 | `mask_specific_rights_bits_0_to_15` | Object-specific rights occupy bits 0-15 | §2 line 191, §9.2 line 3222 | Cargo |
| 82 | `mask_standard_rights_bits_16_to_20` | Standard rights occupy bits 16-20 | §2 line 192, §9.2 line 3230 | Cargo |
| 83 | `mask_delete_bit_16` | DELETE is bit 16 | §9.2 line 3234 | Cargo |
| 84 | `mask_read_control_bit_17` | READ_CONTROL is bit 17 | §9.2 line 3235 | Cargo |
| 85 | `mask_write_dac_bit_18` | WRITE_DAC is bit 18 | §9.2 line 3236 | Cargo |
| 86 | `mask_write_owner_bit_19` | WRITE_OWNER is bit 19 | §9.2 line 3237 | Cargo |
| 87 | `mask_synchronize_bit_20` | SYNCHRONIZE is bit 20 | §9.2 line 3238 | Cargo |
| 88 | `mask_bits_21_to_23_reserved` | Bits 21-23 are reserved | §2 line 197 | Cargo |
| 89 | `mask_access_system_security_bit_24` | ACCESS_SYSTEM_SECURITY is bit 24 | §2 line 193, §9.2 line 3244 | Cargo |
| 90 | `mask_maximum_allowed_bit_25` | MAXIMUM_ALLOWED is bit 25 | §2 line 194, §9.2 line 3245 | Cargo |
| 91 | `mask_bits_26_to_27_reserved` | Bits 26-27 are reserved | §2 line 198 | Cargo |
| 92 | `mask_generic_all_bit_28` | GENERIC_ALL is bit 28 | §9.2 line 3253 | Cargo |
| 93 | `mask_generic_execute_bit_29` | GENERIC_EXECUTE is bit 29 | §9.2 line 3254 | Cargo |
| 94 | `mask_generic_write_bit_30` | GENERIC_WRITE is bit 30 | §9.2 line 3255 | Cargo |
| 95 | `mask_generic_read_bit_31` | GENERIC_READ is bit 31 | §9.2 line 3256 | Cargo |
| 96 | `mask_maximum_allowed_cannot_appear_in_ace` | MAXIMUM_ALLOWED cannot appear in an ACE -- it is a request flag only | §9.2 line 3245, §11.5 line 4560 | Cargo |
| 97 | `mask_generic_mapped_once_at_request_time` | Generic bits in requested mask are mapped to object-specific bits once, then cleared; DACL walk operates on specific+standard bits only | §9.2 line 3264-3268 | Cargo |
| 98 | `mask_ace_generic_bits_mapped_at_eval_time` | (Divergence) Peios maps each ACE's mask via MapGenericBits at eval time using a local variable -- ACE itself never mutated | §9.2 line 3271-3282, §11.3 line 4452-4458 | Cargo |

### 2.8 AccessCheck Definition (from Definitions)

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 99 | `accesscheck_three_inputs` | AccessCheck takes three inputs: token (who), SD (policy), desired access mask (what) | §2 line 178-179 | Cargo |
| 100 | `accesscheck_returns_granted_or_denial` | AccessCheck returns the set of access rights actually granted, or denial | §2 line 184-186 | Cargo |
| 101 | `accesscheck_single_function_for_all_decisions` | Every access control decision passes through AccessCheck -- file opens, registry reads, IPC, signals, network binds | §2 line 186-187 | Provium |
| 102 | `accesscheck_evaluates_privilege_gates_first` | AccessCheck evaluates privilege gates (ACCESS_SYSTEM_SECURITY) | §2 line 180 | Cargo |
| 103 | `accesscheck_evaluates_integrity_policy` | AccessCheck evaluates integrity policy (MIC and PIP) | §2 line 180 | Cargo |
| 104 | `accesscheck_evaluates_dacl_walk` | AccessCheck evaluates DACL walk (owner implicit rights, deny/allow ACEs, conditional expressions) | §2 line 181 | Cargo |
| 105 | `accesscheck_evaluates_post_dacl_privilege_overrides` | AccessCheck evaluates post-DACL privilege overrides (SeTakeOwnershipPrivilege) | §2 line 182 | Cargo |
| 106 | `accesscheck_first_writer_wins` | DACL walk uses first-writer-wins: deny ACE after allow ACE for same bits has no effect (bits already granted) | §9.4 line 3474-3476, §11.3 line 4420-4423 | Cargo |
| 107 | `accesscheck_short_circuit_when_all_bits_decided` | DACL walk can stop early when all bits in desired mask are decided | §11.3 line 4476-4479 | Cargo |
| 108 | `accesscheck_no_short_circuit_maximum_allowed` | Short-circuit does not apply in MAXIMUM_ALLOWED mode; walk runs to completion | §11.3 line 4479-4481 | Cargo |

### 2.9 Impersonation Level Definition (from Definitions)

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 109 | `impersonation_level_anonymous` | Anonymous level: identity is hidden; server cannot identify the caller | §2 line 217-218 | Cargo |
| 110 | `impersonation_level_identification` | Identification level: server can identify caller but cannot act as them | §2 line 219-220 | Cargo |
| 111 | `impersonation_level_impersonation` | Impersonation level: server can act as caller for all local operations including local IPC; cannot forward across machine boundaries | §2 line 221-224 | Cargo |
| 112 | `impersonation_level_delegation` | Delegation level: server can forward caller's identity to remote services on other machines | §2 line 225-227 | Cargo |
| 113 | `impersonation_level_order` | Impersonation levels form a total order: Anonymous < Identification < Impersonation < Delegation | §2 line 215-227 | Cargo |

### 2.10 Integrity Level / MIC Definition (from Definitions)

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 114 | `integrity_levels_five_values` | Five integrity levels exist: Untrusted, Low, Medium, High, System | §2 line 231, §11 line 5317, §7.3 line 2079 | Cargo |
| 115 | `integrity_level_strict_total_order` | Integrity levels form a strict total order: System > High > Medium > Low > Untrusted | §11 line 5348 | Cargo |
| 116 | `mic_evaluated_before_dacl` | MIC is evaluated before the DACL walk | §2 line 233 | Cargo |
| 117 | `mic_blocks_write_if_below_label` | If token integrity is below object label, write access is denied regardless of DACL | §2 line 233-237, §11 line 5325-5326 | Cargo |
| 118 | `mic_optionally_blocks_read` | Object label can additionally block reads (no-read-up) for processes below its integrity | §2 line 234, §11 line 5332-5333 | Cargo |
| 119 | `mic_optionally_blocks_execute` | Object label can additionally block execution (no-execute-up) for processes below its integrity | §2 line 234, §11 line 5333 | Cargo |
| 120 | `mic_default_is_no_write_up_only` | Default MIC behavior is no-write-up only (most common case) | §11 line 5325, 5335-5336 | Cargo |
| 121 | `mic_default_label_is_medium` | Unlabeled objects default to Medium integrity with no-write-up | §11 line 5361-5365 | Cargo |
| 122 | `mic_does_not_constrain_privileges` | MIC does not revoke rights granted by privileges -- it constrains what the DACL can grant | §11 line 5369-5378 | Cargo |
| 123 | `mic_label_in_sacl` | Object integrity label is stored as a SYSTEM_MANDATORY_LABEL_ACE in the SACL | §2 line 232, §9.3 line 3387-3390 | Cargo |
| 124 | `mic_label_sid_encodes_level` | Label SID encodes the integrity level (e.g., S-1-16-8192 = Medium) | §9.3 line 3389 | Cargo |
| 125 | `mic_label_mask_encodes_policy` | Label ACE access mask encodes which operations (write, read, execute) are blocked | §9.3 line 3390-3391 | Cargo |

### 2.11 Ownership Definition (from Definitions)

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 126 | `ownership_implicit_read_control` | Owner receives implicit READ_CONTROL regardless of DACL | §2 line 283-284, §9.7 line 3769 | Cargo |
| 127 | `ownership_implicit_write_dac` | Owner receives implicit WRITE_DAC regardless of DACL | §2 line 283-284, §9.7 line 3770 | Cargo |
| 128 | `ownership_implicit_before_dacl_walk` | Owner implicit rights granted before DACL walk -- deny ACEs cannot override them | §11.4 line 4503-4508 | Cargo |
| 129 | `ownership_owner_rights_suppress_implicit` | Presence of any OWNER RIGHTS ACE (S-1-3-4) in DACL suppresses the implicit READ_CONTROL + WRITE_DAC grant entirely | §2 line 285-286, §11.4 line 4511-4514 | Cargo |
| 130 | `ownership_owner_rights_prescan` | OWNER RIGHTS check is a pre-scan of DACL before implicit grant, before walk | §11.4 line 4523-4524 | Cargo |
| 131 | `ownership_owner_rights_prescan_checks_presence_not_condition` | Pre-scan checks for ACE presence only, not whether conditional expression evaluates to TRUE | §11.4 line 4530-4532 | Cargo |
| 132 | `ownership_owner_rights_restrict_pattern` | Allow ACE for S-1-3-4 with only READ_CONTROL restricts owner to read-only on the SD | §9.7 line 3794-3796 | Cargo |
| 133 | `ownership_owner_rights_expand_pattern` | Allow ACE for S-1-3-4 with READ_CONTROL + WRITE_DAC + DELETE expands owner rights | §9.7 line 3791-3793 | Cargo |
| 134 | `ownership_owner_rights_suppress_pattern` | Deny ACE for S-1-3-4 with READ_CONTROL + WRITE_DAC suppresses owner rights entirely | §9.7 line 3788-3790 | Cargo |
| 135 | `ownership_transfer_requires_write_owner` | Changing object owner requires WRITE_OWNER | §9.7 line 3806 | Cargo |
| 136 | `ownership_take_ownership_privilege_grants_write_owner` | SeTakeOwnershipPrivilege grants WRITE_OWNER on any object regardless of DACL | §9.7 line 3810-3811 | Cargo |

### 2.12 ACL Revision (from §9.9)

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 137 | `acl_revision_0x02_basic_types` | ACL_REVISION (0x02) permits basic ACE types (0x00, 0x01, 0x02, 0x03), mandatory label (0x11), resource attribute (0x12), scoped policy ID (0x13), process trust label (0x14) | §9.9 line 3846-3849 | Cargo |
| 138 | `acl_revision_0x04_ds_types` | ACL_REVISION_DS (0x04) additionally permits object-type ACEs (0x05-0x08), callback ACEs (0x09-0x0D, 0x0F), and alarm callback/object variants (0x0E, 0x10) | §9.9 line 3850-3852 | Cargo |
| 139 | `acl_revision_both_accepted` | KACS accepts both ACL_REVISION and ACL_REVISION_DS | §9.9 line 3855 | Cargo |
| 140 | `acl_revision_set_to_minimum` | When creating new ACLs, revision is set to minimum required: ACL_REVISION if only basic ACEs, ACL_REVISION_DS if object-type or callback ACEs included | §9.9 line 3855-3858 | Cargo |

### 2.13 SD Control Flags (from §9.10)

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 141 | `control_flag_dp_bit_2` | SE_DACL_PRESENT (DP) is bit 2 | §9.10 line 3867 | Cargo |
| 142 | `control_flag_sp_bit_4` | SE_SACL_PRESENT (SP) is bit 4 | §9.10 line 3868 | Cargo |
| 143 | `control_flag_dd_bit_3` | SE_DACL_DEFAULTED (DD) is bit 3 | §9.10 line 3869 | Cargo |
| 144 | `control_flag_sd_bit_5` | SE_SACL_DEFAULTED (SD) is bit 5 | §9.10 line 3870 | Cargo |
| 145 | `control_flag_od_bit_0` | SE_OWNER_DEFAULTED (OD) is bit 0 | §9.10 line 3871 | Cargo |
| 146 | `control_flag_gd_bit_1` | SE_GROUP_DEFAULTED (GD) is bit 1 | §9.10 line 3872 | Cargo |
| 147 | `control_flag_di_bit_10` | SE_DACL_AUTO_INHERITED (DI) is bit 10 | §9.10 line 3873 | Cargo |
| 148 | `control_flag_si_bit_11` | SE_SACL_AUTO_INHERITED (SI) is bit 11 | §9.10 line 3874 | Cargo |
| 149 | `control_flag_pd_bit_12` | SE_DACL_PROTECTED (PD) is bit 12 -- DACL is protected from inheritance | §9.10 line 3875 | Cargo |
| 150 | `control_flag_ps_bit_13` | SE_SACL_PROTECTED (PS) is bit 13 | §9.10 line 3876 | Cargo |
| 151 | `control_flag_sr_bit_15` | SE_SELF_RELATIVE (SR) is bit 15 -- always set for stored SDs | §9.10 line 3877 | Cargo |
| 152 | `control_flag_dt_bit_6` | SE_DACL_TRUSTED (DT) is bit 6 | §9.10 line 3878 | Cargo |
| 153 | `control_flag_ss_bit_7` | SE_SERVER_SECURITY (SS) is bit 7 | §9.10 line 3879 | Cargo |
| 154 | `control_flag_rm_bit_14` | SE_RM_CONTROL_VALID (RM) is bit 14 | §9.10 line 3880 | Cargo |

### 2.14 GenericMapping (from §2 and §9.2)

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 155 | `generic_mapping_provided_by_caller` | GenericMapping is provided by the caller at AccessCheck time, not by KACS | §2 line 277-278, §9.2 line 3284-3294 | Cargo |
| 156 | `generic_mapping_generic_read_file_example` | GENERIC_READ on file maps to FILE_READ_DATA + FILE_READ_ATTRIBUTES + READ_CONTROL | §2 line 273-274 | Cargo |
| 157 | `generic_bits_cleared_after_mapping` | After mapping generic bits to specific bits, generic bits are cleared from the request mask | §9.2 line 3267 | Cargo |

### 2.15 SID Matching in DACL Walk

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 158 | `sid_match_user_sid` | ACE SID matches if it equals the token's user SID | §11.3 line 4425-4426 | Cargo |
| 159 | `sid_match_group_sid` | ACE SID matches if it equals a group SID on the token | §11.3 line 4426 | Cargo |
| 160 | `sid_match_allow_requires_enabled` | For allow ACEs, only groups that are SE_GROUP_ENABLED and not deny-only match | §11.3 line 4427-4428 | Cargo |
| 161 | `sid_match_deny_includes_deny_only` | For deny ACEs, both enabled groups and SE_GROUP_USE_FOR_DENY_ONLY groups match | §11.3 line 4428-4430 | Cargo |
| 162 | `sid_match_deny_only_overrides_enabled` | Deny-only flag overrides enabled check: deny-only group always participates in deny matching regardless of enabled state | §11.3 line 4430-4432 | Cargo |
| 163 | `sid_match_neither_flag_no_match` | A group with neither ENABLED nor USE_FOR_DENY_ONLY set does not participate in any matching | §11.3 line 4432-4433 | Cargo |
| 164 | `sid_match_user_deny_only` | When token user SID is deny-only, it matches deny ACEs but not allow ACEs | §11.3 line 4438-4441 | Cargo |
| 165 | `sid_match_mandatory_group_cannot_be_disabled` | Mandatory groups (SE_GROUP_MANDATORY) cannot be disabled | §7.3 line 2064, line 2435 | Cargo |
| 166 | `sid_match_deny_only_cannot_be_reverted` | Deny-only groups (SE_GROUP_USE_FOR_DENY_ONLY) are permanently set via FilterToken, cannot be reverted | §7.3 line 2065-2066 | Cargo |

### 2.16 Token Privilege Bitmask Fields (from §7.3)

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 167 | `privilege_present_u64` | privileges_present is a u64 bitmask -- bits can be cleared (permanent removal) but never set | §7.3 line 2086 | Cargo |
| 168 | `privilege_enabled_u64` | privileges_enabled is a u64 bitmask -- toggleable for non-removed privileges | §7.3 line 2087 | Cargo |
| 169 | `privilege_enabled_by_default_u64` | privileges_enabled_by_default is a u64 -- the reset position for AdjustTokenPrivileges | §7.3 line 2088 | Cargo |
| 170 | `privilege_used_u64` | privileges_used is a u64 bitmask -- set when a privilege is exercised, audit trail | §7.3 line 2089 | Cargo |
| 171 | `privilege_removal_clears_all_three_masks` | Removing a privilege clears the bit in present, enabled, and enabled_by_default | §7.3 line 2093-2094 | Cargo |
| 172 | `privilege_lifecycle` | Privilege lifecycle: present+disabled -> enabled -> used -> optionally disabled -> optionally permanently removed | §7.3 line 2091-2094 | Cargo |
| 173 | `privilege_present_bits_never_set_after_creation` | Bits in privileges_present can only be cleared, never set after token creation | §7.3 line 2086 | Cargo |

---

### 10.1 Privileges Not Capabilities

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 174 | `privilege_check_is_identity_aware` | Privilege check is always "does this principal hold this privilege?" -- answer differs per principal (unlike capabilities) | §10.1 line 3978-3981 | Provium |
| 175 | `capabilities_neutralized_via_switchboard` | Linux capabilities neutralized: every process gets full capability set so Linux checks pass; LSM hooks enforce KACS privileges instead | §10.1 line 4001-4005 | Provium |
| 176 | `privilege_has_enable_disable_lifecycle` | Privileges have explicit enabled/disabled state, unlike capabilities which are binary (have or not) | §10.1 line 3988-3991 | Cargo |
| 177 | `privilege_usage_tracked` | privileges_used field records which privileges have been exercised; privilege use generates audit events | §10.1 line 3995-3999 | Cargo |

### 10.2 Privilege Model

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 178 | `privilege_assigned_at_token_creation` | Privileges resolved at token creation time -- no runtime privilege grants | §10.2 line 4011-4016 | Cargo |
| 179 | `privilege_no_add_after_creation` | If a privilege is not on the token at birth, it cannot be added later | §10.2 line 4015-4016 | Cargo |
| 180 | `privilege_most_start_disabled` | Most privileges start disabled (present but not active) | §10.2 line 4018-4020 | Cargo |
| 181 | `privilege_must_enable_before_use` | Before using a privilege, holder enables it via AdjustPrivileges | §10.2 line 4023-4025 | Cargo |
| 182 | `privilege_check_requires_present_and_enabled` | Kernel checks whether token holds the privilege (present AND enabled) before permitting operation | §10.2 line 4054 | Cargo |
| 183 | `privilege_can_be_disabled_after_use` | After exercise, privilege can be disabled (returns to resting state) | §10.2 line 4033 | Cargo |
| 184 | `privilege_can_be_permanently_removed` | Privilege can be permanently removed from token (irreversible -- cannot be re-added) | §10.2 line 4033-4034 | Cargo |
| 185 | `privilege_check_is_bitmask_test` | Privilege check is a simple bitmask test against token's privileges_enabled field | §10.2 line 4055-4056 | Cargo |

### 10.3 Two Categories

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 186 | `privilege_standalone_independent_of_accesscheck` | Standalone operation gate privileges are independent of AccessCheck | §10.3 line 4050-4052 | Cargo |
| 187 | `privilege_standalone_via_capability_switchboard` | Most standalone privileges enforced via capability switchboard: Linux capability check -> security_capable() hook -> KACS privilege check | §10.3 line 4057-4059 | Provium |
| 188 | `privilege_accesscheck_influencing_count` | Exactly five privileges influence AccessCheck | §10.3 line 4072 | Cargo |

### 10.3 Five AccessCheck-Influencing Privileges

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 189 | `se_security_privilege_grants_sacl_access` | SeSecurityPrivilege grants ability to read and write an object's SACL | §10.3 line 4074-4080 | Cargo |
| 190 | `se_security_privilege_required_for_sacl` | Without SeSecurityPrivilege, SACL is inaccessible regardless of DACL | §10.3 line 4077-4078 | Cargo |
| 191 | `se_take_ownership_grants_ownership_any_object` | SeTakeOwnershipPrivilege lets administrator take ownership of any object even without current permissions | §10.3 line 4082-4086 | Cargo |
| 192 | `se_backup_grants_read_any_object` | SeBackupPrivilege grants read access to any object regardless of DACL | §10.3 line 4088-4091 | Cargo |
| 193 | `se_restore_grants_write_and_permissions` | SeRestorePrivilege grants write access plus ability to modify permissions, change ownership, and access audit policy | §10.3 line 4093-4096 | Cargo |
| 194 | `se_relabel_punches_write_owner_through_mic` | SeRelabelPrivilege punches WRITE_OWNER through MIC for non-dominant callers | §10.3 line 4099-4101 | Cargo |
| 195 | `se_relabel_removes_only_lower_restriction` | SeRelabelPrivilege removes the "only lower" restriction at label-write time -- any level permitted | §10.3 line 4103-4104 | Cargo |
| 196 | `se_relabel_label_gated_by_write_owner_not_ass` | Label modification is gated by WRITE_OWNER, not ACCESS_SYSTEM_SECURITY, despite label residing in SACL | §10.3 line 4101-4102 | Cargo |

### 10.4 Intent-Gated Privileges

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 197 | `se_backup_intent_gated` | SeBackupPrivilege is only evaluated when caller passes BACKUP_INTENT flag | §10.4 line 4114-4118, §10.8 line 4241 | Cargo |
| 198 | `se_restore_intent_gated` | SeRestorePrivilege is only evaluated when caller passes RESTORE_INTENT flag | §10.4 line 4114-4118, §10.8 line 4242 | Cargo |

### 10.5 Privilege Assignment

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 199 | `privilege_not_from_group_membership` | Being a member of Administrators group does not automatically confer any privilege | §10.5 line 4122-4124 | Cargo |
| 200 | `privilege_orthogonal_to_groups` | Privileges and group memberships are orthogonal: groups determine object access (DACL), privileges determine system operations | §10.5 line 4126-4128 | Cargo |
| 201 | `privilege_set_fixed_at_birth` | Token's set of possible privileges is fixed at birth -- none can be added after creation | §10.5 line 4147-4150 | Cargo |
| 202 | `privilege_no_runtime_escalation` | Process cannot acquire new privileges by joining a group, calling a syscall, or exploiting a race | §10.5 line 4152-4154 | Cargo |
| 203 | `privilege_new_token_only_via_auth_or_create` | Only path to different privileges is new authentication event or SeCreateTokenPrivilege | §10.5 line 4155-4157 | Cargo |
| 204 | `kernel_trusts_authd_does_not_evaluate_policy` | Kernel does not verify or evaluate privilege policy -- trusts authd as TCB component | §10.5 line 4143-4145 | Provium |

### 10.6 Custom Peios Privileges

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 205 | `custom_privileges_from_bit_63_downward` | Custom Peios privileges allocated from bit 63 downward in 64-bit bitmask | §10.6 line 4165-4166 | Cargo |
| 206 | `windows_privileges_from_bit_2_upward` | Windows-compatible privileges occupy standard bit positions starting from bit 2 | §10.6 line 4166-4167 | Cargo |
| 207 | `custom_grow_down_windows_grow_up` | Custom allocations grow downward from top, Windows grow upward from bottom -- avoids collision | §10.6 line 4169-4170 | Cargo |
| 208 | `v1_only_custom_privilege_is_bind_port` | Only custom privilege defined for v1 is SeBindPrivilegedPortPrivilege | §10.6 line 4172-4173 | Cargo |
| 209 | `se_bind_privileged_port_gates_below_1024` | SeBindPrivilegedPortPrivilege gates binding to TCP/UDP ports below 1024 | §10.6 line 4173-4174, §10.8 line 4268 | Provium |

### 10.7 Privilege Auditing

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 210 | `privilege_used_is_monotonic` | privileges_used bitmask is a monotonic accumulator -- bits set but never cleared | §10.7 line 4188-4189 | Cargo |
| 211 | `accesscheck_privilege_audit_only_when_necessary` | For AccessCheck-influencing privileges, audit emitted only when privilege was actually necessary (access would have been denied without it) | §10.7 line 4191-4196 | Cargo |
| 212 | `standalone_privilege_audit_on_exercise` | For standalone privileges, capability switchboard records privilege exercise when security_capable() grants based on KACS privilege check | §10.7 line 4200-4201 | Provium |
| 213 | `audit_event_identifies_privilege_operation_token` | Audit event identifies the privilege, the operation, and the calling thread's token | §10.7 line 4202-4203 | Provium |

### 10.8 Privilege Catalog -- Identity and Token Management

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 214 | `se_create_token_is_kernel_standalone` | SeCreateTokenPrivilege is kernel standalone enforcement; creates tokens from scratch | §10.8 line 4231 | Provium |
| 215 | `se_create_token_only_tcb` | SeCreateTokenPrivilege is limited to TCB components (authd, peinit) | §10.8 line 4231 | Provium |
| 216 | `se_assign_primary_token_is_kernel_standalone` | SeAssignPrimaryTokenPrivilege is kernel standalone; installs token as another process's primary identity | §10.8 line 4232 | Provium |
| 217 | `se_impersonate_is_kernel_standalone` | SeImpersonatePrivilege is kernel standalone; required to impersonate another principal | §10.8 line 4233 | Provium |

### 10.8 Privilege Catalog -- Access Control

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 218 | `se_security_is_accesscheck_enforcement` | SeSecurityPrivilege is AccessCheck enforcement category | §10.8 line 4239 | Cargo |
| 219 | `se_take_ownership_is_accesscheck_enforcement` | SeTakeOwnershipPrivilege is AccessCheck enforcement category | §10.8 line 4240 | Cargo |
| 220 | `se_backup_is_accesscheck_enforcement` | SeBackupPrivilege is AccessCheck enforcement category | §10.8 line 4241 | Cargo |
| 221 | `se_restore_is_accesscheck_enforcement` | SeRestorePrivilege is AccessCheck enforcement category | §10.8 line 4242 | Cargo |
| 222 | `se_relabel_is_accesscheck_plus_enforcement` | SeRelabelPrivilege is AccessCheck + enforcement layer category | §10.8 line 4243 | Cargo |
| 223 | `se_change_notify_is_kernel_standalone` | SeChangeNotifyPrivilege is kernel standalone; bypasses traverse checking | §10.8 line 4244 | Provium |
| 224 | `se_change_notify_default_granted` | SeChangeNotifyPrivilege granted to all principals by default | §10.8 line 4244 | Cargo |
| 225 | `se_create_symbolic_link_is_kernel_standalone` | SeCreateSymbolicLinkPrivilege is kernel standalone; gates symlink creation | §10.8 line 4245 | Provium |
| 226 | `se_create_symbolic_link_default_granted` | SeCreateSymbolicLinkPrivilege granted to all principals by default | §10.8 line 4245 | Cargo |

### 10.8 Privilege Catalog -- System Operations

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 227 | `se_tcb_is_kernel_standalone` | SeTcbPrivilege is kernel standalone; catch-all for CAP_SYS_ADMIN-gated operations | §10.8 line 4251 | Provium |
| 228 | `se_shutdown_is_kernel_standalone` | SeShutdownPrivilege is kernel standalone; gates shutdown/reboot | §10.8 line 4252 | Provium |
| 229 | `se_remote_shutdown_requires_both` | Remote shutdown requires both SeShutdownPrivilege AND SeRemoteShutdownPrivilege when logon type is Network | §10.8 line 4253 | Provium |
| 230 | `se_remote_shutdown_checks_logon_type` | SeRemoteShutdownPrivilege enforcement resolves token auth_id to LogonSession and checks logon_type | §10.8 line 4253 | Provium |
| 231 | `se_load_driver_is_kernel_standalone` | SeLoadDriverPrivilege is kernel standalone; gates kernel module load/unload | §10.8 line 4254 | Provium |
| 232 | `se_load_driver_must_be_stripped` | SeLoadDriverPrivilege must be stripped from all non-peinit tokens via FilterToken | §10.8 line 4254 | Provium |
| 233 | `se_debug_is_kernel_standalone` | SeDebugPrivilege is kernel standalone; grants ptrace/memory access to any process regardless of SD | §10.8 line 4255 | Provium |
| 234 | `se_debug_does_not_bypass_pip` | SeDebugPrivilege does not bypass PIP protections -- PIP-protected processes require both privilege and sufficient PIP trust level | §10.8 line 4255 | Provium |
| 235 | `se_systemtime_is_kernel_standalone` | SeSystemtimePrivilege is kernel standalone; gates system clock changes | §10.8 line 4256 | Provium |
| 236 | `se_increase_base_priority_is_kernel_standalone` | SeIncreaseBasePriorityPrivilege is kernel standalone; gates scheduling priority and CPU affinity changes | §10.8 line 4257 | Provium |
| 237 | `se_increase_quota_is_kernel_standalone` | SeIncreaseQuotaPrivilege is kernel standalone; gates resource limit overrides | §10.8 line 4258 | Provium |
| 238 | `se_lock_memory_is_kernel_standalone` | SeLockMemoryPrivilege is kernel standalone; gates mlock/mlockall | §10.8 line 4259 | Provium |
| 239 | `se_audit_is_kernel_standalone` | SeAuditPrivilege is kernel standalone; allows userspace services to generate audit records | §10.8 line 4260 | Provium |
| 240 | `se_profile_single_process_is_kernel_standalone` | SeProfileSingleProcessPrivilege is kernel standalone; gates perf_event_open | §10.8 line 4261 | Provium |
| 241 | `se_create_job_is_kernel_standalone` | SeCreateJobPrivilege is kernel standalone; custom Peios privilege; gates JFS syscall | §10.8 line 4262 | Provium |

### 10.8 Privilege Catalog -- Network

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 242 | `se_bind_privileged_port_is_kernel_standalone` | SeBindPrivilegedPortPrivilege is kernel standalone; custom Peios privilege | §10.8 line 4268 | Provium |

### 10.8 Privilege Catalog -- Directory and Domain (Application-Level)

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 243 | `se_sync_agent_is_application_level` | SeSyncAgentPrivilege is application-level enforcement; checked by authd/directory service | §10.8 line 4274 | Cargo |
| 244 | `se_enable_delegation_is_application_level` | SeEnableDelegationPrivilege is application-level; checked by authd when modifying delegation trust | §10.8 line 4275 | Cargo |
| 245 | `se_machine_account_is_application_level` | SeMachineAccountPrivilege is application-level; checked by directory service for domain join | §10.8 line 4276 | Cargo |

### 10.8 Privilege Catalog -- Reserved

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 246 | `se_create_global_reserved` | SeCreateGlobalPrivilege is reserved -- bit position exists for AD token compatibility, no enforcement in v1 | §10.8 line 4287 | Cargo |
| 247 | `se_create_pagefile_reserved` | SeCreatePagefilePrivilege is reserved -- absorbed in SeTcbPrivilege | §10.8 line 4288 | Cargo |
| 248 | `se_create_permanent_reserved` | SeCreatePermanentPrivilege is reserved -- no Linux equivalent | §10.8 line 4289 | Cargo |
| 249 | `se_increase_working_set_reserved` | SeIncreaseWorkingSetPrivilege is reserved -- Linux does not gate madvise | §10.8 line 4290 | Cargo |
| 250 | `se_manage_volume_reserved` | SeManageVolumePrivilege is reserved -- absorbed in SeTcbPrivilege | §10.8 line 4291 | Cargo |
| 251 | `se_trusted_cred_man_access_reserved` | SeTrustedCredManAccessPrivilege is reserved -- for future secrets infra | §10.8 line 4292 | Cargo |
| 252 | `se_system_environment_reserved` | SeSystemEnvironmentPrivilege is reserved -- under FACS gated by SDs on efivar files | §10.8 line 4293 | Cargo |
| 253 | `se_system_profile_reserved` | SeSystemProfilePrivilege is reserved -- absorbed in SeProfileSingleProcessPrivilege | §10.8 line 4294 | Cargo |
| 254 | `se_time_zone_reserved` | SeTimeZonePrivilege is reserved -- Linux has no privileged syscall for timezone | §10.8 line 4295 | Cargo |
| 255 | `se_undock_reserved` | SeUndockPrivilege is reserved -- server OS, no use case | §10.8 line 4296 | Cargo |
| 256 | `reserved_privileges_have_no_enforcement` | All reserved privileges have no enforcement point in Peios v1 -- bit positions exist only for AD token compatibility | §10.8 line 4280-4284 | Cargo |

### 10.8 Privilege Catalog -- Total Count

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 257 | `privilege_catalog_identity_count_3` | Identity and token management category has exactly 3 privileges | §10.8 line 4229-4233 | Cargo |
| 258 | `privilege_catalog_access_control_count_7` | Access control category has exactly 7 privileges | §10.8 line 4237-4245 | Cargo |
| 259 | `privilege_catalog_system_ops_count_12` | System operations category has exactly 12 privileges (including SeCreateJobPrivilege) | §10.8 line 4249-4262 | Cargo |
| 260 | `privilege_catalog_network_count_1` | Network category has exactly 1 privilege | §10.8 line 4266-4268 | Cargo |
| 261 | `privilege_catalog_directory_count_3` | Directory and domain operations category has exactly 3 privileges | §10.8 line 4272-4276 | Cargo |
| 262 | `privilege_catalog_reserved_count_10` | Reserved category has exactly 10 privileges | §10.8 line 4285-4296 | Cargo |
| 263 | `privilege_all_fit_in_u64` | All defined privileges (Windows standard from bit 2 + custom from bit 63 down) fit within a u64 bitmask | §10.6 line 4165-4170 | Cargo |

### 10.2/10.5 Privilege Lifecycle Enforcement

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 264 | `adjust_privileges_enable_present` | AdjustPrivileges can enable a privilege that is present but disabled | §10.2 line 4023-4025 | Provium |
| 265 | `adjust_privileges_disable_enabled` | AdjustPrivileges can disable an enabled privilege | §10.2 line 4033 | Provium |
| 266 | `adjust_privileges_remove_permanent` | AdjustPrivileges can permanently remove a privilege -- irreversible | §10.2 line 4033-4034 | Provium |
| 267 | `adjust_privileges_cannot_add_missing` | AdjustPrivileges cannot add a privilege not present on the token | §10.2 line 4015-4016 | Provium |
| 268 | `adjust_privileges_cannot_reenable_removed` | AdjustPrivileges cannot re-enable a permanently removed privilege | §10.2 line 4033-4034 | Provium |
| 269 | `adjust_privileges_reset_to_default` | AdjustTokenPrivileges can restore all privileges to privileges_enabled_by_default state | §7.3 line 2088 | Provium |
| 270 | `privilege_present_disabled_not_exercised` | A privilege that is present but disabled is not exercised by privilege check | §10.2 line 4054 | Cargo |
| 271 | `privilege_enabled_exercised_sets_used_bit` | Exercising a privilege sets the corresponding bit in privileges_used | §10.2 line 4028-4030, §10.7 line 4187-4189 | Cargo |

### SYSTEM Token Bootstrap (from §7.5, referenced by §2)

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 272 | `system_token_user_sid` | SYSTEM token user SID is S-1-5-18 | §7.5 line 2306 | Provium |
| 273 | `system_token_groups_include_administrators` | SYSTEM token groups include BUILTIN\Administrators (S-1-5-32-544) | §7.5 line 2307 | Provium |
| 274 | `system_token_all_privileges_present_and_enabled` | SYSTEM token has all defined privileges, present and enabled | §7.5 line 2309 | Provium |
| 275 | `system_token_integrity_system` | SYSTEM token integrity level is System | §7.5 line 2310 | Provium |
| 276 | `system_token_type_primary` | SYSTEM token type is Primary | §7.5 line 2311 | Provium |
| 277 | `system_token_elevation_default` | SYSTEM token elevation type is Default (no linked token) | §7.5 line 2312 | Provium |
| 278 | `system_token_source_peioskrn` | SYSTEM token source is "PeiosKrn" | §7.5 line 2313 | Provium |
| 279 | `system_token_assigned_to_pid_1` | SYSTEM token assigned to init task and inherited by PID 1 on exec | §7.5 line 2316-2317 | Provium |
| 280 | `system_token_projects_to_uid_0` | SYSTEM token credential projection maps to UID 0 | §7.5 line 2318 | Provium |

### Token Lifecycle across fork/exec (from §7.4, referenced by §2 definitions)

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 281 | `fork_copies_primary_token` | Fork (clone without CLONE_THREAD) gives child independent deep copy of parent's primary token | §7.4 line 2238-2240 | Provium |
| 282 | `fork_does_not_inherit_impersonation` | Fork does not inherit parent's impersonation token -- child gets identity from real_cred | §7.4 line 2241-2242 | Provium |
| 283 | `fork_token_mutations_independent` | After fork, mutations to either token are invisible to the other | §7.4 line 2242-2243 | Provium |
| 284 | `clone_thread_shares_primary_token` | Clone with CLONE_THREAD: threads share parent's real_cred (refcounted), same primary token object | §7.4 line 2247-2249 | Provium |
| 285 | `thread_privilege_adjustments_visible_to_all` | Privilege adjustments on primary token visible to all threads in process | §7.4 line 2249-2250 | Provium |
| 286 | `threads_independent_impersonation` | Each thread maintains independent impersonation state -- new thread does not inherit impersonation | §7.4 line 2250-2252 | Provium |
| 287 | `exec_preserves_primary_token` | Primary token survives execve unchanged (unless NEW_PROCESS_MIN applies) | §7.4 line 2255-2256 | Provium |
| 288 | `exec_reverts_impersonation` | If thread is impersonating, impersonation is reverted before new program runs | §7.4 line 2257-2258 | Provium |

---

## Summary

**Total tests extracted: 288**

- **Cargo tests (pure Rust logic, no kernel): 200**
- **Provium tests (requires booted KACS kernel): 88**

Key groupings:
- SID format and well-known values: 16 tests
- Token definition and fields: 10 tests
- Primary/impersonation token semantics: 6 tests
- Security Descriptor structure and format: 12 tests
- ACL semantics (null/empty/ordering): 7 tests
- ACE types and format: 29 tests
- Access mask bit layout: 18 tests
- AccessCheck inputs and behavior: 10 tests
- Impersonation levels: 5 tests
- Integrity levels / MIC: 12 tests
- Ownership and OWNER RIGHTS: 11 tests
- ACL revision: 4 tests
- Control flags: 14 tests
- GenericMapping: 3 tests
- SID matching in DACL walk: 9 tests
- Token privilege bitmask fields: 7 tests
- Privilege model lifecycle: 16 tests
- Privilege categories and enforcement: 3 tests
- Five AccessCheck-influencing privileges: 10 tests
- Privilege catalog (all categories): 49 tests
- Privilege auditing: 4 tests
- Custom privilege allocation: 5 tests
- SYSTEM token bootstrap: 9 tests
- Token lifecycle across fork/exec: 8 tests
- Privilege lifecycle enforcement: 8 tests
- Reserved privileges: 11 tests


---

# Section 5: Linux Application Compatibility + Section 6: Feature Overview

## KACS Test Corpus: Sections 5 and 6

---

### Section 5.1 — Credential Projection

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 1 | `cred_proj_uid_from_ad_uidnumber` | When a token is installed on a process, `getuid()` returns the UID mapped from the token's user SID via the AD `uidNumber` attribute. | §5.1 L1001-1002 | Provium |
| 2 | `cred_proj_uid_fallback_anonymous` | If the token's user SID has no `uidNumber` attribute, the process's UID defaults to 65534 (Anonymous SID / `nobody`). | §5.1 L1002-1003 | Provium |
| 3 | `cred_proj_gid_from_ad_gidnumber` | The token's primary group SID maps to a GID via the AD `gidNumber` attribute. | §5.1 L1004-1005 | Provium |
| 4 | `cred_proj_gid_fallback_anonymous` | If the token's primary group SID has no `gidNumber`, the GID defaults to 65534. | §5.1 L1005 | Provium |
| 5 | `cred_proj_supplementary_groups` | The token's group SIDs map to supplementary GIDs where `gidNumber` attributes exist; `getgroups()` returns these. | §5.1 L1006-1007 | Provium |
| 6 | `cred_proj_getuid_returns_projected` | `getuid()` returns the projected UID matching the token's user SID. | §5.1 L1008 | Provium |
| 7 | `cred_proj_getgid_returns_projected` | `getgid()` returns the projected GID matching the token's primary group SID. | §5.1 L1008 | Provium |
| 8 | `cred_proj_getgroups_returns_projected` | `getgroups()` returns projected supplementary GIDs matching the token's group SIDs. | §5.1 L1008 | Provium |
| 9 | `cred_proj_proc_status_reflects_uid` | `/proc/<pid>/status` reflects the projected UID and GID values. | §5.1 L1009 | Provium |
| 10 | `cred_proj_stat_reflects_projected` | `stat()` on process-owned resources reflects the projected UID/GID. | §5.1 L1009-1010 | Provium |
| 11 | `cred_proj_no_uid0_without_system_token` | No process runs as UID 0 unless it holds the SYSTEM token (S-1-5-18). | §5.1 L1014-1015 | Provium |
| 12 | `cred_proj_root_refusing_software_works` | Software that refuses to run as root (checks `getuid() == 0`) works without modification for non-SYSTEM tokens. | §5.1 L1018-1019 | Provium |
| 13 | `cred_proj_system_token_gets_uid0` | A process with the SYSTEM token (S-1-5-18) has UID 0. | §5.1 L1015 | Provium |
| 14 | `cred_proj_different_services_different_uids` | Different services with different token user SIDs get different projected UIDs. | §5.1 L1023-1025 | Provium |
| 15 | `cred_proj_on_fork` | When a process forks, the child inherits the projected credentials matching the parent's token. | §5.1 L997-998 | Provium |
| 16 | `cred_proj_on_exec` | When a process execs, projected credentials are set to match the installed token. | §5.1 L997-998 | Provium |
| 17 | `cred_proj_impersonation_not_projected` | Projected Linux credentials reflect the process's primary token, not any impersonation token. `getuid()` and KACS identity may disagree during impersonation. | §5 L969-975 | Provium |
| 18 | `cred_proj_proc_status_shows_primary_not_impersonation` | `/proc/<pid>/status` always shows the primary token's projected UID, even if individual threads are impersonating different identities. | §5.6 L1482-1484 | Provium |
| 19 | `cred_proj_groups_without_gidnumber_omitted` | Group SIDs that lack a `gidNumber` attribute are not included in the supplementary GID list. | §5.1 L1006-1007 | Provium |

---

### Section 5.2 — DAC Neutralization / Capability Switchboard

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 20 | `dac_neutral_all_processes_full_capset` | All processes receive a full capability set in their Linux credentials. | §5.2 L1048-1050 | Provium |
| 21 | `dac_neutral_dac_never_blocks_kacs` | DAC checks pass (because full capabilities) so the LSM hook is always reached for KACS evaluation. | §5.2 L1047-1051 | Provium |
| 22 | `dac_neutral_cross_uid_signal_reaches_lsm` | A process with UID 1000 can attempt `kill()` on UID 2000; DAC does not block it, KACS LSM hook evaluates. | §5.2 L1042-1045 | Provium |
| 23 | `dac_neutral_cross_uid_file_access_reaches_lsm` | File access by a process whose UID does not match the file owner reaches KACS `inode_permission` hook instead of failing at DAC. | §5.2 L1044-1045 | Provium |

#### 5.2.1 — Capability Classification: ALLOW

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 24 | `cap_allow_chown` | CAP_CHOWN (0) is ALLOWED by the switchboard; file ownership changes reach KACS file hooks. | §5.2.1 L1084 | Provium |
| 25 | `cap_allow_dac_override` | CAP_DAC_OVERRIDE (1) is ALLOWED; file permission bypass reaches KACS file hooks. | §5.2.1 L1085 | Provium |
| 26 | `cap_allow_dac_read_search` | CAP_DAC_READ_SEARCH (2) is ALLOWED; file/dir read bypass reaches KACS file hooks. | §5.2.1 L1086 | Provium |
| 27 | `cap_allow_fowner` | CAP_FOWNER (3) is ALLOWED; operations requiring UID=owner reach KACS file hooks. | §5.2.1 L1087 | Provium |
| 28 | `cap_allow_fsetid` | CAP_FSETID (4) is ALLOWED; setuid/setgid bit preservation reaches KACS file hooks. | §5.2.1 L1088 | Provium |
| 29 | `cap_allow_kill` | CAP_KILL (5) is ALLOWED; signal delivery reaches KACS `task_kill` hook. | §5.2.1 L1089 | Provium |
| 30 | `cap_allow_setgid` | CAP_SETGID (6) is ALLOWED; `setgid()` reaches `task_fix_setuid` hook. | §5.2.1 L1090 | Provium |
| 31 | `cap_allow_setuid` | CAP_SETUID (7) is ALLOWED; `setuid()` reaches `task_fix_setuid` hook. | §5.2.1 L1091 | Provium |
| 32 | `cap_allow_net_broadcast` | CAP_NET_BROADCAST (11) is ALLOWED (unused in modern kernels). | §5.2.1 L1092 | Provium |
| 33 | `cap_allow_ipc_owner` | CAP_IPC_OWNER (15) is ALLOWED; SysV IPC permission bypass reaches KACS IPC hooks. | §5.2.1 L1093 | Provium |
| 34 | `cap_allow_lease` | CAP_LEASE (28) is ALLOWED; file leases reach KACS file hooks. | §5.2.1 L1094 | Provium |

#### 5.2.1 — Capability Classification: PRIVILEGE (fail-closed)

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 35 | `cap_priv_linux_immutable_requires_setcb` | CAP_LINUX_IMMUTABLE (9) requires `SeTcbPrivilege`; denied without it. | §5.2.1 L1100 | Provium |
| 36 | `cap_priv_net_bind_service_requires_bind_priv` | CAP_NET_BIND_SERVICE (10) requires `SeBindPrivilegedPortPrivilege`; denied without it. | §5.2.1 L1101 | Provium |
| 37 | `cap_priv_net_bind_service_allows_with_priv` | A process with `SeBindPrivilegedPortPrivilege` can bind ports < 1024. | §5.2.1 L1101 | Provium |
| 38 | `cap_priv_net_admin_requires_setcb` | CAP_NET_ADMIN (12) requires `SeTcbPrivilege`. | §5.2.1 L1102 | Provium |
| 39 | `cap_priv_net_raw_requires_setcb` | CAP_NET_RAW (13) requires `SeTcbPrivilege`. | §5.2.1 L1103 | Provium |
| 40 | `cap_priv_ipc_lock_requires_lockmem` | CAP_IPC_LOCK (14) requires `SeLockMemoryPrivilege`. | §5.2.1 L1104 | Provium |
| 41 | `cap_priv_sys_module_requires_loaddriver` | CAP_SYS_MODULE (16) requires `SeLoadDriverPrivilege`; denied without it. | §5.2.1 L1105 | Provium |
| 42 | `cap_priv_sys_rawio_requires_setcb` | CAP_SYS_RAWIO (17) requires `SeTcbPrivilege`. | §5.2.1 L1106 | Provium |
| 43 | `cap_priv_sys_chroot_requires_setcb` | CAP_SYS_CHROOT (18) requires `SeTcbPrivilege`. | §5.2.1 L1107 | Provium |
| 44 | `cap_priv_sys_ptrace_requires_debug` | CAP_SYS_PTRACE (19) requires `SeDebugPrivilege`. | §5.2.1 L1108 | Provium |
| 45 | `cap_priv_sys_pacct_requires_setcb` | CAP_SYS_PACCT (20) requires `SeTcbPrivilege`. | §5.2.1 L1109 | Provium |
| 46 | `cap_priv_sys_admin_requires_setcb` | CAP_SYS_ADMIN (21) requires `SeTcbPrivilege`. | §5.2.1 L1110 | Provium |
| 47 | `cap_priv_sys_boot_requires_shutdown` | CAP_SYS_BOOT (22) requires `SeShutdownPrivilege`. | §5.2.1 L1111 | Provium |
| 48 | `cap_priv_sys_nice_requires_basepriority` | CAP_SYS_NICE (23) requires `SeIncreaseBasePriorityPrivilege`. | §5.2.1 L1112 | Provium |
| 49 | `cap_priv_sys_resource_requires_quota` | CAP_SYS_RESOURCE (24) requires `SeIncreaseQuotaPrivilege`. | §5.2.1 L1113 | Provium |
| 50 | `cap_priv_sys_time_requires_systemtime` | CAP_SYS_TIME (25) requires `SeSystemtimePrivilege`. | §5.2.1 L1114 | Provium |
| 51 | `cap_priv_sys_tty_config_requires_setcb` | CAP_SYS_TTY_CONFIG (26) requires `SeTcbPrivilege`. | §5.2.1 L1115 | Provium |
| 52 | `cap_priv_mknod_requires_setcb` | CAP_MKNOD (27) requires `SeTcbPrivilege`. | §5.2.1 L1116 | Provium |
| 53 | `cap_priv_audit_write_requires_audit` | CAP_AUDIT_WRITE (29) requires `SeAuditPrivilege`. | §5.2.1 L1117 | Provium |
| 54 | `cap_priv_audit_control_requires_security` | CAP_AUDIT_CONTROL (30) requires `SeSecurityPrivilege`. | §5.2.1 L1118 | Provium |
| 55 | `cap_priv_mac_admin_requires_security` | CAP_MAC_ADMIN (33) requires `SeSecurityPrivilege`. | §5.2.1 L1119 | Provium |
| 56 | `cap_priv_syslog_requires_setcb` | CAP_SYSLOG (34) requires `SeTcbPrivilege`. | §5.2.1 L1120 | Provium |
| 57 | `cap_priv_wake_alarm_requires_setcb` | CAP_WAKE_ALARM (35) requires `SeTcbPrivilege`. | §5.2.1 L1121 | Provium |
| 58 | `cap_priv_block_suspend_requires_setcb` | CAP_BLOCK_SUSPEND (36) requires `SeTcbPrivilege`. | §5.2.1 L1122 | Provium |
| 59 | `cap_priv_audit_read_requires_security` | CAP_AUDIT_READ (37) requires `SeSecurityPrivilege`. | §5.2.1 L1123 | Provium |
| 60 | `cap_priv_perfmon_requires_profilesingle` | CAP_PERFMON (38) requires `SeProfileSingleProcessPrivilege`. | §5.2.1 L1124 | Provium |
| 61 | `cap_priv_bpf_requires_setcb` | CAP_BPF (39) requires `SeTcbPrivilege`. | §5.2.1 L1125 | Provium |
| 62 | `cap_priv_checkpoint_restore_requires_setcb` | CAP_CHECKPOINT_RESTORE (40) requires `SeTcbPrivilege`. | §5.2.1 L1126 | Provium |
| 63 | `cap_priv_unmapped_cap_denied` | An unmapped or unknown capability is denied by default (fail-closed). | §5.2 L1072-1073 | Provium |

#### 5.2.1 — Capability Classification: DENY

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 64 | `cap_deny_setpcap` | CAP_SETPCAP (8) is unconditionally denied. | §5.2.1 L1132 | Provium |
| 65 | `cap_deny_setfcap` | CAP_SETFCAP (31) is unconditionally denied. | §5.2.1 L1133 | Provium |
| 66 | `cap_deny_mac_override` | CAP_MAC_OVERRIDE (32) is unconditionally denied; KACS LSM must not be bypassable. | §5.2.1 L1134 | Provium |

#### 5.2.2 — Capability Inspection Compat Gap

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 67 | `cap_inspect_capget_shows_full_set` | `capget()` returns a full capability set even when KACS privilege restrictions apply. | §5.2.2 L1174-1176 | Provium |
| 68 | `cap_inspect_proc_status_shows_full_set` | `/proc/self/status` shows a full capability set regardless of KACS privilege restrictions. | §5.2.2 L1174-1176 | Provium |
| 69 | `cap_inspect_branch_then_denied` | An application that branches on capability presence takes the "capable" path, but the underlying operation is denied by the KACS switchboard if the privilege is absent. | §5.2.2 L1177-1181 | Provium |

---

### Section 5.3 — The setuid() Syscall

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 70 | `setuid_no_security_properties` | UIDs have zero security properties under KACS. A process with UID 0 and a process with UID 65534 holding the same KACS token have identical authority. | §5.3 L1189-1206 | Provium |
| 71 | `setuid_noop_without_privilege` | `setuid()` without `SeAssignPrimaryTokenPrivilege` returns 0 (success) but neither the Linux credential nor the KACS token changes. | §5.3 L1221-1227 | Provium |
| 72 | `setuid_noop_uid_unchanged` | After a no-op `setuid(nobody)`, `getuid()` still returns the original UID. | §5.3 L1221-1227 | Provium |
| 73 | `setuid_noop_token_unchanged` | After a no-op `setuid()`, the KACS token is unchanged (same authority as before). | §5.3 L1221-1227 | Provium |
| 74 | `setuid_noop_returns_success` | The no-op `setuid()` returns 0, not an error code. | §5.3 L1223 | Provium |
| 75 | `setgid_noop_without_privilege` | `setgid()` without `SeAssignPrimaryTokenPrivilege` is a silent no-op returning 0. | §5.3 L1216-1217 | Provium |
| 76 | `setresuid_noop_without_privilege` | `setresuid()` without `SeAssignPrimaryTokenPrivilege` is a silent no-op returning 0. | §5.3 L1216-1217 | Provium |
| 77 | `setresgid_noop_without_privilege` | `setresgid()` without `SeAssignPrimaryTokenPrivilege` is a silent no-op returning 0. | §5.3 L1216-1217 | Provium |
| 78 | `setgroups_noop_without_privilege` | `setgroups()` without `SeAssignPrimaryTokenPrivilege` is a silent no-op returning 0. | §5.3 L1216-1217 | Provium |
| 79 | `setuid_with_privilege_swaps_token` | `setuid()` with `SeAssignPrimaryTokenPrivilege` triggers a genuine identity transition: both the KACS token and Linux credential change. | §5.3 L1230-1238 | Provium |
| 80 | `setuid_with_privilege_seccomp_intercept` | The privileged `setuid()` path uses seccomp user notification (`SECCOMP_RET_USER_NOTIF`) to redirect to userspace for authd token swap. | §5.3 L1232-1238 | Provium |
| 81 | `setuid_seccomp_only_on_privileged` | The seccomp filter is only installed on processes holding `SeAssignPrimaryTokenPrivilege`. Unprivileged processes never enter the seccomp path. | §5.3 L1241-1244 | Provium |
| 82 | `setuid_lsm_hook_handles_unprivileged` | Unprivileged `setuid()` calls are handled entirely by the `task_fix_setuid` LSM hook (in-kernel, no userspace round-trip). | §5.3 L1224-1227 | Provium |
| 83 | `setuid_noop_preserves_uid_token_consistency` | The no-op preserves consistency: `getuid()` and KACS identity remain in sync (no split). | §5.3 L1279-1284 | Provium |
| 84 | `setfsuid_noop_without_privilege` | `setfsuid()` follows the same no-op/swap model as `setuid()`. | §5.6 L1400-1407 | Provium |
| 85 | `setfsgid_noop_without_privilege` | `setfsgid()` follows the same no-op/swap model as `setgid()`. | §5.6 L1400-1407 | Provium |

---

### Section 5.4 — The Setuid Bit on Exec

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 86 | `setuid_bit_with_privilege_changes_euid_and_token` | Executing a setuid binary with `SeAssignPrimaryTokenPrivilege` changes euid/suid to the file owner's UID AND swaps the KACS token to the corresponding identity. | §5.4 L1313-1316 | Provium |
| 87 | `setuid_bit_without_privilege_changes_euid_only` | Executing a setuid binary without `SeAssignPrimaryTokenPrivilege` changes euid/suid to the file owner's UID but the KACS token is unchanged. | §5.4 L1318-1321 | Provium |
| 88 | `setuid_bit_euid_suid_change` | The setuid bit on exec changes the effective UID (euid) and saved set-user-ID (suid) to the file owner's UID. | §5.4 L1307-1309 | Provium |
| 89 | `setuid_bit_ruid_unchanged` | The real UID (ruid) is unchanged after executing a setuid binary. | §5.4 L1309-1310 | Provium |
| 90 | `setuid_bit_fsuid_follows_euid` | The fsuid follows the euid after executing a setuid binary. | §5.4 L1310 | Provium |
| 91 | `setuid_bit_cosmetic_escalation_kacs_enforces_original` | In cosmetic escalation (no privilege): the process sees `geteuid() == 0` but KACS continues to enforce the original token's authority. | §5.4 L1349-1354 | Provium |
| 92 | `setuid_bit_genuine_escalation_sudo` | With privilege: `sudo` running with `geteuid() == 0` AND a SYSTEM token is real `sudo`. | §5.4 L1315-1316 | Provium |
| 93 | `setuid_bit_at_secure_triggered` | Executing a setuid binary triggers Linux's secure-exec mode (`AT_SECURE`), stripping `LD_PRELOAD`, `LD_LIBRARY_PATH`, clearing `PR_SET_PDEATHSIG`, resetting dumpability — even in cosmetic escalation. | §5.6 L1439-1449 | Provium |

---

### Section 5.5 — Root-Assuming and Root-Refusing Software

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 94 | `root_refusing_software_no_uid0` | Root-refusing software (checks `getuid() == 0` and aborts) works without modification because no regular process has UID 0 under credential projection. | §5.5 L1361-1363 | Provium |
| 95 | `root_assuming_no_dangerous_paths` | Root-assuming software's dangerous codepaths (checks `getuid() == 0` to enable) do not activate in normal operation because no regular process has UID 0. | §5.5 L1366-1369 | Provium |
| 96 | `uid0_tool_cosmetic_uid0` | A `uid0` setuid-root wrapper provides cosmetic UID 0 without token swap (per §5.4 without privilege). | §5.5 L1374-1377 | Provium |

---

### Section 5.6 — Known Compat Gaps (still testable assertions)

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 97 | `capset_behavior_unexpected` | `capset()` / `capget()` calls may behave unexpectedly; the switchboard allows a full set, but modifying capabilities has no KACS effect. | §5.6 L1384-1391 | Provium |
| 98 | `access_and_open_agree` | `access()` and `open()` both use the same KACS token for evaluation, so they agree. The Linux real-UID vs effective-UID distinction is lost. | §5.6 L1409-1418 | Provium |
| 99 | `so_peercred_returns_projected_uid` | `SO_PEERCRED` on a Unix socket returns the projected UID/GID/PID, not KACS token information. | §5.6 L1421-1423 | Provium |
| 100 | `scm_credentials_returns_projected` | `SCM_CREDENTIALS` sends projected UIDs, not KACS token information. | §5.6 L1423-1424 | Provium |
| 101 | `scm_credentials_forgery_cosmetic` | `CAP_SETUID` being ALLOWED permits forging the UID field in `SCM_CREDENTIALS` — this is a cosmetic forgery under KACS. | §5.6 L1426-1430 | Provium |
| 102 | `so_reuseport_uses_projected_uid` | `SO_REUSEPORT` enforces same-UID requirement based on projected UIDs. Services with different KACS tokens (different UIDs) cannot share a port via `SO_REUSEPORT`. | §5.6 L1432-1437 | Provium |
| 103 | `linux_auditd_uses_projected_uids` | Linux `auditd` records use projected UID/GID values, which remain meaningful (each service has a distinct UID). | §5.6 L1452-1458 | Provium |
| 104 | `per_thread_cred_divergence_primary_visible` | Linux credentials show the primary token's UID; impersonation tokens are NOT projected. Multi-threaded apps see consistent process-wide UID from primary token. | §5.6 L1476-1488 | Provium |

---

### Section 5 — Overriding Constraints (cross-cutting)

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 105 | `compat_never_bypasses_accesscheck` | No compatibility shim, silent no-op, or credential projection may bypass AccessCheck or create a path where a UID grants authority the token does not. | §5 L949-952 | Provium |
| 106 | `uid_grants_no_authority` | A UID alone never grants any authority. Two processes with different UIDs but the same KACS token have identical access. | §5.3 L1189-1206 | Provium |
| 107 | `uid_not_in_any_sd` | The UID does not appear in any Security Descriptor. No ACE references a UID. | §5.3 L1192-1194 | Provium |

---

### Section 6.1 — Identity

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 108 | `every_thread_has_token` | Every thread on the system carries a token. There are no anonymous threads. | §6.1 L1499-1503 | Provium |
| 109 | `token_contains_user_groups_privs_trust` | A token contains user identity, group memberships, privileges, and trust level. | §6.1 L1500-1501 | Cargo |
| 110 | `sid_binary_compat_with_ad` | SIDs are binary-compatible with Windows Active Directory SIDs. A SID assigned on a Windows DC is the same SID on every Peios machine in the domain. | §6.1 L1506-1509 | Cargo |
| 111 | `sid_globally_unique_hierarchical` | Every principal has a globally unique, hierarchical SID. | §6.1 L1505-1506 | Cargo |
| 112 | `logon_session_tracks_auth_event` | Each authentication event creates a logon session tracking when, how, and which tokens belong to the session. | §6.1 L1511-1513 | Provium |
| 113 | `logon_session_kill_invalidates_tokens` | Killing a logon session can invalidate all tokens that came from it. | §6.1 L1514-1515 | Provium |
| 114 | `service_sid_as_group` | Each service receives a dedicated service SID (e.g., `NT SERVICE\jellyfin`) added as a group in its token (not as the primary user SID). | §6.1 L1517-1519 | Cargo |
| 115 | `service_primary_sid_is_account` | The token's primary user SID is the account the service runs as (typically SYSTEM, LocalService, or NetworkService). | §6.1 L1519-1520 | Cargo |
| 116 | `service_sid_enables_per_service_acl` | A file's DACL can grant access to `NT SERVICE\jellyfin` specifically, providing per-service access control. | §6.1 L1520-1523 | Cargo |

---

### Section 6.2 — Access Control

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 117 | `sd_on_every_protected_object` | Every protected object (file, registry key, IPC endpoint, service) has a Security Descriptor. | §6.2 L1532-1534 | Provium |
| 118 | `sd_windows_binary_format` | SDs use the Windows binary format and are fully compatible with Samba and Windows file servers. | §6.2 L1535-1536 | Cargo |
| 119 | `dacl_ordered_evaluation` | DACL is an ordered list of rules evaluated in order. | §6.2 L1538-1541 | Cargo |
| 120 | `dacl_allow_and_deny_rules` | Both allow and deny rules are supported in a DACL. | §6.2 L1541 | Cargo |
| 121 | `object_type_ace_targets_subobject` | Access rules can target specific properties or sub-objects via object-type ACEs with property GUIDs. | §6.2 L1543-1546 | Cargo |
| 122 | `conditional_ace_evaluates_token_attrs` | Conditional ACEs evaluate expressions against token attributes (e.g., `department=engineering AND clearance >= 3`). | §6.2 L1548-1551 | Cargo |
| 123 | `central_access_policy_both_must_allow` | AccessCheck evaluates both the file's normal DACL and the referenced central policy; access granted only if both allow. | §6.2 L1555-1557 | Cargo |
| 124 | `central_policy_via_scoped_policy_id_ace` | Central policy is evaluated via `SYSTEM_SCOPED_POLICY_ID_ACE` type. | §6.2 L1562 | Cargo |
| 125 | `sd_inheritance_container_inherit` | Container Inherit flag causes subdirectories to inherit DACL entries. | §6.2 L1566-1567 | Cargo |
| 126 | `sd_inheritance_object_inherit` | Object Inherit flag causes files to inherit DACL entries. | §6.2 L1567 | Cargo |
| 127 | `sd_inheritance_no_propagate` | No Propagate flag limits inheritance to one level only. | §6.2 L1567-1568 | Cargo |
| 128 | `sd_inheritance_inherit_only` | Inherit Only flag means the ACE does not apply to the container itself, only its children. | §6.2 L1568 | Cargo |
| 129 | `default_security_on_create` | When a new object is created, it automatically gets an SD: creator as owner, inheritable rules from parent, default DACL from creator's token. | §6.2 L1570-1573 | Provium |
| 130 | `no_object_without_sd` | No object is ever created without security policy. | §6.2 L1573 | Provium |
| 131 | `owner_implicit_read_control_write_dac` | The owner of an object receives implicit READ_CONTROL and WRITE_DAC. | §6.2 L1575-1577 | Cargo |
| 132 | `owner_rights_ace_overrides_implicit` | An OWNER RIGHTS ACE (`S-1-3-4`) in the DACL overrides the owner's implicit grants — can restrict or expand them. | §6.2 L1577-1580 | Cargo |
| 133 | `accesscheck_single_function` | A single kernel function evaluates every access control decision given a token, an SD, and a requested operation. | §6.2 L1582-1583 | Cargo |
| 134 | `accesscheck_all_subsystems_same_evaluator` | Every subsystem (files, registry, IPC, services) uses the same AccessCheck evaluator. | §6.2 L1584-1586 | Cargo |

---

### Section 6.3 — Integrity

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 135 | `mic_five_trust_levels` | Every token has one of five trust levels: Untrusted, Low, Medium, High, or System. | §6.3 L1591 | Cargo |
| 136 | `mic_no_write_up` | A lower-trust process cannot write to a higher-trust object, regardless of DACL. | §6.3 L1592-1593 | Cargo |
| 137 | `mic_integrity_policy_no_write_up_flag` | Per-token policy flags control whether the no-write-up rule applies. | §6.3 L1597-1598 | Cargo |
| 138 | `mic_child_integrity_inheritance` | Integrity policy flags control whether child processes inherit the minimum integrity level of parent and child. | §6.3 L1598-1599 | Cargo |

---

### Section 6.4 — Privileges

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 139 | `privilege_required_for_special_ops` | Special operations (reboot, load modules, change clock, take ownership, debug processes) require specific privileges on the calling token. | §6.4 L1603-1606 | Provium |
| 140 | `privilege_granted_by_policy_not_identity` | Privileges are granted by policy, not identity. A user in Administrators does not automatically get SeDebugPrivilege. | §6.4 L1606-1608 | Cargo |
| 141 | `privilege_enable_disable` | Privileges on a token can be present but disabled. Must be explicitly enabled to take effect. | §6.4 L1610-1612 | Cargo |
| 142 | `se_backup_grants_read` | SeBackupPrivilege, when enabled, grants read access. | §6.4 L1616-1617 | Cargo |
| 143 | `se_restore_grants_write_and_more` | SeRestorePrivilege, when enabled, grants write access plus WRITE_DAC, WRITE_OWNER, DELETE, ACCESS_SYSTEM_SECURITY. | §6.4 L1617-1618 | Cargo |
| 144 | `privilege_backup_restore_requires_intent_flag` | Backup/restore privilege bypass only applies when the caller passes a backup/restore intent flag. | §6.4 L1618-1619 | Cargo |
| 145 | `se_takeownership_grants_write_owner` | SeTakeOwnershipPrivilege grants WRITE_OWNER on any object when the DACL does not independently grant it. | §6.4 L1620-1621 | Cargo |
| 146 | `pip_overrides_privilege_granted_bits` | PIP enforcement can override privilege-granted bits on trust-labeled objects. | §6.4 L1622-1623 | Cargo |
| 147 | `privileges_start_disabled` | Privileges always start disabled and must be explicitly enabled. | §6.4 L1623-1624 | Cargo |

---

### Section 6.5 — Impersonation

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 148 | `impersonation_per_thread` | Impersonation is per-thread; a server thread takes on the user's identity while other threads are unaffected. | §6.5 L1629-1633 | Provium |
| 149 | `impersonation_level_anonymous` | Anonymous level: the server cannot identify the caller. | §6.5 L1637 | Cargo |
| 150 | `impersonation_level_identification` | Identification level: the server can identify the caller but cannot act as them. | §6.5 L1638-1639 | Cargo |
| 151 | `impersonation_level_impersonation` | Impersonation level: the server can act as the caller for local operations. | §6.5 L1640-1641 | Cargo |
| 152 | `impersonation_level_delegation` | Delegation level: the server can forward the caller's identity to other services. | §6.5 L1642-1643 | Cargo |
| 153 | `revert_to_self` | A server thread can drop the impersonated identity and return to its own service identity. | §6.5 L1645-1647 | Provium |

---

### Section 6.6 — Delegation

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 154 | `delegation_requires_delegation_level` | Delegation requires the user's token to be at the Delegation impersonation level. Services cannot silently forward identities without authorization. | §6.6 L1657-1659 | Provium |
| 155 | `delegation_backend_sees_user_identity` | A back-end service sees the original user's identity, not the front-end service's identity, during delegation. | §6.6 L1653-1655 | Provium |

---

### Section 6.7 — Elevation

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 156 | `linked_tokens_elevated_and_filtered` | A principal can have two linked tokens: one elevated (full privileges) and one filtered (reduced privileges). | §6.7 L1665-1668 | Cargo |
| 157 | `filtered_token_is_default` | The filtered token is the default for day-to-day work. | §6.7 L1668 | Cargo |
| 158 | `token_elevation_type_queryable` | Each token knows whether it is elevated, filtered, or non-elevated. Services and tools can query this. | §6.7 L1672-1674 | Cargo |

---

### Section 6.8 — Token Restriction

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 159 | `restricted_token_privs_removed` | A restricted token can have privileges removed. | §6.8 L1679 | Cargo |
| 160 | `restricted_token_groups_deny_only` | A restricted token can have groups set to deny-only (they block access but don't grant it). | §6.8 L1679-1680 | Cargo |
| 161 | `restricted_token_dual_sid_check` | Access is granted only if both the normal SIDs and the restricted SIDs pass the access check independently. | §6.8 L1681-1682 | Cargo |
| 162 | `write_restricted_token_reads_normal` | A write-restricted variant subjects only write access to the restricted SID check; reads use the normal SID list. | §6.8 L1682-1684 | Cargo |
| 163 | `child_process_restriction_flag` | A process can be flagged (via PSB) to prevent it from creating child processes entirely. | §6.8 L1686-1688 | Provium |

---

### Section 6.9 — Application Confinement

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 164 | `confinement_default_deny` | A confined token is default-deny: the process can only access objects that explicitly grant access to its confinement SID, its capability SIDs, or `ALL_APPLICATION_PACKAGES`. | §6.9 L1693-1696 | Cargo |
| 165 | `confinement_accesscheck_behavior` | Confined tokens are denied by default in AccessCheck unless the object explicitly opts in. This is real kernel behavior in AccessCheck, not just group membership. | §6.9 L1697-1699 | Cargo |
| 166 | `confinement_capability_sids` | Confined services declare what they need via capability SIDs. Objects can grant access to specific capability SIDs. | §6.9 L1701-1703 | Cargo |
| 167 | `confinement_scope_enforced` | A service that declares only filesystem access cannot touch the network, even if its user identity would otherwise permit it. | §6.9 L1703-1705 | Provium |
| 168 | `lpac_no_all_app_packages` | LPAC is a confined token that lacks the `ALL_APPLICATION_PACKAGES` group; retains `ALL_RESTRICTED_APPLICATION_PACKAGES` instead. | §6.9 L1707-1713 | Cargo |
| 169 | `lpac_smaller_access_surface` | LPAC tokens have a smaller default access surface because fewer objects grant to `ALL_RESTRICTED_APPLICATION_PACKAGES`. | §6.9 L1710-1712 | Cargo |
| 170 | `lpac_kernel_eval_identical` | The kernel evaluation for LPAC is identical to normal confinement; the difference is purely which well-known SIDs are in the token's groups. | §6.9 L1712-1713 | Cargo |
| 171 | `confinement_exempt_flag` | A confinement-exempt token has confinement restrictions not evaluated. | §6.9 L1715-1717 | Cargo |

---

### Section 6.10 — Process Protection (PIP)

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 172 | `pip_trust_label_in_sacl` | Objects carry a `SYSTEM_PROCESS_TRUST_LABEL_ACE` in their SACL that defines a PIP trust level. | §6.10 L1726-1727 | Cargo |
| 173 | `pip_2d_model_type_and_level` | PIP identity is a 2D model: type x trust level. | §6.10 L1728 | Cargo |
| 174 | `pip_revokes_privilege_bits` | Unlike MIC, PIP actively revokes privilege-granted bits — even SeBackupPrivilege and SeTakeOwnershipPrivilege cannot bypass PIP. | §6.10 L1729-1731 | Cargo |
| 175 | `pip_ptrace_blocked` | Kernel hooks on ptrace enforce PIP: even full admin privileges cannot ptrace a PIP-protected process. | §6.10 L1733-1737 | Provium |
| 176 | `pip_memory_access_blocked` | Kernel hooks on memory access enforce PIP: even full admin privileges cannot read memory of a PIP-protected process. | §6.10 L1733-1737 | Provium |
| 177 | `pip_signal_delivery_blocked` | Kernel hooks on signal delivery enforce PIP: even full admin privileges cannot send signals to a PIP-protected process. | §6.10 L1733-1737 | Provium |

---

### Section 6.11 — Claims & Conditional Access

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 178 | `user_claims_on_token` | Tokens carry name-value user claims (e.g., `department=engineering`, `clearance=3`). | §6.11 L1741-1743 | Cargo |
| 179 | `user_claims_feed_conditional_ace` | User claims feed into conditional ACE evaluation. | §6.11 L1743 | Cargo |
| 180 | `device_claims_on_machine_token` | The machine's token carries its own device claim attributes. | §6.11 L1745-1747 | Cargo |
| 181 | `compound_identity_user_and_machine` | Access decisions consider both user identity and machine identity simultaneously. A conditional ACE can require user group AND machine group. Neither alone is sufficient. | §6.11 L1750-1753 | Cargo |

---

### Section 6.12 — Audit

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 182 | `sacl_object_audit` | Objects can have audit rules in their SACL evaluated by the same AccessCheck engine. | §6.12 L1757-1761 | Cargo |
| 183 | `sacl_same_sid_matching_as_dacl` | Audit rules use the same SID matching, inheritance, and vocabulary as access rules. | §6.12 L1760-1761 | Cargo |
| 184 | `per_token_audit_policy` | Per-token audit policy overrides system-wide audit settings for specific tokens via a per-category bitmask. | §6.12 L1763-1766 | Cargo |
| 185 | `per_token_audit_additive` | Per-token audit is additive: can force audits, cannot suppress them. | §6.12 L1768 | Cargo |
| 186 | `per_token_audit_follows_impersonation` | Per-token audit policy follows impersonation. | §6.12 L1768-1769 | Provium |
| 187 | `privilege_use_audit` | When a privilege is exercised to grant access, the privilege use is recorded in the audit trail. | §6.12 L1771-1774 | Cargo |

---

### Section 6.13 — File Access Control

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 188 | `facs_sd_in_xattr` | Files are protected by Security Descriptors stored in filesystem extended attributes. | §6.13 L1779-1780 | Provium |
| 189 | `facs_replaces_uid_gid_mode` | FACS replaces Linux's UID/GID/mode-bit system. | §6.13 L1780 | Provium |
| 190 | `facs_same_acl_model_as_registry` | The same ACL model that protects registry keys and IPC endpoints protects files. | §6.13 L1780-1781 | Cargo |
| 191 | `facs_sd_inheritance_propagates` | Setting a DACL on a directory automatically propagates it to all files and subdirectories. | §6.13 L1783-1786 | Provium |

---

### Section 6.16 — Linux Compatibility (summary)

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 192 | `anonymous_impersonation_any_thread` | Any thread can assume the Anonymous identity (S-1-5-7) for operations that should execute at the lowest possible trust level. | §6.16 L1821-1823 | Provium |

---

### Summary Counts

- **Total tests extracted: 192**
- **Cargo tests (pure Rust logic, no kernel): 68**
- **Provium tests (requires booted KACS kernel): 124**

The Cargo tests cluster around AccessCheck evaluation logic (DACL ordered evaluation, conditional ACEs, inheritance flags, owner implicit grants, OWNER RIGHTS override, MIC no-write-up, PIP trust label revocation, privilege enable/disable semantics, restricted token dual-SID check, confinement default-deny, SD binary format correctness, SID parsing and comparison, token elevation types, claims evaluation, audit SACL matching).

The Provium tests cluster around syscall interception and kernel behavior (credential projection via getuid/getgid/getgroups, /proc visibility, capability switchboard enforcement for all 41 capabilities, setuid() no-op vs swap behavior, setuid bit on exec, seccomp filter installation, DAC neutralization, signal delivery authorization, PIP kernel hooks for ptrace/memory/signals, FACS xattr storage, SD inheritance propagation, process creation restrictions, impersonation per-thread lifecycle, logon session invalidation).


---

# Section 7: Tokens + Section 8: Process Security Block

## Exhaustive Test Corpus: KACS Specification §7 (Tokens) and §8 (Process Security Block)

---

### §7.0 Token Fundamentals (lines 1850-1923)

#### Cargo
- `token_is_refcounted_kernel_object`: Token is a separately-allocated, refcounted KACS kernel object [§7, line 1857]
- `cred_blob_holds_pointer_not_data`: The credential's LSM security blob holds a pointer to the token, not the token data itself [§7, line 1858]
- `token_carries_all_identity_fields`: Token carries SIDs, group memberships, privileges, integrity level, claims, and security policy [§7, lines 1859-1860]
- `token_supersedes_credential_for_kacs`: For all KACS-mediated access control decisions, the token supersedes traditional credential attributes [§7, lines 1861-1862]
- `token_mutation_no_cred_realloc`: Token-internal mutations (privilege enable/disable, group adjustment) do not require credential reallocation [§7, lines 1870-1872]
- `credential_immutable_token_mutable`: The credential is immutable after commit; the token it points to is not [§7, lines 1872-1873]
- `adjust_privilege_visible_to_all_sharers`: AdjustTokenPrivileges modifies the token in place; all threads sharing that token see the change immediately [§7, lines 1876-1878]
- `real_cred_holds_primary_token`: real_cred's LSM blob holds a pointer to the primary token (baseline identity inherited from parent on fork) [§7, lines 1891-1894]
- `cred_holds_effective_token`: cred's LSM blob holds a pointer to the effective token (either primary or impersonation) [§7, lines 1896-1900]
- `no_impersonation_same_cred_same_token`: In the common case (no impersonation), real_cred and cred point to the same struct cred, and both resolve to the same token object [§7, lines 1902-1903]
- `all_threads_share_primary_token`: All threads in a process share the primary token; privilege adjustments on the primary token are visible to every thread [§7, lines 1904-1906]
- `impersonation_is_cred_swap`: Impersonation is a credential swap: the thread's cred is pointed at a new struct cred whose LSM blob points to a different token object [§7, lines 1908-1909]
- `revert_restores_real_cred`: Reverting to self restores cred to real_cred [§7, line 1910]
- `projection_one_way_token_to_cred`: Credential projection is one-way: token state flows into credential fields, never the reverse [§7, lines 1918-1919]
- `projected_creds_observational_only`: Projected credentials are observational compatibility data; the token is the authority [§7, lines 1921-1922]

#### Provium
- `thread_identity_divergence`: Two threads in the same process can carry different effective tokens (one impersonating, one not) [§7, lines 1884-1886]
- `impersonation_swap_rcu_safe`: Impersonation swap uses override_creds/revert_creds and is atomically and RCU-safely handled [§7, lines 1911-1914]

---

### §7.1 Token Evaluation and Asynchronous Kernel Contexts (lines 1924-1993)

#### Cargo
- `access_check_at_synchronous_boundary`: Authorization is evaluated once at the synchronous boundary where the user requests access [§7.1, lines 1948-1950]
- `cached_mask_on_file_lsm_blob`: The granted access mask from AccessCheck at open() is cached on the file's LSM blob [§7.1, lines 1958-1960]
- `open_handles_survive_sd_changes`: Open handles survive subsequent SD changes; if a file's DACL is modified to deny access after open, existing fd retains its cached grants [§7.1, lines 1961-1966]

#### Provium
- `file_access_check_at_open`: AccessCheck runs at open() via security_file_open LSM hook [§7.1, lines 1958-1959]
- `reads_writes_verify_cached_mask`: Reads and writes verify the cached mask, not re-evaluate identity [§7.1, lines 1960-1961]
- `writeback_no_identity_reevaluation`: Writeback, journaling, and other deferred I/O never re-evaluate identity [§7.1, lines 1961-1962]
- `ipc_access_check_at_connect`: IPC AccessCheck runs at connection time; messages authorized by connection's cached state [§7.1, lines 1970-1972]
- `io_uring_captures_submitter_cred`: io_uring captures the submitter's effective credential at submission time and applies it to worker threads via override_creds [§7.1, lines 1974-1976]
- `io_uring_impersonation_token_honored`: Operations submitted through io_uring are evaluated under the submitter's identity including impersonation tokens [§7.1, lines 1977-1979]
- `kthread_no_override_hard_deny`: LSM hooks that detect running without a meaningful user context (PF_KTHREAD without override, interrupt context) must hard-deny rather than evaluate a meaningless identity [§7.1, lines 1991-1993]
- `kernel_maintenance_implicitly_trusted`: Kernel-internal maintenance (writeback, journaling, memory reclaim, deferred fput) operates on already-authorized file objects [§7.1, lines 1981-1984]

---

### §7.2 External Token Replacement (lines 1995-2037)

#### Cargo
- `external_replacement_primary_only`: If a thread is impersonating, replacement affects real_cred (primary token) only; impersonation state is left intact until the thread reverts [§7.2, lines 2009-2010]

#### Provium
- `external_token_replacement_via_task_work`: External token replacement uses task_work_add to queue a credential swap on each task in the target thread group [§7.2, lines 2004-2005]
- `each_task_executes_own_swap`: Each task executes the swap in its own context (prepare_creds, set new token pointer, commit_creds), preserving RCU safety [§7.2, lines 2005-2007]
- `gated_by_assign_primary_privilege`: External token replacement is gated by SeAssignPrimaryTokenPrivilege [§7.2, line 2008]
- `non_atomic_window_acceptable`: Brief transition window where some threads have new token while others still have old is acceptable because replacement is always a privilege downgrade [§7.2, lines 2012-2016]
- `no_completion_semantics`: No barrier or acknowledgment mechanism; caller cannot determine when all threads have executed the swap [§7.2, lines 2018-2019]
- `v1_mitigation_filter_token`: v1 mitigation: peinit uses FilterToken to create a copy of the SYSTEM token with dangerous privileges permanently deleted for pre-authd services [§7.2, lines 2025-2032]

---

### §7.3 Token Object Model (lines 2039-2231)

#### Identity Core

##### Cargo
- `token_user_sid_required`: Token must always have a user_sid (SID type), never None [§7.3, line 2055]
- `token_user_sid_immutable`: user_sid is immutable after creation [§7.3 identity core, line 2051]
- `token_user_deny_only_immutable`: user_deny_only is immutable after creation [§7.3, line 2056]
- `user_deny_only_matches_deny_aces_only`: If user_deny_only is true, user SID matches only deny ACEs, not allow ACEs [§7.3, line 2056]
- `user_deny_only_set_by_filter_token`: user_deny_only is set by FilterToken when creating a write-restricted token [§7.3, line 2056]
- `groups_sids_immutable_attrs_atomic`: Group SIDs are immutable; per-group attribute flags are atomic (mutable) [§7.3, line 2057]
- `logon_sid_immutable`: logon_sid is immutable after creation [§7.3, line 2058]
- `logon_sid_format`: logon_sid is per-authentication-event SID (S-1-5-5-x-y) [§7.3, line 2058]
- `restricted_sids_immutable_after_creation`: restricted_sids are set by FilterToken at creation, immutable after [§7.3, line 2059]
- `restricted_sids_nullable`: restricted_sids is null on unrestricted tokens [§7.3, line 2059]
- `write_restricted_immutable`: write_restricted is immutable after creation [§7.3, line 2060]
- `write_restricted_restricts_write_only`: If write_restricted is true, restricted SID check applies only to write access; read access uses normal SID list only [§7.3, line 2060]
- `adjust_groups_cannot_add_remove_sids`: NtAdjustGroupsToken can enable/disable groups by flipping SE_GROUP_ENABLED but cannot add or remove SIDs from the list [§7.3, lines 2062-2064]
- `mandatory_groups_cannot_be_disabled`: Mandatory groups (SE_GROUP_MANDATORY) cannot be disabled [§7.3, lines 2064-2065]
- `deny_only_groups_permanent`: Deny-only groups (SE_GROUP_USE_FOR_DENY_ONLY) are permanently set via FilterToken and cannot be reverted [§7.3, lines 2065-2066]

#### Token Type

##### Cargo
- `token_type_primary_or_impersonation`: token_type is an enum: Primary or Impersonation, immutable [§7.3, line 2072]
- `impersonation_level_enum_values`: impersonation_level is enum: Anonymous, Identification, Impersonation, Delegation [§7.3, line 2073]
- `impersonation_level_meaningful_on_impersonation_only`: impersonation_level is meaningful only on impersonation tokens [§7.3, line 2073]
- `token_type_immutable`: token_type is immutable after creation [§7.3, line 2068]

#### Integrity

##### Cargo
- `integrity_level_enum_values`: integrity_level is enum: Untrusted, Low, Medium, High, System [§7.3, line 2079]
- `integrity_level_immutable`: integrity_level is immutable after creation [§7.3, line 2079]
- `mandatory_policy_immutable`: mandatory_policy flags are immutable after creation [§7.3, line 2080]
- `mandatory_policy_flags`: mandatory_policy contains NO_WRITE_UP and NEW_PROCESS_MIN flags [§7.3, line 2080]
- `mandatory_policy_set_at_creation_by_authd`: mandatory_policy is set at token creation time by authd [§7.3, line 2080]

#### Privileges

##### Cargo
- `privilege_present_bits_one_way_clear`: Bits in privileges_present can be cleared (removal is permanent) but never set [§7.3, line 2086]
- `privilege_enabled_toggleable`: privileges_enabled bits are toggleable for non-removed privileges [§7.3, line 2087]
- `privilege_enabled_by_default_is_reset_position`: privileges_enabled_by_default is the reset position; AdjustTokenPrivileges can restore all privileges to this state [§7.3, line 2088]
- `privilege_used_tracks_exercise`: privileges_used flags set when a privilege is actually exercised; audit trail [§7.3, line 2089]
- `privilege_lifecycle`: A privilege's lifecycle on a token: present and disabled -> enabled -> used -> optionally disabled again -> optionally permanently removed [§7.3, lines 2091-2094]
- `privilege_removal_clears_all_masks`: Removal clears the bit in all three masks (privileges_present, privileges_enabled, privileges_enabled_by_default) [§7.3, line 2094]
- `cannot_enable_non_present_privilege`: Privileges that are not present cannot be enabled [§7.3, implied by line 2086]

#### Elevation

##### Cargo
- `elevation_type_enum_values`: elevation_type is enum: Default (non-elevated context), Full (elevated), Limited (filtered) [§7.3, line 2100]
- `elevation_type_immutable`: elevation_type is immutable after creation [§7.3, line 2096]
- `linked_token_nullable`: linked_token is null for non-elevated tokens [§7.3, line 2101]

#### Default Object Security

##### Cargo
- `owner_sid_index_must_reference_valid`: owner_sid_index must reference user SID or a group with SE_GROUP_OWNER [§7.3, line 2107]
- `owner_sid_index_is_atomic`: owner_sid_index is mutable via atomic operations [§7.3, line 2107]
- `primary_group_index_is_atomic`: primary_group_index is mutable via atomic operations [§7.3, line 2108]
- `default_dacl_is_rcu`: default_dacl is mutable via RCU pointer replacement [§7.3, line 2109]
- `indices_reference_user_plus_groups`: Owner and primary group are stored as indices into the token's SID arrays (user+groups), not as separate SID copies [§7.3, lines 2111-2112]

#### Metadata

##### Cargo
- `token_id_is_luid`: token_id is a LUID unique identifier for this token instance [§7.3, line 2119]
- `auth_id_is_luid`: auth_id is a logon session LUID linking to the authentication event [§7.3, line 2120]
- `token_source_format`: source is TOKEN_SOURCE: 8-char name + LUID [§7.3, line 2121]
- `expiration_zero_means_no_expiry`: expiration timestamp zero means no expiry [§7.3, line 2123]
- `origin_luid_for_derived_tokens`: origin is LUID for originating logon session for derived tokens (S4U, network logon) [§7.3, line 2124]
- `created_at_is_timestamp`: created_at is a timestamp recording when the token was created [§7.3, line 2122]

#### Mutation Tracking

##### Cargo
- `modified_id_increments_on_mutation`: modified_id counter incremented on any token mutation [§7.3, line 2130]
- `modified_id_is_cache_invalidation_key`: If modified_id changed since last AccessCheck, cached decisions are stale [§7.3, line 2130]

#### Session

##### Cargo
- `session_id_zero_for_services`: interactive_session_id is 0 for services, 1+ for interactive/remote [§7.3, line 2136]
- `session_id_mutable_requires_tcb`: interactive_session_id is mutable but requires SeTcbPrivilege [§7.3, line 2136]

#### Claims and Security Attributes

##### Cargo
- `user_claims_immutable`: user_claims (CLAIM_ATTRIBUTES name-value pairs) are immutable after creation [§7.3, line 2138]
- `device_claims_immutable`: device_claims are immutable after creation [§7.3, line 2143]
- `claims_fed_into_conditional_ace`: Claims are fed into conditional ACE evaluation [§7.3, line 2142]

#### Device Identity

##### Cargo
- `device_groups_immutable`: device_groups (SID_AND_ATTRIBUTES) are immutable after creation [§7.3, line 2145]
- `device_groups_nullable`: device_groups is nullable (null when not applicable) [§7.3, line 2149]
- `restricted_device_groups_immutable`: restricted_device_groups are immutable after creation [§7.3, line 2150]

#### Confinement

##### Cargo
- `confinement_sid_nullable`: confinement_sid is null when not confined [§7.3, line 2156]
- `confinement_sid_immutable`: confinement_sid is immutable after creation [§7.3, line 2152]
- `confinement_switches_to_default_deny`: When confinement_sid is set, AccessCheck switches to default-deny: access requires explicit grant to this SID, a capability SID, or ALL_APPLICATION_PACKAGES [§7.3, line 2156]
- `confinement_capabilities_nullable`: confinement_capabilities are nullable [§7.3, line 2157]
- `isolation_boundary_requires_confinement_sid`: isolation_boundary requires confinement_sid to be set [§7.3, line 2158]
- `isolation_boundary_enables_namespace_filtering`: isolation_boundary enables namespace filtering on top of DACL-based confinement; objects outside the boundary are invisible, not just access-denied [§7.3, line 2158]
- `confinement_exempt_bypasses_restrictions`: When confinement_exempt is true, confinement restrictions are not evaluated [§7.3, line 2159]

#### Audit

##### Cargo
- `audit_policy_additive_only`: audit_policy is additive; forces audit events that system-wide policy would not generate but cannot suppress events that system-wide policy requires [§7.3, lines 2175-2176]
- `audit_policy_follows_impersonation`: audit_policy follows impersonation; if service A impersonates client B and B's token has syscall auditing enabled, syscalls during impersonation are audited under B's identity [§7.3, lines 2182-2185]
- `audit_policy_consulted_during_sacl_emission`: AccessCheck consults audit_policy during SACL audit emission; if the token's policy flags success or failure for the object access category, emit audit event regardless of matching SACL audit ACE [§7.3, lines 2187-2190]

#### Credential Projection

##### Cargo
- `projected_uid_from_sid_uid_number`: projected_uid is pre-computed UID from user SID's AD uidNumber; 65534 if unmapped [§7.3, line 2200]
- `projected_gid_from_primary_group`: projected_gid is from primary group SID's gidNumber; falls back to SID's uidNumber if primary group is a user SID; 65534 if unmapped [§7.3, line 2201]
- `projected_supplementary_gids_from_groups`: projected_supplementary_gids from group SIDs where gidNumber attributes exist [§7.3, line 2202]
- `projection_computed_at_creation_stored_on_token`: Computed by authd at token creation time, stored on the token [§7.3, line 2204]
- `kacs_never_resolves_sid_to_uid_at_runtime`: KACS never resolves SID-to-UID mappings at runtime [§7.3, lines 2205-2206]
- `projection_reflects_all_groups_regardless_of_enabled`: Projection reflects all groups on the token regardless of their enabled/disabled state [§7.3, lines 2206-2207]
- `adjust_groups_no_projection_recalc`: AdjustGroups does not trigger projection recalculation [§7.3, lines 2207-2208]
- `authd_unified_counter_for_uid_gid`: authd must allocate uidNumber/gidNumber values from a single unified counter across all principal types [§7.3, lines 2212-2213]

#### Token Security

##### Cargo
- `token_has_own_sd`: Every token has its own SD controlling who can query, adjust, duplicate, or impersonate the token [§7.3, lines 2222-2224]
- `token_sd_is_rcu_mutable`: token security_descriptor is mutable via RCU [§7.3, line 2220]

#### Internal

##### Cargo
- `token_freed_when_last_ref_drops`: Token freed when last reference (refcount) drops [§7.3, line 2230]
- `refcount_not_exposed_to_userspace`: refcount is internal, not exposed to userspace [§7.3, line 2226]

---

### §7.4 Token Lifecycle Across Fork and Exec (lines 2232-2295)

#### Cargo
- `fork_deep_copies_primary_token`: Clone without CLONE_THREAD: child gets independent deep copy of parent's primary token [§7.4, lines 2238-2240]
- `fork_does_not_inherit_impersonation`: If parent is impersonating, the impersonation token is not inherited; child's effective credential is set from real_cred [§7.4, lines 2241-2242]
- `fork_mutations_invisible_to_other`: After fork, mutations to either token are invisible to the other [§7.4, lines 2242-2243]
- `clone_thread_shares_primary_token`: Clone with CLONE_THREAD: threads share the parent's real_cred (refcounted) and therefore share the same primary token object [§7.4, lines 2247-2249]
- `thread_priv_adjustments_visible_all`: Privilege adjustments on the primary token are visible to all threads [§7.4, lines 2249-2250]
- `thread_independent_impersonation`: Each thread maintains independent impersonation state via its own cred; new thread does not inherit another thread's impersonation [§7.4, lines 2250-2253]
- `exec_primary_token_survives`: Primary token survives execve unchanged unless NEW_PROCESS_MIN replaces it [§7.4, lines 2255-2256]
- `exec_reverts_impersonation`: If the calling thread is impersonating, impersonation is reverted before the new program runs (enforced in security_bprm_creds_for_exec) [§7.4, lines 2256-2258]
- `exec_starts_with_primary_token`: The new program always starts with the primary token as its effective identity [§7.4, lines 2258-2259]
- `new_process_min_can_only_lower`: NEW_PROCESS_MIN can only lower integrity, never raise it; child's integrity is always <= parent's [§7.4, lines 2292-2293]
- `new_process_min_creates_new_token`: NEW_PROCESS_MIN creates a new token rather than mutating an existing one, preserving token immutability [§7.4, lines 2280-2283]
- `new_process_min_integrity_from_file_label`: If file's integrity < token's integrity, create a new token with integrity_level set to the file's label; all other fields copied unchanged [§7.4, lines 2274-2276]
- `new_process_min_no_action_if_file_ge_token`: If file's integrity >= token's integrity, no action; fork'd token survives exec unchanged [§7.4, lines 2277-2278]
- `new_process_min_default_medium`: If the file has no label, use the default (Medium) [§7.4, lines 2271-2272]
- `new_process_min_flag_immutable`: The NEW_PROCESS_MIN flag is immutable on the token (set by authd at creation) [§7.4, lines 2293-2294]

#### Provium
- `fork_child_primary_token_independent`: After fork, parent and child have independent token objects; mutating parent's privileges does not affect child [§7.4]
- `fork_impersonating_parent_child_gets_primary`: If parent thread is impersonating, forked child starts with parent's primary (not impersonation) token [§7.4]
- `clone_thread_shares_primary_token_object`: New thread shares the same primary token object as siblings; privilege change visible to all threads [§7.4]
- `new_thread_no_inherit_impersonation`: A new thread does not inherit the creating thread's impersonation state [§7.4]
- `exec_reverts_impersonation_provium`: Thread impersonating calls execve; the new program starts with primary token, impersonation is reverted [§7.4]
- `exec_preserves_primary_token`: Primary token survives exec unchanged (no NEW_PROCESS_MIN) [§7.4]
- `new_process_min_lowers_integrity_on_exec`: Token with NEW_PROCESS_MIN policy: exec of lower-integrity-labeled binary creates new token with lower integrity [§7.4]
- `new_process_min_no_action_high_integrity_file`: Token with NEW_PROCESS_MIN: exec of same-or-higher-integrity-labeled binary keeps token unchanged [§7.4]
- `token_assignment_between_fork_and_exec`: peinit forks, installs service's token on child via SeAssignPrimaryTokenPrivilege, then child execs service binary [§7.4, lines 2260-2263]

---

### §7.5 Token Creation (lines 2296-2400)

#### Kernel Bootstrap

##### Cargo
- `system_token_user_sid`: SYSTEM token has user SID S-1-5-18 [§7.5, line 2306]
- `system_token_groups`: SYSTEM token includes BUILTIN\Administrators (S-1-5-32-544), Authenticated Users, and other well-known SIDs [§7.5, lines 2307-2308]
- `system_token_all_privileges`: SYSTEM token has all defined privileges, present and enabled [§7.5, line 2309]
- `system_token_system_integrity`: SYSTEM token has System integrity level [§7.5, line 2310]
- `system_token_primary_type`: SYSTEM token has token type Primary [§7.5, line 2311]
- `system_token_elevation_default`: SYSTEM token has elevation type Default (no linked token) [§7.5, line 2312]
- `system_token_source`: SYSTEM token source is "PeiosKrn" [§7.5, line 2313]
- `system_token_projects_uid_zero`: Credential projection maps SYSTEM to UID 0 [§7.5, line 2318]

##### Provium
- `system_token_assigned_to_init`: SYSTEM token is assigned to the kernel's init task and inherited by PID 1 on exec [§7.5, lines 2316-2318]
- `system_token_no_syscall`: No syscall is involved in SYSTEM token creation; kernel allocates directly during init [§7.5, lines 2315-2316]

#### CreateToken

##### Cargo
- `create_token_requires_privilege`: CreateToken is gated by SeCreateTokenPrivilege [§7.5, line 2326]
- `create_token_kernel_generates_token_id`: Kernel generates token_id (LUID) [§7.5, line 2334]
- `create_token_kernel_generates_modified_id`: Kernel generates modified_id (initialized to token_id) [§7.5, line 2335]
- `create_token_kernel_generates_created_at`: Kernel generates created_at (current time) [§7.5, line 2335]
- `create_token_kernel_generates_default_sd`: Kernel generates token SD (default SD described in §7.9) [§7.5, lines 2335-2336]
- `create_token_validates_sids_wellformed`: Kernel validates all SIDs are structurally well-formed [§7.5, line 2342]
- `create_token_validates_owner_sid`: Owner SID must be user SID or a group with SE_GROUP_OWNER; kernel resolves to owner_sid_index [§7.5, lines 2343-2344]
- `create_token_validates_primary_group_sid`: Primary group SID must be user SID or a group SID on the token; kernel resolves to primary_group_index [§7.5, lines 2344-2346]
- `create_token_validates_auth_id`: auth_id must reference an existing logon session object [§7.5, line 2347]
- `create_token_kernel_does_not_authenticate`: Kernel does not authenticate the user, look up SIDs in directory, resolve SID-to-UID mappings, or validate principal actually exists [§7.5, lines 2352-2354]

##### Provium
- `create_token_returns_token_fd`: CreateToken returns a token fd to the caller [§7.5, line 2350]
- `create_token_without_privilege_denied`: Attempting CreateToken without SeCreateTokenPrivilege fails [§7.5]
- `create_token_invalid_owner_sid_rejected`: CreateToken with owner SID that is neither user SID nor group with SE_GROUP_OWNER is rejected [§7.5]
- `create_token_invalid_primary_group_rejected`: CreateToken with primary group SID not in user+groups is rejected [§7.5]
- `create_token_invalid_auth_id_rejected`: CreateToken with auth_id referencing nonexistent logon session is rejected [§7.5]
- `create_token_malformed_sid_rejected`: CreateToken with structurally malformed SID is rejected [§7.5]

#### DuplicateToken

##### Cargo
- `duplicate_requires_token_duplicate`: DuplicateToken requires TOKEN_DUPLICATE access on the source token [§7.5, lines 2360-2361]
- `duplicate_can_change_token_type`: Caller can change token type (primary <-> impersonation) during duplication [§7.5, line 2365]
- `duplicate_impersonation_level_no_escalation`: Impersonation level can only be equal to or lower than the source token's level; escalation is forbidden [§7.5, lines 2366-2368]
- `duplicate_can_change_token_sd`: Caller can set the new token's own security descriptor [§7.5, line 2369]
- `duplicate_copies_everything_else_verbatim`: Everything other than token type, impersonation level, and SD is copied verbatim [§7.5, line 2371]
- `duplicate_linked_token_not_copied`: Linked token relationship is not copied; elevation_type is reset to Default [§7.5, lines 2372-2374]
- `duplicate_gets_own_token_id`: New token gets its own token_id [§7.5, line 2375]
- `duplicate_modified_id_resets`: modified_id resets on duplicate [§7.5, line 2375]
- `duplicate_original_unaffected`: The original token is unaffected by duplication [§7.5, line 2375]

##### Provium
- `duplicate_identification_to_impersonation_denied`: An Identification-level token cannot be duplicated as Impersonation (escalation forbidden) [§7.5, lines 2367-2368]
- `duplicate_impersonation_to_identification_allowed`: Downgrading impersonation level during duplication succeeds [§7.5]
- `duplicate_primary_to_impersonation`: Duplicating a primary token as impersonation token succeeds [§7.5]
- `duplicate_without_access_right_denied`: DuplicateToken without TOKEN_DUPLICATE access right on source fails [§7.5]

#### FilterToken

##### Cargo
- `filter_requires_token_duplicate`: FilterToken requires TOKEN_DUPLICATE access on the source token [§7.5, lines 2379-2380]
- `filter_can_remove_privileges`: FilterToken can permanently delete specified privileges from the new token [§7.5, lines 2382-2383]
- `filter_can_set_groups_deny_only`: FilterToken can set specified groups to SE_GROUP_USE_FOR_DENY_ONLY; permanent, cannot be reverted [§7.5, lines 2384-2386]
- `filter_deny_only_blocks_not_grants`: Deny-only groups can block access via deny ACEs but cannot grant access [§7.5, line 2385]
- `filter_can_add_restricted_sids`: FilterToken can add a secondary SID list (restricted_sids) to the new token [§7.5, lines 2387-2389]
- `filter_restricted_token_dual_check`: AccessCheck runs twice on restricted tokens; access granted only if both normal SIDs and restricted SIDs independently pass [§7.5, lines 2388-2389]
- `filter_write_restricted_mode`: Write-restricted mode limits restricted SID check to write operations only; read access uses normal SID list, bypassing restricted SID evaluation [§7.5, lines 2390-2393]
- `filter_creates_new_token`: FilterToken creates a new token object; original is untouched [§7.5, line 2394]
- `filter_born_restricted`: Result is born restricted (creation with different initial state, not mutation) [§7.5, lines 2395-2396]
- `filter_preserves_group_sid_immutability`: FilterToken changes per-group attribute flags and adds restricted SID list but does not add or remove SIDs from group list itself [§7.5, lines 2396-2399]

##### Provium
- `filter_token_removes_privilege`: FilterToken with privilege removal produces token without that privilege [§7.5]
- `filter_token_deny_only_group`: FilterToken with deny-only group: group in result blocks via deny ACEs but does not grant access [§7.5]
- `filter_token_restricted_sids_dual_check`: AccessCheck on filtered token with restricted SIDs requires both SID lists to independently pass [§7.5]
- `filter_token_write_restricted_read_bypass`: Write-restricted filtered token: read access bypasses restricted SID check [§7.5]
- `filter_token_without_access_right_denied`: FilterToken without TOKEN_DUPLICATE access on source fails [§7.5]

---

### §7.6 Token Adjustment (lines 2401-2471)

#### AdjustPrivileges

##### Cargo
- `adjust_priv_requires_access_right`: AdjustPrivileges requires TOKEN_ADJUST_PRIVILEGES on the token [§7.6, line 2409]
- `adjust_priv_enable_disable_present_only`: Enable/disable flips bits in privileges_enabled for privileges that are present on the token; privileges not present cannot be enabled [§7.6, lines 2412-2415]
- `adjust_priv_cannot_grant_new`: Enable/disable cannot grant new privileges, only activate existing ones [§7.6, lines 2414-2415]
- `adjust_priv_reset_to_defaults`: Reset restores privileges_enabled to match privileges_enabled_by_default [§7.6, lines 2416-2418]
- `adjust_priv_remove_permanent`: Remove permanently deletes a privilege; clears the bit in all three masks (present, enabled, enabled_by_default) [§7.6, lines 2419-2421]
- `adjust_priv_remove_irreversible`: Removal is irreversible; the privilege cannot be re-added [§7.6, line 2421]
- `adjust_priv_remove_sets_used_for_audit`: Removal sets privileges_used for audit if the privilege was exercised before removal [§7.6, lines 2422-2423]
- `adjust_priv_returns_previous_state`: Caller receives a report of the previous state of each adjusted privilege [§7.6, lines 2425-2427]

##### Provium
- `adjust_priv_enable_disable_roundtrip`: Enable a present privilege, verify it is active; disable it, verify it is inactive [§7.6]
- `adjust_priv_enable_nonpresent_fails`: Attempting to enable a privilege not present on the token fails [§7.6]
- `adjust_priv_remove_then_enable_fails`: Remove a privilege, then attempt to enable it; operation fails [§7.6]
- `adjust_priv_reset_to_defaults_restores`: After enable/disable changes, reset restores all to default state [§7.6]
- `adjust_priv_without_access_right_denied`: AdjustPrivileges without TOKEN_ADJUST_PRIVILEGES access right fails [§7.6]
- `adjust_priv_visible_to_all_threads`: Privilege adjustment on primary token visible to all threads sharing it [§7.6]

#### AdjustGroups

##### Cargo
- `adjust_groups_requires_access_right`: AdjustGroups requires TOKEN_ADJUST_GROUPS on the token [§7.6, line 2431]
- `adjust_groups_enable_disable`: Enable/disable flips SE_GROUP_ENABLED on individual groups [§7.6, lines 2433-2434]
- `adjust_groups_mandatory_cannot_disable`: SE_GROUP_MANDATORY groups cannot be disabled [§7.6, lines 2435-2436]
- `adjust_groups_deny_only_cannot_reenable`: SE_GROUP_USE_FOR_DENY_ONLY groups cannot be re-enabled [§7.6, lines 2437-2438]
- `adjust_groups_logon_sid_cannot_disable`: Logon SID cannot be disabled [§7.6, line 2440]
- `adjust_groups_user_sid_cannot_disable`: User SID (if present in group list) cannot be disabled [§7.6, line 2441]
- `adjust_groups_reset_to_defaults`: Reset restores all groups to their creation-time enabled/disabled state [§7.6, lines 2442-2443]
- `adjust_groups_returns_previous_state`: Caller receives a report of previous state [§7.6, lines 2445-2446]

##### Provium
- `adjust_groups_disable_nonmandatory`: Disable a non-mandatory group; verify it no longer grants access [§7.6]
- `adjust_groups_disable_mandatory_fails`: Attempting to disable a mandatory group fails [§7.6]
- `adjust_groups_enable_deny_only_fails`: Attempting to re-enable a deny-only group fails [§7.6]
- `adjust_groups_disable_logon_sid_fails`: Attempting to disable the logon SID fails [§7.6]
- `adjust_groups_disable_user_sid_fails`: Attempting to disable the user SID in the group list fails [§7.6]
- `adjust_groups_reset_restores_creation_state`: After changes, reset restores all groups to creation-time state [§7.6]
- `adjust_groups_without_access_right_denied`: AdjustGroups without TOKEN_ADJUST_GROUPS fails [§7.6]

#### AdjustDefault

##### Cargo
- `adjust_default_requires_access_right`: AdjustDefault requires TOKEN_ADJUST_DEFAULT on the token [§7.6, line 2450]
- `adjust_default_dacl_rcu_swap`: Default DACL replacement is an RCU pointer swap; readers see old or new value, never partial update [§7.6, lines 2452-2454]
- `adjust_default_owner_must_be_valid`: Owner SID index must reference user SID or a group with SE_GROUP_OWNER on the token [§7.6, lines 2456-2457]
- `adjust_default_primary_group_must_be_valid`: Primary group index must reference user SID or a group SID on the token [§7.6, lines 2458-2459]
- `adjust_default_affects_future_only`: Adjustments affect future object creation only; existing objects are unaffected [§7.6, lines 2462-2463]
- `adjust_default_no_escalation`: No escalation possible: caller chooses among SIDs already on their token, not adding new ones [§7.6, lines 2463-2464]

##### Provium
- `adjust_default_dacl_takes_effect`: Replace default DACL; new objects created by this token use the new DACL [§7.6]
- `adjust_default_owner_invalid_rejected`: Attempt to set owner_sid_index to a group without SE_GROUP_OWNER fails [§7.6]
- `adjust_default_primary_group_invalid_rejected`: Attempt to set primary_group_index to a SID not in user+groups fails [§7.6]
- `adjust_default_without_access_right_denied`: AdjustDefault without TOKEN_ADJUST_DEFAULT fails [§7.6]

#### Shared Semantics

##### Cargo
- `adjustments_mutate_in_place_atomic`: All three adjustment operations mutate the token object in place via atomic operations [§7.6, lines 2467-2469]
- `adjustments_visible_immediately`: The change is visible immediately to all threads sharing the token [§7.6, lines 2469-2470]
- `adjustments_bump_modified_id`: All adjustments bump modified_id, invalidating cached AccessCheck results keyed on this token's identity [§7.6, lines 2470-2471]

##### Provium
- `adjustment_bumps_modified_id_provium`: After any adjustment (privilege, group, default), modified_id is incremented [§7.6]
- `cached_access_check_stale_after_adjustment`: A cached AccessCheck result from before an adjustment is stale (modified_id changed) [§7.6]

---

### §7.7 Linked Tokens and Elevation (lines 2473-2604)

#### Cargo
- `elevated_token_full_type`: Elevated token has elevation_type = Full, all groups active, all assigned privileges present and enabled [§7.7, lines 2495-2497]
- `filtered_token_limited_type`: Filtered token has elevation_type = Limited, administrative groups deny-only, dangerous privileges stripped [§7.7, lines 2498-2501]
- `filtered_created_via_filter_token`: Filtered token is created from the elevated token via FilterToken [§7.7, line 2501]
- `both_share_auth_id`: Both tokens in linked pair share the same auth_id (logon session) [§7.7, line 2503]
- `linked_via_weak_references`: Both tokens linked via weak references (linked_token field) [§7.7, line 2504]
- `no_linked_pair_default_elevation`: A token with no linked pair has elevation_type = Default [§7.7, line 2509]
- `unprivileged_query_returns_identification_copy`: When unprivileged caller queries a token's linked token, KACS returns a copy at Identification impersonation level [§7.7, lines 2523-2524]
- `identification_copy_cannot_be_used`: The Identification-level copy can inspect the elevated token but cannot be used for access control decisions, impersonation, or assignment as primary token [§7.7, lines 2525-2528]
- `tcb_privilege_gets_full_handle`: A caller holding SeTcbPrivilege receives a full handle to the actual linked token instead [§7.7, lines 2529-2530]
- `linked_token_query_exception_to_duplicate_model`: Returning a token copy via TOKEN_QUERY is an intentional exception to the normal access-right model [§7.7, lines 2531-2537]
- `session_termination_destroys_both_tokens`: Both tokens in a linked pair share a logon session; session termination destroys both [§7.7, lines 2603-2604]

##### Provium
- `query_linked_token_unprivileged`: Unprivileged process queries own token's linked token; receives Identification-level copy that cannot be installed for impersonation [§7.7]
- `query_linked_token_with_tcb`: TCB-privileged process queries linked token; receives full usable handle [§7.7]
- `identification_copy_reject_impersonation`: Attempt to install Identification-level linked token copy as impersonation token fails [§7.7]
- `identification_copy_reject_assign_primary`: Attempt to assign Identification-level linked token copy as primary token fails [§7.7]

---

### §7.8 Token Expiration and Revocation (lines 2606-2700)

#### Cargo
- `expiration_not_enforced_v1`: In v1, the expiration field is not enforced by KACS during access evaluation; AccessCheck does not consult it [§7.8, lines 2611-2613]
- `expiration_informational_only`: expiration exists for informational queries and future enforcement [§7.8, lines 2617-2618]
- `token_lifetime_by_refcount`: Token lifetime is governed by reference counting, not by expiration timestamp [§7.8, lines 2620-2621]
- `tokens_exist_while_any_reference`: Tokens exist as long as at least one reference (process credential or open fd) exists [§7.8, lines 2621-2622]
- `logon_session_identified_by_luid`: A logon session is a lightweight kernel object identified by a LUID (auth_id) [§7.8, lines 2630-2631]
- `every_token_references_logon_session`: Every token references a logon session [§7.8, line 2631]
- `multiple_tokens_share_session`: Multiple tokens can share a session (linked pairs, tokens derived via duplication) [§7.8, lines 2638-2640]
- `last_token_freed_destroys_session`: When the last token referencing a logon session is freed, the kernel destroys the session object [§7.8, lines 2641-2642]
- `session_cleanup_notifies_authd`: Session cleanup notifies authd (with dead session's auth_id asynchronously) [§7.8, lines 2642-2647]
- `logon_sessions_are_bookkeeping`: Logon sessions are bookkeeping; no access control decision depends on the logon session [§7.8, lines 2649-2650]
- `access_check_never_consults_auth_id`: AccessCheck never consults auth_id [§7.8, line 2650]
- `compare_tokens_uses_auth_id`: CompareTokens uses auth_id to determine whether two tokens originate from the same authentication event [§7.8, lines 2651-2653]
- `interactive_session_id_is_metadata`: interactive_session_id is metadata; no kernel security mechanism evaluates it [§7.8, lines 2655-2659]
- `no_token_revocation_primitive`: KACS does not provide a token revocation primitive; no "invalidate token X" or "kill session Y" syscall [§7.8, lines 2663-2665]

#### Provium
- `logon_session_creation_by_authd`: authd creates a logon session via KACS syscall at authentication time, before creating the token [§7.8, lines 2634-2636]
- `logon_session_cleanup_on_last_ref_drop`: When last token referencing a session is freed, session is destroyed [§7.8]
- `session_termination_is_userspace_coordination`: Session termination is userspace coordination: authd enumerates processes, requests termination, processes die, token references drop [§7.8, lines 2667-2677]
- `token_fd_survives_session_termination`: Token fd passed via IPC to process outside session survives session's process termination [§7.8, lines 2686-2693]

---

### §7.9 Token Access Rights (lines 2702-2797)

#### Cargo
- `tokens_are_securable_objects`: Tokens are securable objects; every token has its own Security Descriptor [§7.9, lines 2703-2707]
- `token_fd_access_check_at_open`: Accessing a token requires passing an AccessCheck against that SD [§7.9, line 2707]
- `token_access_cached_on_fd`: Granted access mask is cached on the token fd; subsequent operations verify cached mask [§7.9, lines 2716-2717]
- `token_query_right_value`: TOKEN_QUERY = 0x0008; read token information [§7.9, line 2738]
- `token_adjust_privileges_right_value`: TOKEN_ADJUST_PRIVILEGES = 0x0020 [§7.9, line 2739]
- `token_adjust_groups_right_value`: TOKEN_ADJUST_GROUPS = 0x0040 [§7.9, line 2740]
- `token_adjust_default_right_value`: TOKEN_ADJUST_DEFAULT = 0x0080 [§7.9, line 2741]
- `token_adjust_sessionid_right_value`: TOKEN_ADJUST_SESSIONID = 0x0100; also requires SeTcbPrivilege [§7.9, line 2742]
- `token_duplicate_right_value`: TOKEN_DUPLICATE = 0x0002 [§7.9, line 2743]
- `token_impersonate_right_value`: TOKEN_IMPERSONATE = 0x0004 [§7.9, line 2744]
- `token_assign_primary_right_value`: TOKEN_ASSIGN_PRIMARY = 0x0001; also requires SeAssignPrimaryTokenPrivilege [§7.9, line 2745]
- `token_query_source_folded_into_query`: Bit 0x0010 reserved (TOKEN_QUERY_SOURCE in Windows) but folded into TOKEN_QUERY in Peios; bit must not be reused [§7.9, lines 2747-2752]
- `standard_rights_apply_to_tokens`: Standard rights (READ_CONTROL, WRITE_DAC, WRITE_OWNER, DELETE) apply to tokens [§7.9, lines 2756-2763]
- `delete_right_no_practical_effect`: DELETE right present for uniformity but has no practical effect for tokens [§7.9, line 2763]
- `implicit_self_access_for_query`: Thread always has implicit access to its own effective token for query operations [§7.9, lines 2731-2732]
- `self_access_no_fd_required`: Self-inspection (getuid, privilege checks) does not require opening a token fd [§7.9, line 2732]

#### Default Token SD

##### Cargo
- `default_sd_owner_is_creator_sid`: Default token SD owner is the creating process's user SID [§7.9, line 2769]
- `default_sd_grants_self_limited`: Default SD grants the token's own user SID: TOKEN_QUERY, TOKEN_ADJUST_PRIVILEGES, TOKEN_ADJUST_GROUPS, TOKEN_ADJUST_DEFAULT [§7.9, lines 2771-2775]
- `default_sd_grants_creator_all_access`: Default SD grants the creator TOKEN_ALL_ACCESS [§7.9, line 2776]
- `default_sd_grants_system_all_access`: Default SD grants SYSTEM TOKEN_ALL_ACCESS [§7.9, line 2777]
- `default_sd_no_self_duplicate`: TOKEN_DUPLICATE not granted to the token's subject by default [§7.9, lines 2784-2785]
- `default_sd_no_self_impersonate`: TOKEN_IMPERSONATE not granted to the token's subject by default [§7.9, line 2784]
- `default_sd_no_self_write_dac`: WRITE_DAC not granted to the token's subject by default [§7.9, line 2785]

##### Provium
- `open_process_token_access_check`: Opening a process's token evaluates the caller's token against the target token's SD [§7.9]
- `open_process_token_requires_process_query`: Opening a process's token also requires sufficient access to the process itself (analogous to PROCESS_QUERY_INFORMATION) [§7.9, lines 2721-2723]
- `token_fd_via_ipc_preserves_access_mask`: Token fd passed via SCM_RIGHTS preserves the access mask cached at the time it was originally opened [§7.9, lines 2724-2728]
- `open_thread_impersonation_token`: Separate variant opens a thread's impersonation token given a thread identifier [§7.9, lines 2718-2719]
- `token_adjust_sessionid_requires_tcb`: TOKEN_ADJUST_SESSIONID operation also requires SeTcbPrivilege on the caller's token [§7.9, line 2742]
- `token_assign_primary_requires_privilege`: TOKEN_ASSIGN_PRIMARY operation also requires SeAssignPrimaryTokenPrivilege on caller's token [§7.9, line 2745]
- `check_at_open_no_per_operation_reevaluation`: Token access check is check-at-open; AccessCheck runs once when token fd is obtained, cached mask used for subsequent operations [§7.9, lines 2794-2797]
- `self_query_without_fd`: Thread can query its own effective token without opening a token fd [§7.9]

---

### §8.0 Process Security Block - Intro (lines 2799-2837)

#### Cargo
- `psb_not_affected_by_impersonation`: The PSB is never affected by impersonation; impersonation changes who the thread is acting as, not what the process is [§8, lines 2828-2830]
- `psb_on_task_struct_security`: PSB lives on task_struct->security (the task's own LSM blob), not on struct cred [§8, lines 2832-2836]
- `token_on_cred_psb_on_task`: Token lives on struct cred; PSB lives on task_struct->security [§8, lines 2832-2835]
- `impersonation_swaps_cred_not_task_blob`: Credential is swapped by impersonation; the task blob (PSB) is not [§8, line 2836]

#### Provium
- `psb_unchanged_during_impersonation`: A thread impersonating a client retains its process's PSB values (PIP, mitigations) unchanged [§8]
- `pip_stays_during_impersonation`: A Protected process impersonating a None client retains PIP protection [§8, lines 2810-2813]

---

### §8.1 PSB Object Model (lines 2838-2936)

#### Protection

##### Cargo
- `pip_type_enum_values`: pip_type is enum: Isolated, Protected, or None [§8.1, line 2847]
- `pip_type_immutable_after_exec`: pip_type is set at exec, immutable afterward [§8.1, line 2843]
- `pip_type_signing_based`: PIP fields are signing-based; determined by the binary's cryptographic signature at exec time [§8.1, lines 2850-2852]
- `pip_not_configurable_by_parent`: PIP not configurable by parent process; even compromised peinit cannot forge PIP for unsigned binary [§8.1, lines 2852-2854]
- `pip_trust_is_uint`: pip_trust is uint; higher values can access lower [§8.1, line 2848]
- `pip_trust_from_signer_identity`: pip_trust determined by the binary's signer identity [§8.1, line 2848]
- `public_key_compiled_into_kernel`: Public verification key is compiled into the kernel image [§8.1, line 2857]
- `kernel_only_verifies_never_signs`: Kernel only verifies signatures; it never signs [§8.1, line 2858]

#### Process Mitigations

##### Cargo
- `lsv_signed_libraries_only`: LSV: only cryptographically signed shared libraries can be loaded [§8.1, line 2879]
- `wxp_no_write_and_execute`: WXP: memory pages cannot be simultaneously writable and executable [§8.1, line 2880]
- `wxp_blocks_shellcode_injection`: WXP blocks shellcode injection [§8.1, line 2880]
- `tlp_approved_directories_only`: TLP: shared libraries can only be loaded from approved directories [§8.1, line 2881]
- `tlp_weaker_than_lsv`: TLP is weaker than LSV (trusts the path, not the binary) [§8.1, line 2881]
- `cfi_hardware_control_flow`: CFI: hardware control-flow enforcement (Intel CET shadow stack, ARM BTI) locked on and cannot be disabled [§8.1, line 2882]
- `mitigations_set_at_exec_immutable`: All mitigation fields determined by binary's metadata or signing properties at exec time; process cannot change them [§8.1, lines 2884-2886]
- `lsv_wxp_cfi_compose`: LSV + WXP + CFI compose: cannot inject new code (WXP), cannot reuse existing code out of order (CFI), cannot load malicious libraries (LSV/TLP) [§8.1, lines 2888-2893]

#### UI Access

##### Cargo
- `ui_access_set_at_exec_immutable`: ui_access is set at exec, immutable [§8.1, line 2895]
- `ui_access_bypasses_uipi`: ui_access permits interaction with higher-integrity UI elements (bypasses UIPI restrictions) [§8.1, line 2899]

#### Process Restrictions

##### Cargo
- `no_child_process_one_way`: no_child_process is one-way; once set, cannot be cleared [§8.1, lines 2903-2905]
- `no_child_process_blocks_fork_not_thread`: no_child_process blocks fork/clone without CLONE_THREAD; new threads unaffected [§8.1, line 2905]
- `no_child_process_set_between_fork_and_exec`: no_child_process can be set between fork and exec by the parent's code running in the freshly forked child [§8.1, lines 2910-2913]
- `no_child_process_set_at_runtime`: A process can set no_child_process on itself at any time [§8.1, lines 2914-2916]
- `no_child_process_via_kacs_syscall`: The mechanism is a KACS syscall operating on the calling process's own PSB [§8.1, lines 2918-2920]

##### Provium
- `no_child_process_blocks_fork`: Process with no_child_process set cannot fork (clone without CLONE_THREAD); fork fails [§8.1]
- `no_child_process_allows_thread_creation`: Process with no_child_process set can still create new threads (CLONE_THREAD) [§8.1]
- `no_child_process_cannot_be_cleared`: Once no_child_process is set, attempting to clear it fails [§8.1]
- `no_child_process_set_then_exec`: Process sets no_child_process between fork and exec; after exec, fork still blocked [§8.1]
- `no_child_process_impersonation_cannot_bypass`: Process with no_child_process impersonates a token without the restriction; fork still blocked because PSB is not affected by impersonation [§8.1]

#### Identity Virtualization

##### Cargo
- `virtualization_reserved_not_active_v1`: virtualization is reserved in PSB; not active in v1 [§8.1, line 2935]

---

### §8.2 Lifecycle (lines 2937-2957)

#### Cargo
- `fork_copies_psb`: At fork (clone without CLONE_THREAD), child receives a copy of parent's PSB [§8.2, lines 2939-2940]
- `pip_inherits_across_fork`: PIP fields, mitigations, and active restrictions inherited at fork [§8.2, lines 2940-2942]
- `protected_children_start_protected`: A Protected process's children start as Protected (PIP propagates across fork) [§8.2, line 2942]
- `exec_resets_pip_from_signature`: At exec, pip_type and pip_trust are reset based on new binary's cryptographic signature [§8.2, lines 2944-2945]
- `exec_resets_mitigations_from_metadata`: At exec, mitigation flags (lsv, wxp, tlp, cfi, ui_access) are reset based on new binary's metadata [§8.2, lines 2945-2946]
- `protected_parent_unsigned_child_loses_pip`: A Protected parent that execs an unsigned binary loses PIP protection [§8.2, lines 2947-2948]
- `no_child_process_persists_across_exec`: no_child_process flag persists across exec; a restricted process remains restricted regardless of what binary it loads [§8.2, lines 2950-2953]
- `clone_thread_shares_psb`: Threads share the process's PSB (CLONE_THREAD) [§8.2, line 2955]
- `thread_creation_not_affected_by_no_child`: Thread creation (CLONE_THREAD) is not affected by no_child_process [§8.2, lines 2956-2957]

#### Provium
- `fork_inherits_psb_pip_mitigations`: Fork inherits PIP fields and mitigations from parent to child [§8.2]
- `exec_unsigned_binary_loses_pip`: Protected process execs unsigned binary; child has pip_type = None [§8.2]
- `exec_signed_binary_gains_pip`: Non-protected process execs a signed binary; child has pip_type based on signature [§8.2]
- `no_child_process_survives_exec`: Process sets no_child_process, then execs a different binary; fork still blocked after exec [§8.2]
- `exec_resets_mitigations`: Process with lsv=true execs a binary without LSV requirement; lsv is reset to false [§8.2]

---

### §8.3 Relationship to AccessCheck (lines 2959-2985)

#### Cargo
- `psb_not_input_to_access_check_general`: PSB is not an input to AccessCheck in the general case [§8.3, lines 2961-2963]
- `pip_is_exception`: PIP is the exception; AccessCheck pipeline includes a PIP enforcement step that reads pip_type and pip_trust [§8.3, lines 2965-2966]
- `pip_from_psb_not_token`: PIP values come from the PSB (task_struct->security), not from any token [§8.3, lines 2967-2968]
- `pip_passed_as_explicit_params_to_access_check`: Enforcement layer extracts PIP values from PSB and passes them as explicit parameters to AccessCheck [§8.3, lines 2968-2970]
- `mic_uses_effective_token`: MIC (integrity level) uses the effective token; impersonation changes how MIC evaluates [§8.3, lines 2974-2977]
- `pip_uses_psb`: PIP (process protection) uses the PSB; impersonation does not change how PIP evaluates [§8.3, lines 2978-2980]
- `mitigations_no_access_check_interaction`: Process mitigations (lsv, wxp, tlp, cfi) and no_child_process do not interact with AccessCheck at all [§8.3, lines 2982-2985]

#### Provium
- `mic_changes_with_impersonation`: Thread impersonating a lower-integrity client; MIC uses impersonation token's integrity level for access evaluation [§8.3]
- `pip_unchanged_with_impersonation`: Thread impersonating a client; PIP check still uses process's PSB pip_type, not any token value [§8.3]
- `lsv_enforced_at_mmap_not_access_check`: LSV enforced at security_mmap_file hook, not through AccessCheck pipeline [§8.3]
- `wxp_enforced_at_mmap_and_mprotect`: WXP enforced at security_mmap_file and security_file_mprotect hooks [§8.3]
- `cfi_enforced_at_shstk_management`: CFI enforced at kernel CET management code, not AccessCheck [§8.3]

---

### §8.4 Process Security Descriptors (lines 2987-3117)

#### Cargo
- `every_process_has_sd`: Every process carries a security descriptor that controls who can perform operations on it [§8.4, lines 2989-2990]
- `process_sd_stored_on_psb`: Process SD is stored on the PSB [§8.4, line 2991]
- `process_terminate_right_value`: PROCESS_TERMINATE = 0x0001; send lethal signals [§8.4, line 3003]
- `process_signal_right_value`: PROCESS_SIGNAL = 0x0002; send non-lethal signals [§8.4, line 3004]
- `process_vm_read_right_value`: PROCESS_VM_READ = 0x0010 [§8.4, line 3005]
- `process_vm_write_right_value`: PROCESS_VM_WRITE = 0x0020; includes debugger attach [§8.4, line 3006]
- `process_dup_handle_right_value`: PROCESS_DUP_HANDLE = 0x0040 [§8.4, line 3007]
- `process_query_information_right_value`: PROCESS_QUERY_INFORMATION = 0x0400 [§8.4, line 3008]
- `process_query_limited_right_value`: PROCESS_QUERY_LIMITED = 0x1000 [§8.4, line 3009]
- `process_set_information_right_value`: PROCESS_SET_INFORMATION = 0x0200 [§8.4, line 3010]
- `generic_read_maps_to_process`: GENERIC_READ maps to PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | READ_CONTROL [§8.4, lines 3018-3019]
- `generic_write_maps_to_process`: GENERIC_WRITE maps to PROCESS_SET_INFORMATION | PROCESS_VM_WRITE | WRITE_DAC [§8.4, line 3020]
- `generic_execute_maps_to_process`: GENERIC_EXECUTE maps to PROCESS_TERMINATE | PROCESS_QUERY_LIMITED [§8.4, line 3021]
- `generic_all_maps_to_all_process`: GENERIC_ALL maps to all process rights [§8.4, line 3022]

#### Default Process SD

##### Cargo
- `default_process_sd_owner_is_creator`: Default process SD owner is creator's user SID [§8.4, line 3029]
- `default_process_sd_self_generic_all`: Default SD: process's own user SID gets GENERIC_ALL [§8.4, line 3032]
- `default_process_sd_admins_generic_all`: Default SD: Administrators (S-1-5-32-544) get GENERIC_ALL [§8.4, line 3033]
- `default_process_sd_system_generic_all`: Default SD: SYSTEM (S-1-5-18) gets GENERIC_ALL [§8.4, line 3034]
- `default_process_sd_everyone_query_limited`: Default SD: Everyone (S-1-1-0) gets PROCESS_QUERY_LIMITED [§8.4, line 3035]
- `ps_top_works_for_all_users`: Everyone can see basic process info (PID, name, status) making ps and top work for all users [§8.4, lines 3042-3043]
- `detailed_inspection_restricted`: Detailed inspection (token, memory, environment) restricted to self, admin, and SYSTEM [§8.4, lines 3044-3045]

#### Enforcement via LSM Hooks

##### Cargo
- `task_kill_maps_to_terminate_or_signal`: security_task_kill maps to PROCESS_TERMINATE (lethal) or PROCESS_SIGNAL (non-lethal) based on signal number [§8.4, line 3058]
- `ptrace_read_maps_to_vm_read`: security_ptrace_access_check(MODE_READ) maps to PROCESS_VM_READ [§8.4, line 3059]
- `ptrace_attach_maps_to_vm_write`: security_ptrace_access_check(MODE_ATTACH) maps to PROCESS_VM_WRITE [§8.4, line 3060]
- `pidfd_getfd_maps_to_dup_handle`: security_ptrace_access_check(MODE_ATTACH|MODE_GETFD) maps to PROCESS_DUP_HANDLE [§8.4, line 3061]
- `pip_and_sd_complementary`: PIP and process SD are complementary, not redundant; SD controls who, PIP controls trust level [§8.4, lines 3070-3073]
- `both_pip_and_sd_must_pass`: Both AccessCheck against process SD and PIP trust level check must pass [§8.4, lines 3074-3079]
- `permissive_sd_but_pip_protected`: Process can have permissive SD but be PIP-protected; Administrators pass SD check but need sufficient PIP trust [§8.4, lines 3080-3082]
- `restrictive_sd_no_pip`: Non-PIP process can have restrictive SD that denies even Administrators specific operations [§8.4, lines 3083-3084]

#### Lifecycle

##### Cargo
- `fork_gets_new_default_sd`: At fork, child receives a new default SD; owner is forking thread's effective token's user SID [§8.4, lines 3088-3090]
- `exec_sd_not_reset`: At exec, the process SD is not reset; persists from fork time [§8.4, lines 3092-3095]
- `sd_reflects_creation_context_not_binary`: SD reflects process's creation context, not the binary it's running [§8.4, lines 3093-3094]
- `self_sd_modification_requires_write_dac`: Self-modification of process SD via kacs_set_sd requires WRITE_DAC (granted by default SD to process's own SID) [§8.4, lines 3097-3099]

#### Storage

##### Cargo
- `process_sd_inline_on_psb`: Process SD is stored inline on the PSB as a pointer to heap-allocated SD structure [§8.4, lines 3106-3108]
- `process_sd_freed_on_exit`: SD is freed when the process exits [§8.4, line 3109]
- `kacs_task_struct_has_proc_sd`: kacs_task struct contains proc_sd field (process security descriptor) [§8.4, lines 3112-3115]

##### Provium
- `kill_signal_requires_process_terminate`: Sending SIGKILL to a process requires PROCESS_TERMINATE access right on target's process SD [§8.4]
- `non_lethal_signal_requires_process_signal`: Sending SIGHUP requires PROCESS_SIGNAL [§8.4]
- `ptrace_read_requires_vm_read`: Reading /proc/<pid>/mem requires PROCESS_VM_READ [§8.4]
- `ptrace_attach_requires_vm_write`: ptrace attach requires PROCESS_VM_WRITE [§8.4]
- `pidfd_getfd_requires_dup_handle`: pidfd_getfd requires PROCESS_DUP_HANDLE [§8.4]
- `open_process_token_requires_query_information`: kacs_open_process_token requires PROCESS_QUERY_INFORMATION [§8.4]
- `proc_detailed_requires_query_information`: Detailed /proc/<pid>/* files require PROCESS_QUERY_INFORMATION [§8.4]
- `proc_basic_requires_query_limited`: Basic /proc/<pid>/stat and cmdline require PROCESS_QUERY_LIMITED [§8.4]
- `nice_requires_set_information`: nice/setpriority requires PROCESS_SET_INFORMATION [§8.4]
- `sched_set_requires_set_information`: sched_setscheduler/sched_setaffinity requires PROCESS_SET_INFORMATION [§8.4]
- `ioprio_set_requires_set_information`: ioprio_set requires PROCESS_SET_INFORMATION [§8.4]
- `prlimit_requires_set_information`: prlimit on another process requires PROCESS_SET_INFORMATION [§8.4]
- `everyone_can_see_basic_info`: Unprivileged process can see PID, name, status of other processes (PROCESS_QUERY_LIMITED) [§8.4]
- `non_owner_cannot_read_maps`: Unprivileged non-owner/non-admin process cannot read /proc/<pid>/maps (requires PROCESS_QUERY_INFORMATION) [§8.4]
- `service_custom_sd`: Service launched with custom SD has different access control than default [§8.4]
- `self_tighten_sd`: Process tightens own SD after initialization (removes PROCESS_VM_WRITE from all principals); subsequent ptrace attach by Administrators fails [§8.4, lines 3099-3102]
- `pip_protected_process_blocks_unprivileged_ptrace`: PIP-protected process blocks ptrace attach from process with insufficient PIP trust even if SD allows PROCESS_VM_WRITE [§8.4]
- `fork_child_sd_owner_from_effective_token`: After fork, child's SD owner comes from the forking thread's effective token's user SID (including impersonation) [§8.4]
- `exec_preserves_process_sd`: Process SD persists across exec; not reset to default [§8.4]

---

**Summary counts:**

| Category | Cargo tests | Provium tests | Total |
|----------|------------|--------------|-------|
| §7.0 Fundamentals | 15 | 2 | 17 |
| §7.1 Async contexts | 3 | 8 | 11 |
| §7.2 External replacement | 1 | 6 | 7 |
| §7.3 Object model | 64 | 0 | 64 |
| §7.4 Fork/exec lifecycle | 15 | 9 | 24 |
| §7.5 Token creation | 27 | 17 | 44 |
| §7.6 Token adjustment | 22 | 17 | 39 |
| §7.7 Linked tokens | 11 | 4 | 15 |
| §7.8 Expiration/revocation | 14 | 4 | 18 |
| §7.9 Token access rights | 24 | 8 | 32 |
| §8.0 PSB intro | 4 | 2 | 6 |
| §8.1 PSB object model | 22 | 5 | 27 |
| §8.2 Lifecycle | 9 | 5 | 14 |
| §8.3 AccessCheck relationship | 7 | 5 | 12 |
| §8.4 Process SDs | 22 | 17 | 39 |
| **Total** | **260** | **109** | **369** |


---

# Section 9: Security Descriptors

## §9 Security Descriptors — Exhaustive Test Corpus

---

### §9.1 Structure (lines 3150–3209)

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 1 | `sd_has_four_components` | A parsed SD exposes owner SID, group SID, DACL, and SACL fields | §9.1 L3152 | Cargo |
| 2 | `sd_has_control_flags` | A parsed SD exposes a 16-bit control flags field | §9.1 L3192 | Cargo |
| 3 | `sd_binary_header_is_20_bytes` | The self-relative SD header is exactly 20 bytes: revision (1), Sbz1 (1), control (2), four 32-bit offsets (16) | §9.1 L3197 | Cargo |
| 4 | `sd_self_relative_format_only` | KACS only produces/accepts self-relative format SDs (SE_SELF_RELATIVE always set on serialized SDs) | §9.1 L3204 | Cargo |
| 5 | `sd_contiguous_byte_buffer` | A serialized SD is a single contiguous byte buffer with no pointers or external references | §9.1 L3200 | Cargo |
| 6 | `sd_parse_in_place` | AccessCheck can parse a self-relative SD buffer without copying — offsets resolve to correct sub-structures | §9.1 L3206 | Cargo |
| 7 | `sd_rebuild_on_modification` | When an SD is modified (ACE added, DACL replaced), a new complete self-relative buffer is produced | §9.1 L3207 | Cargo |
| 8 | `sd_owner_sid_roundtrip` | Owner SID survives serialize/deserialize roundtrip identically | §9.1 L3154 | Cargo |
| 9 | `sd_group_sid_roundtrip` | Group SID survives serialize/deserialize roundtrip identically | §9.1 L3159 | Cargo |
| 10 | `sd_dacl_roundtrip` | DACL (with ACEs) survives serialize/deserialize roundtrip identically | §9.1 L3167 | Cargo |
| 11 | `sd_sacl_roundtrip` | SACL (with ACEs) survives serialize/deserialize roundtrip identically | §9.1 L3173 | Cargo |
| 12 | `sd_group_sid_not_used_for_access_control` | The group SID is stored and returned on query but no AccessCheck decision depends on it | §9.1 L3161–3165 | Cargo |
| 13 | `sd_windows_binary_compatibility` | A known-good Windows SD binary blob parses correctly and produces identical field values | §9.1 L3136–3143 | Cargo |
| 14 | `sd_offsets_point_to_correct_components` | The four 32-bit offsets in the header resolve to the correct owner, group, SACL, and DACL within the buffer | §9.1 L3198 | Cargo |
| 15 | `sd_zero_offset_means_absent` | An offset of zero for DACL or SACL means that component is absent (null DACL/SACL) | §9.1 L3197–3202 | Cargo |

---

### §9.2 Access Masks (lines 3211–3294)

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 16 | `access_mask_is_32_bits` | Access masks are 32-bit integers | §9.2 L3213 | Cargo |
| 17 | `access_mask_object_specific_bits_0_to_15` | Bits 0-15 are reserved for object-specific rights | §9.2 L3222 | Cargo |
| 18 | `access_mask_standard_rights_bits_16_to_20` | DELETE=bit16, READ_CONTROL=bit17, WRITE_DAC=bit18, WRITE_OWNER=bit19, SYNCHRONIZE=bit20 | §9.2 L3230–3238 | Cargo |
| 19 | `access_mask_access_system_security_bit_24` | ACCESS_SYSTEM_SECURITY is bit 24 | §9.2 L3244 | Cargo |
| 20 | `access_mask_maximum_allowed_bit_25` | MAXIMUM_ALLOWED is bit 25 | §9.2 L3245 | Cargo |
| 21 | `maximum_allowed_cannot_appear_in_ace` | MAXIMUM_ALLOWED is a request flag only; ACE construction rejects it in an ACE mask | §9.2 L3245 | Cargo |
| 22 | `access_mask_generic_rights_bits_28_to_31` | GENERIC_ALL=bit28, GENERIC_EXECUTE=bit29, GENERIC_WRITE=bit30, GENERIC_READ=bit31 | §9.2 L3251–3256 | Cargo |
| 23 | `generic_mapping_at_request_time` | Generic bits in the requested mask are mapped to object-specific bits via GenericMapping, then generic bits are cleared, before DACL walk | §9.2 L3264–3269 | Cargo |
| 24 | `generic_bits_cleared_after_mapping_request` | After mapping, the requested mask has no generic bits set (bits 28-31 all zero) | §9.2 L3268 | Cargo |
| 25 | `ace_mask_generic_bits_mapped_locally` | (Divergence) AccessCheck maps each ACE's mask via MapGenericBits using a local variable; the ACE itself is never mutated | §9.2 L3271–3282 | Cargo |
| 26 | `ace_mask_mapping_uses_same_generic_mapping` | The same GenericMapping table is used for both request mask mapping and ACE mask mapping | §9.2 L3275 | Cargo |
| 27 | `generic_read_in_ace_maps_correctly` | An ACE granting GENERIC_READ matches the corresponding object-specific read bits after mapping | §9.2 L3280–3282 | Cargo |
| 28 | `generic_all_in_ace_maps_correctly` | An ACE granting GENERIC_ALL maps to all object-specific + standard rights per the GenericMapping | §9.2 L3278 | Cargo |
| 29 | `different_object_types_different_generic_mappings` | File GenericMapping and registry key GenericMapping produce different specific bits for the same generic right | §9.2 L3258–3262 | Cargo |
| 30 | `dacl_walk_never_sees_generic_bits` | During the DACL walk, neither the requested mask nor the effective ACE mask contain generic bits | §9.2 L3267–3269 | Cargo |
| 31 | `same_mask_layout_for_ace_request_granted` | The same 32-bit layout is used for ACE mask, requested access, and granted access | §9.2 L3216–3218 | Cargo |

---

### §9.3 Access Control Entries (lines 3296–3469)

#### ACE Header (lines 3303–3310)

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 32 | `ace_header_is_4_bytes` | Every ACE begins with a 4-byte header | §9.3 L3305 | Cargo |
| 33 | `ace_header_type_field_1_byte` | AceType is byte 0 of the header (1 byte) | §9.3 L3307 | Cargo |
| 34 | `ace_header_flags_field_1_byte` | AceFlags is byte 1 of the header (1 byte) | §9.3 L3308 | Cargo |
| 35 | `ace_header_size_field_2_bytes` | AceSize is bytes 2-3 of the header (2 bytes, little-endian) | §9.3 L3309 | Cargo |
| 36 | `ace_size_multiple_of_4` | AceSize must be a multiple of 4 | §9.3 L3310 | Cargo |
| 37 | `ace_size_includes_header` | AceSize is total size including the 4-byte header | §9.3 L3309 | Cargo |

#### DACL ACE Types (lines 3312–3365)

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 38 | `access_allowed_ace_type_0x00` | ACCESS_ALLOWED_ACE has type value 0x00 | §9.3 L3323 | Cargo |
| 39 | `access_denied_ace_type_0x01` | ACCESS_DENIED_ACE has type value 0x01 | §9.3 L3324 | Cargo |
| 40 | `access_allowed_object_ace_type_0x05` | ACCESS_ALLOWED_OBJECT_ACE has type value 0x05 | §9.3 L3335 | Cargo |
| 41 | `access_denied_object_ace_type_0x06` | ACCESS_DENIED_OBJECT_ACE has type value 0x06 | §9.3 L3336 | Cargo |
| 42 | `object_ace_has_flags_field` | Object-type ACEs contain a flags field indicating which GUIDs are present | §9.3 L3329–3330 | Cargo |
| 43 | `object_ace_optional_object_type_guid` | ObjectType GUID may be absent (indicated by flags field), in which case ACE behaves like basic ACE for property dimension | §9.3 L3340–3341 | Cargo |
| 44 | `object_ace_optional_inherited_object_type_guid` | InheritedObjectType GUID may be absent (indicated by flags field) | §9.3 L3340–3341 | Cargo |
| 45 | `object_ace_both_guids_absent` | When both GUIDs are absent, object-type ACE behaves identically to a basic ACE | §9.3 L3341 | Cargo |
| 46 | `object_ace_both_guids_present` | Object-type ACE can have both ObjectType and InheritedObjectType GUIDs simultaneously | §9.3 L3330 | Cargo |
| 47 | `callback_allowed_ace_type_0x09` | ACCESS_ALLOWED_CALLBACK_ACE has type value 0x09 | §9.3 L3356 | Cargo |
| 48 | `callback_denied_ace_type_0x0a` | ACCESS_DENIED_CALLBACK_ACE has type value 0x0A | §9.3 L3357 | Cargo |
| 49 | `callback_allowed_object_ace_type_0x0b` | ACCESS_ALLOWED_CALLBACK_OBJECT_ACE has type value 0x0B | §9.3 L3358 | Cargo |
| 50 | `callback_denied_object_ace_type_0x0c` | ACCESS_DENIED_CALLBACK_OBJECT_ACE has type value 0x0C | §9.3 L3359 | Cargo |
| 51 | `callback_ace_has_conditional_expression` | Callback ACEs contain a conditional expression appended after the SID | §9.3 L3348–3349 | Cargo |
| 52 | `callback_ace_evaluated_inline` | Conditional expression is evaluated inline by AccessCheck, not via external callback | §9.3 L3363–3364 | Cargo |

#### SACL ACE Types (lines 3367–3459)

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 53 | `sacl_ace_types_not_in_dacl` | DACL must not contain SACL ACE types (SYSTEM_AUDIT, SYSTEM_MANDATORY_LABEL, etc.) | §9.3 L3371 | Cargo |
| 54 | `dacl_ace_types_not_in_sacl` | SACL must not contain DACL ACE types (ACCESS_ALLOWED, ACCESS_DENIED, etc.) | §9.3 L3372 | Cargo |
| 55 | `system_audit_ace_type_0x02` | SYSTEM_AUDIT_ACE has type value 0x02 | §9.3 L3382 | Cargo |
| 56 | `system_audit_object_ace_type_0x07` | SYSTEM_AUDIT_OBJECT_ACE has type value 0x07 | §9.3 L3383 | Cargo |
| 57 | `system_audit_callback_ace_type_0x0d` | SYSTEM_AUDIT_CALLBACK_ACE has type value 0x0D | §9.3 L3384 | Cargo |
| 58 | `system_audit_callback_object_ace_type_0x0f` | SYSTEM_AUDIT_CALLBACK_OBJECT_ACE has type value 0x0F | §9.3 L3385 | Cargo |
| 59 | `audit_ace_successful_access_flag_0x40` | SUCCESSFUL_ACCESS_ACE_FLAG is 0x40 in AceFlags | §9.3 L3375–3376 | Cargo |
| 60 | `audit_ace_failed_access_flag_0x80` | FAILED_ACCESS_ACE_FLAG is 0x80 in AceFlags | §9.3 L3376 | Cargo |
| 61 | `audit_ace_both_success_and_fail` | An audit ACE can have both SUCCESSFUL_ACCESS and FAILED_ACCESS flags simultaneously | §9.3 L3376 | Cargo |
| 62 | `mandatory_label_ace_type_0x11` | SYSTEM_MANDATORY_LABEL_ACE has type value 0x11 | §9.3 L3397 | Cargo |
| 63 | `mandatory_label_ace_at_most_one_per_sacl` | At most one SYSTEM_MANDATORY_LABEL_ACE per SACL | §9.3 L3388 | Cargo |
| 64 | `mandatory_label_ace_sid_encodes_integrity_level` | The mandatory label ACE's SID encodes the integrity level (e.g., S-1-16-8192 = Medium, S-1-16-12288 = High) | §9.3 L3389 | Cargo |
| 65 | `mandatory_label_ace_mask_encodes_mic_policy` | The mandatory label ACE's access mask encodes which operations are blocked for lower-integrity callers | §9.3 L3390–3392 | Cargo |
| 66 | `resource_attribute_ace_type_0x12` | SYSTEM_RESOURCE_ATTRIBUTE_ACE has type value 0x12 | §9.3 L3409 | Cargo |
| 67 | `resource_attribute_ace_sid_is_everyone` | The resource attribute ACE's SID is always the well-known Everyone SID (S-1-1-0) | §9.3 L3403–3404 | Cargo |
| 68 | `resource_attribute_ace_claim_format` | The attribute data follows CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 format | §9.3 L3405 | Cargo |
| 69 | `scoped_policy_id_ace_type_0x13` | SYSTEM_SCOPED_POLICY_ID_ACE has type value 0x13 | §9.3 L3422 | Cargo |
| 70 | `process_trust_label_ace_type_0x14` | SYSTEM_PROCESS_TRUST_LABEL_ACE has type value 0x14 | §9.3 L3435 | Cargo |
| 71 | `process_trust_label_ace_mask_encodes_allowed_rights` | PIP trust label ACE mask specifies exact rights non-dominant callers are allowed | §9.3 L3435 | Cargo |
| 72 | `alarm_ace_type_0x03` | SYSTEM_ALARM_ACE has type value 0x03 | §9.3 L3450 | Cargo |
| 73 | `alarm_object_ace_type_0x08` | SYSTEM_ALARM_OBJECT_ACE has type value 0x08 | §9.3 L3451 | Cargo |
| 74 | `alarm_callback_ace_type_0x0e` | SYSTEM_ALARM_CALLBACK_ACE has type value 0x0E | §9.3 L3452 | Cargo |
| 75 | `alarm_callback_object_ace_type_0x10` | SYSTEM_ALARM_CALLBACK_OBJECT_ACE has type value 0x10 | §9.3 L3453 | Cargo |
| 76 | `compound_ace_type_0x04_reserved` | ACCESS_ALLOWED_COMPOUND_ACE (0x04) is reserved and not implemented; parser rejects or ignores it | §9.3 L3468 | Cargo |

---

### §9.4 ACE Ordering (lines 3470–3514)

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 77 | `ace_ordering_semantically_significant` | A deny ACE after an allow ACE for the same SID and bits has no effect (bits already granted) | §9.4 L3474–3476 | Cargo |
| 78 | `canonical_order_explicit_deny_first` | Canonical ordering: explicit deny ACEs come first | §9.4 L3488–3490 | Cargo |
| 79 | `canonical_order_explicit_allow_second` | Canonical ordering: explicit allow ACEs come after explicit deny | §9.4 L3491–3492 | Cargo |
| 80 | `canonical_order_inherited_deny_third` | Canonical ordering: inherited deny ACEs come after explicit allow | §9.4 L3493–3494 | Cargo |
| 81 | `canonical_order_inherited_allow_fourth` | Canonical ordering: inherited allow ACEs come last | §9.4 L3495–3496 | Cargo |
| 82 | `canonical_order_nearest_parent_first` | Within inherited categories, nearest parent's ACEs come first | §9.4 L3494 | Cargo |
| 83 | `canonical_order_object_type_after_whole_object` | Within each category, object-type ACEs (GUID-scoped) are ordered after whole-object ACEs | §9.4 L3498–3501 | Cargo |
| 84 | `non_canonical_dacl_accepted` | KACS does not reject non-canonical DACLs — it evaluates whatever order it receives | §9.4 L3481–3482 | Cargo |
| 85 | `non_canonical_dacl_produces_different_result` | A non-canonical DACL (allow before deny) produces a different AccessCheck result than the same ACEs in canonical order | §9.4 L3482–3484 | Cargo |
| 86 | `sacl_ordering_not_canonical` | SACL ACEs do not require canonical ordering; order does not affect evaluation semantics | §9.4 L3509–3514 | Cargo |
| 87 | `sacl_audit_aces_evaluated_independently` | Each matching audit ACE generates its own audit event regardless of order | §9.4 L3510–3511 | Cargo |
| 88 | `sacl_label_found_by_type_scan_not_position` | The mandatory label ACE in the SACL is located by type scan, not by position | §9.4 L3512 | Cargo |
| 89 | `sacl_resource_attr_found_by_type_scan` | Resource attribute ACEs in the SACL are located by type scan, not by position | §9.4 L3512–3513 | Cargo |
| 90 | `sacl_scoped_policy_found_by_type_scan` | Scoped policy ID ACEs in the SACL are located by type scan, not by position | §9.4 L3513 | Cargo |
| 91 | `explicit_deny_overrides_explicit_allow_canonical` | In canonical order, explicit deny takes precedence over explicit allow for the same SID and bits | §9.4 L3503–3504 | Cargo |
| 92 | `explicit_rules_override_inherited_rules` | In canonical order, explicit rules take precedence over inherited rules | §9.4 L3504 | Cargo |

---

### §9.5 Inheritance (lines 3516–3674)

#### Inheritance Flags (lines 3533–3578)

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 93 | `object_inherit_flag_0x01` | OBJECT_INHERIT_ACE flag is 0x01 | §9.5 L3538 | Cargo |
| 94 | `container_inherit_flag_0x02` | CONTAINER_INHERIT_ACE flag is 0x02 | §9.5 L3544 | Cargo |
| 95 | `no_propagate_inherit_flag_0x04` | NO_PROPAGATE_INHERIT_ACE flag is 0x04 | §9.5 L3549 | Cargo |
| 96 | `inherit_only_flag_0x08` | INHERIT_ONLY_ACE flag is 0x08 | §9.5 L3554 | Cargo |
| 97 | `inherited_ace_flag_0x10` | INHERITED_ACE flag is 0x10 | §9.5 L3562 | Cargo |
| 98 | `oi_inherits_to_non_container_children` | An ACE with OI set is inherited by non-container child objects (files) | §9.5 L3538–3539 | Cargo |
| 99 | `oi_inherit_only_on_container_children` | An ACE with OI (without NP) is inherited as inherit-only on child containers (it does not apply to the container itself) | §9.5 L3540–3542 | Cargo |
| 100 | `ci_inherits_to_container_children` | An ACE with CI set is inherited by child containers (subdirectories) | §9.5 L3544–3545 | Cargo |
| 101 | `ci_remains_inheritable` | An ACE with CI propagates to grandchildren and beyond (unless NP set) | §9.5 L3546–3547 | Cargo |
| 102 | `np_clears_oi_ci_on_inherited_copy` | When an ACE with NP is inherited, OI and CI flags are cleared on the inherited copy | §9.5 L3549–3551 | Cargo |
| 103 | `np_applies_to_immediate_child_only` | An ACE with NP applies to the immediate child but does not propagate further (one-level inheritance) | §9.5 L3551–3552 | Cargo |
| 104 | `io_ace_does_not_apply_to_attached_object` | An ACE with IO set does not apply to the object it is attached to — it exists only to be inherited | §9.5 L3554–3555 | Cargo |
| 105 | `inherited_ace_flag_set_on_inherited_aces` | ACEs created through inheritance have the INHERITED_ACE flag (0x10) set | §9.5 L3562–3563 | Cargo |
| 106 | `inherited_ace_flag_informational` | The INHERITED_ACE flag is informational — it distinguishes inherited from explicit ACEs | §9.5 L3564 | Cargo |
| 107 | `ci_oi_inherits_everything_recursively` | CI|OI: inherits to containers and non-containers, recursively ("apply to folder, subfolders, and files") | §9.5 L3572 | Cargo |
| 108 | `ci_only_inherits_containers_recursively` | CI only: inherits to containers only, recursively ("apply to folder and subfolders, not files") | §9.5 L3573 | Cargo |
| 109 | `oi_only_inherit_only_on_containers` | OI only: inherits to non-containers; for containers, inherited as inherit-only | §9.5 L3574 | Cargo |
| 110 | `ci_oi_io_inherits_contents_only` | CI|OI|IO: inherits to everything but does not apply to the object itself ("contents only") | §9.5 L3575 | Cargo |
| 111 | `ci_oi_np_immediate_children_only` | CI|OI|NP: inherits to immediate children only, no grandchildren | §9.5 L3576 | Cargo |
| 112 | `ci_np_immediate_child_containers_only` | CI|NP: inherits to immediate child containers only — one level of subdirectories | §9.5 L3577 | Cargo |
| 113 | `no_flags_no_inheritance` | No inheritance flags: ACE applies only to this object, no inheritance | §9.5 L3578 | Cargo |

#### CREATOR OWNER / CREATOR GROUP Substitution (lines 3580–3598)

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 114 | `creator_owner_sid_substituted_on_inherit` | When an ACE with CREATOR OWNER (S-1-3-0) SID is inherited, the SID is replaced with the creating principal's SID (owner of new object) | §9.5 L3584–3589 | Cargo |
| 115 | `creator_group_sid_substituted_on_inherit` | When an ACE with CREATOR GROUP (S-1-3-1) SID is inherited, the SID is replaced with the creating principal's primary group SID | §9.5 L3591–3592 | Cargo |
| 116 | `substitution_happens_at_inheritance_time` | Substitution produces a resolved SID on the child; child ACE contains actual SID, not placeholder | §9.5 L3594–3595 | Cargo |
| 117 | `io_ace_preserves_placeholder_on_parent` | If the original ACE has IO set, the placeholder SID is preserved on the parent for future children | §9.5 L3596–3598 | Cargo |
| 118 | `each_child_gets_resolved_copy` | Each child object gets its own resolved copy with its specific creator's SID | §9.5 L3598 | Cargo |

#### Inheritance Algorithm (lines 3600–3674)

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 119 | `sd_creation_three_sources` | A new object's SD is computed from parent SD, creator SD, and creator token | §9.5 L3603–3612 | Cargo |
| 120 | `owner_from_creator_sd_if_specified` | If the creator SD specifies an owner, that owner is used | §9.5 L3616 | Cargo |
| 121 | `owner_from_token_if_creator_sd_omits` | If the creator SD does not specify an owner, the token's owner SID is used | §9.5 L3617 | Cargo |
| 122 | `group_from_creator_sd_if_specified` | If the creator SD specifies a group, that group is used | §9.5 L3619 | Cargo |
| 123 | `group_from_token_if_creator_sd_omits` | If the creator SD does not specify a group, the token's primary group SID is used | §9.5 L3620 | Cargo |
| 124 | `dacl_inherit_only_no_creator_sd` | No creator SD + parent has inheritable ACEs → new DACL is entirely inherited ACEs from parent | §9.5 L3625–3628 | Cargo |
| 125 | `dacl_token_default_no_creator_no_inheritable` | No creator SD + parent has no inheritable ACEs → new DACL is token's default DACL | §9.5 L3630–3631 | Cargo |
| 126 | `dacl_creator_sd_explicit_aces_preserved` | Creator SD with DACL → explicit ACEs (without INHERITED_ACE) are preserved | §9.5 L3634–3635 | Cargo |
| 127 | `dacl_unprotected_merges_parent_inheritance` | Creator SD with unprotected DACL + auto-inheritance → inheritable ACEs from parent appended after explicit ACEs | §9.5 L3636–3638 | Cargo |
| 128 | `dacl_protected_blocks_parent_inheritance` | Creator SD with SE_DACL_PROTECTED → parent inheritance blocked, only creator's explicit ACEs used | §9.5 L3639–3640 | Cargo |
| 129 | `inherited_aces_creator_owner_substituted` | In all DACL construction paths, CREATOR OWNER / CREATOR GROUP SIDs are substituted with actual owner and group | §9.5 L3643–3644 | Cargo |
| 130 | `inherited_aces_generic_rights_mapped` | Generic rights in inherited ACEs are mapped to object-specific rights via GenericMapping | §9.5 L3645–3646 | Cargo |
| 131 | `inherited_aces_flag_set` | INHERITED_ACE flag is set on all ACEs that came from the parent | §9.5 L3647–3648 | Cargo |
| 132 | `sacl_computed_identically_to_dacl` | SACL inheritance follows the same algorithm as DACL inheritance | §9.5 L3650 | Cargo |
| 133 | `no_token_default_sacl` | Token has no "default SACL"; if no creator SACL and parent has no inheritable SACL ACEs → new object has no SACL | §9.5 L3651–3653 | Cargo |
| 134 | `inheritance_is_eager` | The new object's SD is fully computed at creation time — no lazy inheritance at access time | §9.5 L3655–3658 | Cargo |
| 135 | `no_parent_tree_walk_at_access_time` | AccessCheck does not walk up the directory tree to find inheritable ACEs | §9.5 L3657 | Cargo |
| 136 | `stored_sd_is_complete_evaluated_policy` | The SD stored on disk is always the complete, evaluated policy | §9.5 L3658 | Cargo |

#### Re-propagation (lines 3664–3674)

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 137 | `repropagation_recomputes_children` | When inheritable ACE on parent is modified, change is re-propagated to descendant objects by recomputing each child's DACL/SACL | §9.5 L3664–3671 | Provium |
| 138 | `repropagation_skips_protected_children` | During re-propagation, children with SE_DACL_PROTECTED or SE_SACL_PROTECTED are skipped | §9.5 L3672–3673 | Provium |
| 139 | `repropagation_merges_parent_new_with_child_explicit` | Re-propagation merges parent's new inheritable ACEs with child's explicit ACEs | §9.5 L3670–3671 | Provium |
| 140 | `repropagation_is_explicit_operation` | Re-propagation is an explicit operation, not automatic side-effect of next access check | §9.5 L3660–3662 | Provium |
| 141 | `standalone_objects_no_inherit` | Objects without a container parent (IPC endpoints, tokens, processes) do not inherit — SDs are explicit or from token defaults | §9.5 L3529–3531 | Cargo |

---

### §9.6 Conditional ACEs (lines 3676–3761)

#### Structure (lines 3676–3687)

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 142 | `conditional_ace_appends_expression_after_sid` | Conditional ACE is structurally identical to non-conditional counterpart with expression appended after SID | §9.6 L3684–3685 | Cargo |
| 143 | `conditional_expression_binary_format` | The conditional expression is stored in binary format per MS-DTYP §2.4.4.17 | §9.6 L3687 | Cargo |

#### Expression Language (lines 3689–3714)

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 144 | `expression_user_claims_prefix` | User claims are queried via @User. prefix in conditional expressions | §9.6 L3693–3695 | Cargo |
| 145 | `expression_device_claims_prefix` | Device claims are queried via @Device. prefix in conditional expressions | §9.6 L3696–3699 | Cargo |
| 146 | `expression_resource_attribute_prefix` | Resource attributes are queried via @Resource. prefix in conditional expressions | §9.6 L3700–3702 | Cargo |
| 147 | `expression_relational_operators` | Conditional expressions support ==, !=, <, <=, >, >= operators | §9.6 L3706 | Cargo |
| 148 | `expression_set_operators_contains` | Conditional expressions support Contains operator | §9.6 L3707 | Cargo |
| 149 | `expression_set_operators_any_of` | Conditional expressions support Any_of operator | §9.6 L3707 | Cargo |
| 150 | `expression_member_of` | Conditional expressions support Member_of operator (checks token groups for SID) | §9.6 L3707–3708 | Cargo |
| 151 | `expression_member_of_any` | Conditional expressions support Member_of_Any operator | §9.6 L3708 | Cargo |
| 152 | `expression_not_member_of` | Conditional expressions support Not_Member_of operator | §9.6 L3708 | Cargo |
| 153 | `expression_not_member_of_any` | Conditional expressions support Not_Member_of_Any operator | §9.6 L3708 | Cargo |
| 154 | `expression_device_member_of` | Conditional expressions support Device_Member_of operator | §9.6 L3709 | Cargo |
| 155 | `expression_device_member_of_any` | Conditional expressions support Device_Member_of_Any operator | §9.6 L3709 | Cargo |
| 156 | `expression_not_device_member_of` | Conditional expressions support Not_Device_Member_of operator | §9.6 L3710 | Cargo |
| 157 | `expression_not_device_member_of_any` | Conditional expressions support Not_Device_Member_of_Any operator | §9.6 L3710 | Cargo |
| 158 | `expression_logical_and` | Conditional expressions support && (AND) operator | §9.6 L3711 | Cargo |
| 159 | `expression_logical_or` | Conditional expressions support \|\| (OR) operator | §9.6 L3711 | Cargo |
| 160 | `expression_logical_not` | Conditional expressions support ! (NOT) operator | §9.6 L3711 | Cargo |
| 161 | `expression_exists_operator` | Conditional expressions support Exists test | §9.6 L3712 | Cargo |
| 162 | `expression_not_exists_operator` | Conditional expressions support Not_Exists test | §9.6 L3712 | Cargo |
| 163 | `expression_literal_integers` | Conditional expressions support integer literal values | §9.6 L3713 | Cargo |
| 164 | `expression_literal_strings` | Conditional expressions support string literal values | §9.6 L3713 | Cargo |
| 165 | `expression_literal_sids` | Conditional expressions support SID literal values | §9.6 L3713 | Cargo |
| 166 | `expression_literal_octet_strings` | Conditional expressions support octet string literal values | §9.6 L3713 | Cargo |
| 167 | `expression_literal_composites` | Conditional expressions support composite (multi-valued) literals | §9.6 L3714 | Cargo |
| 168 | `member_of_checks_token_groups` | Member_of evaluates group membership by checking whether the token's groups include the given SID | §9.6 L3716–3718 | Cargo |
| 169 | `member_of_combinable_with_conditions` | Member_of can be combined with other conditions in the same expression (e.g., Member_of{SID} && @User.clearance >= 3) | §9.6 L3719–3720 | Cargo |

#### Evaluation (lines 3722–3749)

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 170 | `expression_stack_based_evaluation` | Conditional expressions are evaluated as a stack-based bytecode program in reverse Polish notation | §9.6 L3724–3726 | Cargo |
| 171 | `expression_binary_representation_rpn` | The binary representation is operands and operators in reverse Polish notation | §9.6 L3725–3726 | Cargo |
| 172 | `allow_ace_applied_only_on_true` | Conditional allow ACE: applied only when expression evaluates to TRUE; FALSE or UNKNOWN → skip | §9.6 L3732 | Cargo |
| 173 | `deny_ace_applied_on_true_or_unknown` | Conditional deny ACE: applied on TRUE or UNKNOWN; only FALSE → skip (fail-closed) | §9.6 L3733–3735 | Cargo |
| 174 | `audit_ace_emitted_on_true_or_unknown` | Conditional audit ACE: emitted on TRUE or UNKNOWN; only FALSE → skip (conservative) | §9.6 L3736–3738 | Cargo |
| 175 | `deny_false_does_not_deny` | A conditional deny ACE that evaluates to FALSE does NOT deny — it is simply not applied | §9.6 L3740–3741 | Cargo |
| 176 | `deny_unknown_does_deny` | A conditional deny ACE that evaluates to UNKNOWN DOES deny (missing attribute → denial) | §9.6 L3741–3743 | Cargo |
| 177 | `allow_unknown_does_not_grant` | A missing attribute on an allow ACE means "don't grant" (UNKNOWN → skip) | §9.6 L3743–3744 | Cargo |
| 178 | `deny_unknown_asymmetry` | The TRUE/FALSE/UNKNOWN asymmetry: missing attribute on allow → no grant; missing attribute on deny → deny anyway | §9.6 L3743–3745 | Cargo |
| 179 | `expression_evaluator_three_valued_logic` | Expression evaluator supports three-valued logic: TRUE, FALSE, UNKNOWN | §9.6 L3755–3756 | Cargo |
| 180 | `expression_binary_format_windows_compatible` | Conditional expression binary format is byte-compatible with Windows (MS-DTYP §2.4.4.17.4) | §9.6 L3749 | Cargo |

---

### §9.7 Ownership (lines 3763–3812)

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 181 | `owner_implicit_read_control` | The owner of an object is implicitly granted READ_CONTROL regardless of DACL | §9.7 L3769 | Cargo |
| 182 | `owner_implicit_write_dac` | The owner of an object is implicitly granted WRITE_DAC regardless of DACL | §9.7 L3770 | Cargo |
| 183 | `owner_can_recover_from_empty_dacl` | Even with an empty DACL, the owner can read and rewrite the DACL to restore access | §9.7 L3773–3776 | Cargo |
| 184 | `owner_rights_ace_suppresses_implicit_rights` | An ACE for OWNER RIGHTS SID (S-1-3-4) replaces the implicit READ_CONTROL \| WRITE_DAC with the rights in that ACE | §9.7 L3782–3784 | Cargo |
| 185 | `owner_rights_deny_suppresses_entirely` | A deny ACE for S-1-3-4 with READ_CONTROL \| WRITE_DAC removes all implicit owner rights | §9.7 L3788–3790 | Cargo |
| 186 | `owner_rights_expand` | An allow ACE for S-1-3-4 with additional rights (e.g., + DELETE) expands owner's implicit rights | §9.7 L3791–3793 | Cargo |
| 187 | `owner_rights_restrict` | An allow ACE for S-1-3-4 with only READ_CONTROL (no WRITE_DAC) restricts owner to read-only SD access | §9.7 L3794–3796 | Cargo |
| 188 | `owner_rights_sid_is_s_1_3_4` | The OWNER RIGHTS well-known SID is S-1-3-4 | §9.7 L3781 | Cargo |
| 189 | `ownership_transfer_requires_write_owner` | Changing an object's owner requires WRITE_OWNER on the object | §9.7 L3806 | Cargo |
| 190 | `take_ownership_privilege_grants_write_owner` | SeTakeOwnershipPrivilege grants WRITE_OWNER on any object regardless of the DACL | §9.7 L3810–3812 | Cargo |
| 191 | `default_ownership_system_and_privilege_holders` | By default, only SYSTEM and holders of SeTakeOwnershipPrivilege can take ownership of objects they don't own | §9.7 L3807–3808 | Provium |
| 192 | `owner_can_transfer_ownership_with_write_owner` | An owner can transfer ownership to another SID if they have WRITE_OWNER (implicitly or explicitly) | §9.7 L3808–3810 | Provium |

---

### §9.8 Null DACL vs Empty DACL (lines 3814–3839)

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 193 | `null_dacl_grants_all_requested_access` | Null DACL (DP flag clear): AccessCheck grants ALL requested access to every caller | §9.8 L3818–3820 | Cargo |
| 194 | `null_dacl_dp_flag_clear` | Null DACL is indicated by the DP (SE_DACL_PRESENT) control flag being clear | §9.8 L3818 | Cargo |
| 195 | `empty_dacl_grants_no_access` | Empty DACL (DP flag set, AceCount=0): AccessCheck grants NO access to any caller (except owner implicit rights) | §9.8 L3824–3827 | Cargo |
| 196 | `empty_dacl_owner_still_has_implicit_rights` | With an empty DACL, the owner still receives implicit READ_CONTROL \| WRITE_DAC | §9.8 L3826 | Cargo |
| 197 | `null_vs_empty_asymmetry` | Null DACL = no restrictions (allow everything); empty DACL = deny everyone everything. Opposite effects. | §9.8 L3829–3833 | Cargo |
| 198 | `new_objects_always_get_dacl` | The SD creation algorithm ensures every new object receives a DACL (from creator, parent, or token default) | §9.8 L3835–3838 | Cargo |
| 199 | `null_dacl_requires_explicit_privileged_intent` | A null DACL would require explicit intent from a privileged caller | §9.8 L3838–3839 | Cargo |

---

### §9.9 ACL Revision (lines 3841–3858)

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 200 | `acl_revision_0x02_basic_types` | ACL_REVISION (0x02) permits basic ACE types: 0x00, 0x01, 0x02, 0x03, plus 0x11, 0x12, 0x13, 0x14 | §9.9 L3846–3849 | Cargo |
| 201 | `acl_revision_ds_0x04_permits_object_and_callback` | ACL_REVISION_DS (0x04) additionally permits object-type ACEs (0x05-0x08) and callback ACEs (0x09-0x10) | §9.9 L3850–3853 | Cargo |
| 202 | `kacs_accepts_both_revisions` | KACS accepts both ACL_REVISION and ACL_REVISION_DS | §9.9 L3855 | Cargo |
| 203 | `new_acl_minimum_revision` | When creating new ACLs, revision is set to the minimum required by ACE types present | §9.9 L3855–3857 | Cargo |
| 204 | `basic_aces_only_get_acl_revision` | An ACL containing only basic ACE types gets ACL_REVISION (0x02) | §9.9 L3857 | Cargo |
| 205 | `object_or_callback_aces_get_revision_ds` | An ACL containing object-type or callback ACEs gets ACL_REVISION_DS (0x04) | §9.9 L3857–3858 | Cargo |
| 206 | `revision_0x02_rejects_object_type_aces` | An ACL with revision 0x02 containing object-type ACEs (0x05-0x08) is invalid | §9.9 L3846–3853 | Cargo |
| 207 | `revision_0x02_rejects_callback_aces` | An ACL with revision 0x02 containing callback ACEs (0x09-0x10) is invalid | §9.9 L3846–3853 | Cargo |

---

### §9.10 Control Flags (lines 3860–3888)

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 208 | `control_flags_16_bits` | The SD Control field is 16 bits | §9.10 L3862 | Cargo |
| 209 | `se_dacl_present_bit_2` | SE_DACL_PRESENT (DP) is bit 2 | §9.10 L3867 | Cargo |
| 210 | `se_sacl_present_bit_4` | SE_SACL_PRESENT (SP) is bit 4 | §9.10 L3868 | Cargo |
| 211 | `se_dacl_defaulted_bit_3` | SE_DACL_DEFAULTED (DD) is bit 3 (informational) | §9.10 L3869 | Cargo |
| 212 | `se_sacl_defaulted_bit_5` | SE_SACL_DEFAULTED (SD) is bit 5 (informational) | §9.10 L3870 | Cargo |
| 213 | `se_owner_defaulted_bit_0` | SE_OWNER_DEFAULTED (OD) is bit 0 (informational) | §9.10 L3871 | Cargo |
| 214 | `se_group_defaulted_bit_1` | SE_GROUP_DEFAULTED (GD) is bit 1 (informational) | §9.10 L3872 | Cargo |
| 215 | `se_dacl_auto_inherited_bit_10` | SE_DACL_AUTO_INHERITED (DI) is bit 10 | §9.10 L3873 | Cargo |
| 216 | `se_sacl_auto_inherited_bit_11` | SE_SACL_AUTO_INHERITED (SI) is bit 11 | §9.10 L3874 | Cargo |
| 217 | `se_dacl_protected_bit_12` | SE_DACL_PROTECTED (PD) is bit 12 | §9.10 L3875 | Cargo |
| 218 | `se_sacl_protected_bit_13` | SE_SACL_PROTECTED (PS) is bit 13 | §9.10 L3876 | Cargo |
| 219 | `se_self_relative_bit_15` | SE_SELF_RELATIVE (SR) is bit 15 — always set for stored SDs | §9.10 L3877 | Cargo |
| 220 | `se_dacl_trusted_bit_6` | SE_DACL_TRUSTED (DT) is bit 6 | §9.10 L3878 | Cargo |
| 221 | `se_server_security_bit_7` | SE_SERVER_SECURITY (SS) is bit 7 | §9.10 L3879 | Cargo |
| 222 | `se_rm_control_valid_bit_14` | SE_RM_CONTROL_VALID (RM) is bit 14 | §9.10 L3880 | Cargo |
| 223 | `dacl_protected_blocks_inheritable_aces_from_parent` | SE_DACL_PROTECTED: inheritable ACEs from parent objects are not merged into this DACL | §9.10 L3875 | Cargo |
| 224 | `sacl_protected_blocks_inheritable_aces_from_parent` | SE_SACL_PROTECTED: inheritable ACEs from parent objects are not merged into this SACL | §9.10 L3876 | Cargo |
| 225 | `break_inheritance_preserves_existing_aces_as_explicit` | Setting SE_DACL_PROTECTED preserves current ACEs (inherited and explicit become explicit) and stops accepting new inheritable ACEs | §9.10 L3884–3888 | Cargo |
| 226 | `dp_flag_clear_means_null_dacl` | When DP (SE_DACL_PRESENT) is clear, AccessCheck treats the DACL as null (all access granted) | §9.10 L3867 | Cargo |

---

### §9.11 Storage (lines 3890–3942)

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 227 | `file_sd_stored_as_xattr` | File/directory SDs are stored as filesystem extended attributes in self-relative binary format | §9.11 L3895–3896 | Provium |
| 228 | `file_sd_xattr_name_security_peios_sd` | The canonical xattr name is `security.peios.sd` on most filesystems | §9.11 L3897 | Provium |
| 229 | `ntfs_sd_xattr_name_system_ntfs_security` | On NTFS volumes, FACS uses `system.ntfs_security` (ntfs3 driver's native SD xattr) | §9.11 L3898 | Provium |
| 230 | `samba_sd_not_security_ntacl` | FACS does NOT use Samba's `security.NTACL` (which uses NDR envelope with POSIX ACL hashes) | §9.11 L3900–3901 | Provium |
| 231 | `samba_vfs_kacs_reads_canonical_xattr` | Samba interacts with file SDs through `vfs_kacs` VFS module reading/writing the canonical SD xattr directly | §9.11 L3902–3903 | Provium |
| 232 | `sd_max_size_64kb` | Architectural maximum SD size is 64 KB (ACL header AclSize is 16-bit integer) | §9.11 L3907 | Cargo |
| 233 | `filesystem_must_support_64kb_xattr` | Underlying filesystem must support extended attributes of at least 64 KB per value | §9.11 L3906–3907 | Provium |
| 234 | `facs_reads_sd_at_open_time` | FACS reads the SD from the xattr at file open time | §9.11 L3915 | Provium |
| 235 | `facs_parses_sd_in_place` | FACS parses the self-relative buffer in place and passes it to AccessCheck | §9.11 L3916 | Provium |
| 236 | `sd_cached_in_lsm_security_blob` | Parsed SD may be cached in the inode's LSM security blob to avoid repeated xattr reads | §9.11 L3917–3919 | Provium |
| 237 | `registry_sd_same_binary_format` | Registry key SDs use the same self-relative binary format | §9.11 L3922 | Cargo |
| 238 | `registry_sd_stored_by_registryd` | Registry SDs are stored by registryd alongside key data | §9.11 L3921 | Provium |
| 239 | `registry_access_via_impersonation` | registryd enforces access control by impersonating the client and calling AccessCheck via KACS syscall | §9.11 L3924–3926 | Provium |
| 240 | `kernel_objects_sd_inline` | Kernel object SDs (tokens, processes, logon sessions) are stored inline on the kernel object | §9.11 L3933–3934 | Provium |
| 241 | `kernel_object_sd_set_at_creation` | Kernel object SDs are typically set at object creation time | §9.11 L3935–3936 | Provium |
| 242 | `ipc_endpoints_sd_owned_by_service` | IPC endpoint SDs are stored by the service that owns the endpoint | §9.11 L3938–3939 | Provium |
| 243 | `ipc_access_check_before_accept` | When a client connects to an IPC endpoint, the service calls AccessCheck with client token and endpoint SD before accepting | §9.11 L3939–3941 | Provium |

---

## Summary

| Section | Cargo tests | Provium tests | Total |
|---------|-------------|---------------|-------|
| §9.1 Structure | 15 | 0 | 15 |
| §9.2 Access Masks | 16 | 0 | 16 |
| §9.3 ACE Types | 25 | 0 | 25 |
| §9.4 ACE Ordering | 16 | 0 | 16 |
| §9.5 Inheritance | 49 | 4 | 53 |
| §9.6 Conditional ACEs | 39 | 0 | 39 |
| §9.7 Ownership | 10 | 2 | 12 |
| §9.8 Null vs Empty DACL | 7 | 0 | 7 |
| §9.9 ACL Revision | 8 | 0 | 8 |
| §9.10 Control Flags | 19 | 0 | 19 |
| §9.11 Storage | 4 | 13 | 17 |
| **TOTAL** | **208** | **19** | **227** (numbered 1–243, no gaps) |

**Classification rationale:** The vast majority of §9 tests are Cargo tests because Security Descriptors are pure data structures — parsing, serialization, format validation, inheritance computation, ACE ordering, conditional expression evaluation, and access mask manipulation are all pure Rust logic testable without a kernel. The Provium tests are concentrated in §9.5 re-propagation (requires a live filesystem tree walk), §9.7 ownership transfer (requires actual privilege checks through syscalls), and §9.11 storage (requires xattr I/O, LSM blob caching, registryd impersonation, and IPC endpoint behavior in a running system).


---

# Section 11: AccessCheck (First Half)

## AccessCheck Test Corpus -- Section 11 (First Half)

### 11.1 API Variants

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 1 | `access_check_tree_requires_all_nodes_pass` | AccessCheck with object type list fails if any node is denied | 11.1 | Cargo |
| 2 | `access_check_tree_granted_is_intersection` | AccessCheck with tree returns root.granted (intersection of all nodes) | 11.1, 11.17 | Cargo |
| 3 | `access_check_result_list_requires_tree` | AccessCheckResultList without object_tree returns ERROR_INVALID_PARAMETER | 11.1, 11.17 | Cargo |
| 4 | `access_check_result_list_per_node_verdict` | AccessCheckResultList returns per-node granted/status independently | 11.1 | Cargo |
| 5 | `access_check_result_list_partial_denial` | AccessCheckResultList: denial on one property fails only that property, not the whole request | 11.1 | Cargo |
| 6 | `access_check_result_list_max_allowed_returns_per_node_granted` | AccessCheckResultList in MAXIMUM_ALLOWED mode returns node.granted per node | 11.17 | Cargo |
| 7 | `access_check_result_list_normal_mode_returns_desired_or_zero` | AccessCheckResultList in normal mode returns mapped_desired for OK nodes, 0 for denied nodes | 11.17 | Cargo |

### 11.2 Generic Mapping

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 8 | `generic_read_maps_to_specific_bits` | GENERIC_READ in desired mask maps to mapping.read and clears bit 31 | 11.2 | Cargo |
| 9 | `generic_write_maps_to_specific_bits` | GENERIC_WRITE in desired mask maps to mapping.write and clears bit 30 | 11.2 | Cargo |
| 10 | `generic_execute_maps_to_specific_bits` | GENERIC_EXECUTE in desired mask maps to mapping.execute and clears bit 29 | 11.2 | Cargo |
| 11 | `generic_all_maps_to_specific_bits` | GENERIC_ALL in desired mask maps to mapping.all and clears bit 28 | 11.2 | Cargo |
| 12 | `multiple_generic_bits_map_simultaneously` | Multiple generic bits in desired map all at once (OR of all mapped sets) | 11.2 | Cargo |
| 13 | `generic_bits_never_in_comparisons` | After mapping, no generic bits remain in the desired mask | 11.2 | Cargo |
| 14 | `mapped_desired_used_for_success_verdict` | The success/failure verdict compares granted against mapped_desired, not original desired | 11.2 | Cargo |
| 15 | `ace_mask_mapped_defensively_during_walk` | ACE masks in the DACL are mapped through MapGenericBits at evaluation time (not at SD creation) | 11.2, 11.3 | Cargo |
| 16 | `ace_mask_mapping_uses_local_copy` | ACE mask mapping does not mutate the original ACE (uses local copy) | 11.2, 11.3 | Cargo |
| 17 | `map_generic_bits_noop_if_no_generic_bits` | MapGenericBits is a no-op when input has no generic bits set | 11.2 | Cargo |
| 18 | `generic_bits_in_ace_mask_work_after_mapping` | An ACE with GENERIC_READ in its mask grants the mapped-specific bits, not bit 31 | 11.2, 11.3 | Cargo |

### 11.3 DACL Walk -- Core Mechanics

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 19 | `allow_ace_grants_undecided_bits` | Allow ACE grants rights for bits not yet decided | 11.3 | Cargo |
| 20 | `deny_ace_denies_undecided_bits` | Deny ACE marks bits as decided-but-not-granted for undecided bits | 11.3 | Cargo |
| 21 | `first_writer_wins_deny_before_allow` | A deny ACE preceding an allow ACE for the same bits: deny wins | 11.3 | Cargo |
| 22 | `first_writer_wins_allow_before_deny` | An allow ACE preceding a deny ACE for the same bits: allow wins | 11.3 | Cargo |
| 23 | `already_decided_bits_unaffected_by_later_allow` | An allow ACE cannot override bits already decided (either granted or denied) | 11.3 | Cargo |
| 24 | `already_decided_bits_unaffected_by_later_deny` | A deny ACE cannot override bits already decided (either granted or denied) | 11.3 | Cargo |
| 25 | `each_bit_decided_at_most_once` | Each bit position is resolved at most once during the DACL walk | 11.3 | Cargo |
| 26 | `non_canonical_order_respects_position` | Non-canonical ACE ordering (allow before deny) grants via first-writer-wins | 11.3 | Cargo |
| 27 | `no_hard_failure_on_denial` | Denials during the walk are recorded as decided-not-granted, not errors | 11.3 | Cargo |

### 11.3 DACL Walk -- SID Matching

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 28 | `allow_ace_matches_user_sid` | Allow ACE with token's user SID matches | 11.3 | Cargo |
| 29 | `allow_ace_matches_enabled_group` | Allow ACE matches a group SID that has SE_GROUP_ENABLED | 11.3 | Cargo |
| 30 | `allow_ace_skips_deny_only_group` | Allow ACE does NOT match a group with USE_FOR_DENY_ONLY | 11.3 | Cargo |
| 31 | `deny_ace_matches_deny_only_group` | Deny ACE DOES match a group with USE_FOR_DENY_ONLY | 11.3 | Cargo |
| 32 | `deny_ace_matches_enabled_group` | Deny ACE matches a group with SE_GROUP_ENABLED | 11.3 | Cargo |
| 33 | `neither_enabled_nor_deny_only_skipped` | A group with neither ENABLED nor USE_FOR_DENY_ONLY is invisible to both allow and deny ACEs | 11.3 | Cargo |
| 34 | `user_sid_deny_only_blocks_allow` | Token with user SID marked deny-only: user SID matches deny ACEs but not allow ACEs | 11.3 | Cargo |
| 35 | `user_sid_deny_only_matches_deny` | Token with user SID marked deny-only: deny ACE targeting user SID fires | 11.3 | Cargo |
| 36 | `ace_sid_no_match_skipped` | ACE whose SID matches neither user SID nor any group SID is skipped | 11.3 | Cargo |
| 37 | `deny_only_group_blocks_access_via_deny_ace` | A deny-only group triggers deny ACEs that block access but cannot grant via allow ACEs | 11.3, 11.7 | Cargo |

### 11.3 DACL Walk -- Special Cases

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 38 | `inherit_only_ace_skipped` | ACE with INHERIT_ONLY flag is skipped during the DACL walk | 11.3 | Cargo |
| 39 | `null_dacl_grants_all_valid_bits` | SD with SE_DACL_PRESENT clear grants all valid rights (via MapGenericBits(GENERIC_ALL)) | 11.3 | Cargo |
| 40 | `null_dacl_does_not_grant_garbage_bits` | NULL DACL grants MapGenericBits(GENERIC_ALL, mapping), not raw 0xFFFFFFFF | 11.3 | Cargo |
| 41 | `null_dacl_respects_already_decided` | NULL DACL only grants bits not already decided by earlier pipeline stages | 11.3 | Cargo |
| 42 | `empty_dacl_grants_nothing` | DACL present with zero ACEs: no rights are granted by the walk | 11.3 | Cargo |
| 43 | `short_circuit_when_all_desired_decided` | Walk stops early when all bits in desired are decided (optimization) | 11.3 | Cargo |
| 44 | `short_circuit_disabled_in_max_allowed` | In MAXIMUM_ALLOWED mode, walk runs to completion even if all desired bits decided | 11.3, 11.5 | Cargo |
| 45 | `short_circuit_not_applied_with_tree` | Short-circuit does not apply when object_tree is present | 11.3, 11.17 | Cargo |
| 46 | `duplicate_guids_in_tree_rejected` | Object type list with duplicate GUIDs returns ERROR_INVALID_PARAMETER | 11.3 | Cargo |
| 47 | `level_gap_in_tree_rejected` | Object type list with level gap (level 3 after level 1) returns ERROR_INVALID_PARAMETER | 11.3 | Cargo |

### 11.4 Owner Implicit Rights

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 48 | `owner_gets_read_control_write_dac` | Owner receives READ_CONTROL and WRITE_DAC regardless of DACL contents | 11.4 | Cargo |
| 49 | `owner_implicit_before_dacl_walk` | Owner implicit rights are granted before the DACL walk (deny ACEs cannot override them) | 11.4 | Cargo |
| 50 | `owner_implicit_immune_to_deny_aces` | A deny ACE for READ_CONTROL/WRITE_DAC against the owner does not override implicit rights | 11.4 | Cargo |
| 51 | `owner_rights_sid_suppresses_implicit` | Presence of any ACE targeting S-1-3-4 (OWNER RIGHTS) in the DACL suppresses the implicit grant | 11.4 | Cargo |
| 52 | `owner_rights_deny_ace_suppresses_implicit` | A deny ACE targeting OWNER RIGHTS suppresses implicit grant (mere presence triggers suppression) | 11.4 | Cargo |
| 53 | `owner_rights_prescan_ignores_inherit_only` | Pre-scan for OWNER RIGHTS skips inherit-only ACEs | 11.4 | Cargo |
| 54 | `owner_rights_prescan_ignores_non_access_control` | Pre-scan for OWNER RIGHTS ignores non-access-control ACE types (e.g., audit ACEs in SACL) | 11.4 | Cargo |
| 55 | `owner_rights_prescan_checks_presence_not_condition` | Pre-scan checks for ACE presence only, not conditional expression result | 11.4, 11.12 | Cargo |
| 56 | `owner_rights_allow_ace_narrows_access` | OWNER RIGHTS allow ACE with only READ_CONTROL: owner gets READ_CONTROL but not WRITE_DAC | 11.4 | Cargo |
| 57 | `owner_rights_allow_ace_expands_access` | OWNER RIGHTS allow ACE with READ_CONTROL+WRITE_DAC+DELETE: owner gets more than default | 11.4 | Cargo |
| 58 | `owner_rights_sid_matches_owner_in_walk` | During DACL walk, S-1-3-4 ACEs match the owner as if they were normal SID ACEs | 11.4 | Cargo |
| 59 | `owner_rights_not_exclusive_channel` | Owner also receives access from ACEs matching their user/group SIDs in addition to S-1-3-4 | 11.4 | Cargo |
| 60 | `owner_empty_dacl_gets_implicit_rights_only` | Owner with empty DACL receives only READ_CONTROL+WRITE_DAC (from implicit rights) | 11.3, 11.4 | Cargo |
| 61 | `owner_implicit_rights_on_tree_nodes` | Owner implicit rights (READ_CONTROL+WRITE_DAC) are applied to all tree nodes | 11.4, 11.17 | Cargo |

### 11.5 MAXIMUM_ALLOWED

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 62 | `max_allowed_stripped_before_evaluation` | MAXIMUM_ALLOWED bit is stripped from desired mask before evaluation | 11.5 | Cargo |
| 63 | `max_allowed_not_a_right` | MAXIMUM_ALLOWED cannot appear in an ACE mask | 11.5 | Cargo |
| 64 | `max_allowed_returns_full_effective_mask` | MAXIMUM_ALLOWED mode returns the complete set of rights the pipeline accumulated | 11.5 | Cargo |
| 65 | `max_allowed_no_short_circuit` | MAXIMUM_ALLOWED mode: DACL walk runs to completion (all ACEs evaluated) | 11.5 | Cargo |
| 66 | `max_allowed_combined_with_specific_rights` | MAXIMUM_ALLOWED | READ_CONTROL: allowed reflects whether READ_CONTROL granted; granted reflects full mask | 11.5 | Cargo |
| 67 | `max_allowed_with_ass_without_privilege` | MAXIMUM_ALLOWED | ACCESS_SYSTEM_SECURITY without SeSecurityPrivilege: allowed=false, granted has everything else | 11.5 | Cargo |
| 68 | `pure_max_allowed_always_succeeds` | Pure MAXIMUM_ALLOWED with no specific bits always returns allowed=true | 11.5 | Cargo |
| 69 | `pure_max_allowed_zero_granted_succeeds` | Pure MAXIMUM_ALLOWED that produces zero granted returns allowed=true (not an error) | 11.5 | Cargo |
| 70 | `max_allowed_first_writer_wins_same_as_targeted` | MAXIMUM_ALLOWED uses same first-writer-wins as targeted requests (no accumulate-and-subtract) | 11.5 | Cargo |
| 71 | `max_allowed_agrees_with_targeted_on_noncanonical_dacl` | On non-canonical DACL, MAXIMUM_ALLOWED and targeted request agree (Peios divergence from Windows) | 11.5 | Cargo |
| 72 | `zero_desired_mask_succeeds` | Zero desired mask (no rights requested) returns allowed=true | 11.5, 11.17 | Cargo |

### 11.6 Privileges in AccessCheck

#### SeSecurityPrivilege / ACCESS_SYSTEM_SECURITY

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 73 | `ass_granted_with_security_privilege` | ACCESS_SYSTEM_SECURITY granted when SeSecurityPrivilege is present and enabled | 11.6 | Cargo |
| 74 | `ass_denied_without_security_privilege` | ACCESS_SYSTEM_SECURITY denied when SeSecurityPrivilege is absent | 11.6 | Cargo |
| 75 | `ass_always_decided_before_dacl` | ACCESS_SYSTEM_SECURITY is always decided before the DACL walk | 11.6 | Cargo |
| 76 | `ass_no_dacl_ace_can_grant_it` | No DACL ACE can grant ACCESS_SYSTEM_SECURITY (bit always resolved before walk) | 11.6 | Cargo |
| 77 | `ass_no_dacl_ace_can_deny_it` | No DACL ACE can deny ACCESS_SYSTEM_SECURITY (already decided) | 11.6 | Cargo |
| 78 | `ass_denial_no_early_out` | Missing SeSecurityPrivilege does not cause an early-out; denial falls out from final result computation | 11.6 | Cargo |
| 79 | `ass_tracked_in_privilege_granted` | ACCESS_SYSTEM_SECURITY grant is tracked in privilege_granted mask | 11.6 | Cargo |
| 80 | `ass_tracked_in_security_provenance` | ACCESS_SYSTEM_SECURITY is attributed to SeSecurityPrivilege in provenance | 11.17 | Cargo |

#### SeTakeOwnershipPrivilege

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 81 | `take_ownership_grants_write_owner_if_dacl_did_not` | SeTakeOwnershipPrivilege grants WRITE_OWNER only if the DACL did not independently grant it | 11.6 | Cargo |
| 82 | `take_ownership_silent_when_dacl_granted` | If DACL granted WRITE_OWNER, SeTakeOwnershipPrivilege stays silent (not exercised, not audited) | 11.6 | Cargo |
| 83 | `take_ownership_post_dacl_position` | SeTakeOwnershipPrivilege is evaluated after the DACL walk (step 7a) | 11.6, 11.17 | Cargo |
| 84 | `take_ownership_overrides_dacl_deny` | SeTakeOwnershipPrivilege overrides a DACL deny ACE for WRITE_OWNER (deny-proof) | 11.6, 11.17 | Cargo |
| 85 | `take_ownership_respects_mic_mandatory_decided` | SeTakeOwnershipPrivilege does NOT override MIC-decided WRITE_OWNER (checks mandatory_decided) | 11.6, 11.17 | Cargo |
| 86 | `take_ownership_respects_pip_mandatory_decided` | SeTakeOwnershipPrivilege does NOT override PIP-decided WRITE_OWNER | 11.6, 11.17 | Cargo |
| 87 | `take_ownership_tracked_in_privilege_granted` | WRITE_OWNER granted by SeTakeOwnershipPrivilege tracked in privilege_granted | 11.6, 11.17 | Cargo |
| 88 | `take_ownership_in_max_allowed_mode` | In MAXIMUM_ALLOWED mode, SeTakeOwnershipPrivilege is evaluated (WRITE_OWNER or max_allowed_mode guard) | 11.17 | Cargo |
| 89 | `take_ownership_updates_tree_nodes` | SeTakeOwnershipPrivilege grants WRITE_OWNER to all tree nodes that lack it | 11.17 | Cargo |

#### SeBackupPrivilege / SeRestorePrivilege

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 90 | `backup_privilege_grants_all_read_bits` | SeBackupPrivilege grants MapGenericBits(GENERIC_READ, mapping) | 11.6 | Cargo |
| 91 | `restore_privilege_grants_all_write_bits_plus_extras` | SeRestorePrivilege grants MapGenericBits(GENERIC_WRITE) | WRITE_DAC | WRITE_OWNER | DELETE | ACCESS_SYSTEM_SECURITY | 11.6, 11.17 | Cargo |
| 92 | `backup_intent_gated` | SeBackupPrivilege is invisible without BACKUP_INTENT flag | 11.6 | Cargo |
| 93 | `restore_intent_gated` | SeRestorePrivilege is invisible without RESTORE_INTENT flag | 11.6 | Cargo |
| 94 | `backup_with_intent_grants_rights` | SeBackupPrivilege + BACKUP_INTENT grants all read-mapped bits | 11.6 | Cargo |
| 95 | `restore_with_intent_grants_rights` | SeRestorePrivilege + RESTORE_INTENT grants all write-mapped bits plus extras | 11.6 | Cargo |
| 96 | `backup_without_intent_invisible` | Token has SeBackupPrivilege but no BACKUP_INTENT: backup bits not granted | 11.6 | Cargo |
| 97 | `restore_without_intent_invisible` | Token has SeRestorePrivilege but no RESTORE_INTENT: restore bits not granted | 11.6 | Cargo |
| 98 | `intent_gated_inside_pipeline_not_bypass` | Backup/restore privileges are evaluated inside AccessCheck, not as a short-circuit bypass | 11.6 | Cargo |
| 99 | `backup_bits_tracked_in_privilege_granted` | Bits from SeBackupPrivilege tracked in privilege_granted and backup_granted provenance | 11.17 | Cargo |
| 100 | `restore_bits_tracked_in_privilege_granted` | Bits from SeRestorePrivilege tracked in privilege_granted and restore_granted provenance | 11.17 | Cargo |

#### SeRelabelPrivilege

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 101 | `relabel_privilege_loosens_mic_for_write_owner` | SeRelabelPrivilege allows WRITE_OWNER through MIC even when caller is non-dominant | 11.6, 11.13 | Cargo |
| 102 | `relabel_privilege_does_not_grant_directly` | SeRelabelPrivilege does not grant any access rights directly (only loosens MIC) | 11.6 | Cargo |
| 103 | `relabel_audit_when_write_owner_granted_and_no_take_ownership` | SeRelabelPrivilege audit fires when WRITE_OWNER granted AND SeTakeOwnershipPrivilege did not claim it | 11.17 | Cargo |

### 11.7 Restricted Tokens

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 104 | `restricted_token_two_pass_evaluation` | Restricted token: DACL evaluated twice (normal pass and restricted pass) | 11.7 | Cargo |
| 105 | `restricted_intersection_normal_and_restricted` | Final granted = intersection of normal pass and restricted pass | 11.7 | Cargo |
| 106 | `restricted_pass_matches_only_restricting_sids` | Restricted pass: ACE matches only if its SID appears in restricting SID list | 11.7 | Cargo |
| 107 | `restricted_caps_access` | Normal pass grants READ+WRITE, restricted grants only READ: final is READ only | 11.7 | Cargo |
| 108 | `write_restricted_intersection_only_write_bits` | Write-restricted token: intersection applies only to write-category bits (from GENERIC_WRITE mapping) | 11.7 | Cargo |
| 109 | `write_restricted_read_from_normal_pass_only` | Write-restricted token: read/execute access comes from normal pass alone | 11.7 | Cargo |
| 110 | `privilege_granted_bypass_restricted` | Privilege-granted bits are OR'd back after intersection (privileges bypass restricted pass) | 11.7 | Cargo |
| 111 | `owner_implicit_rights_in_restricted_pass` | Restricted pass grants owner implicit rights if owner SID is in restricting SID list | 11.7 | Cargo |
| 112 | `restricted_pass_no_owner_implicit_if_owner_not_restricting` | Restricted pass does NOT grant owner implicit rights if owner SID is NOT in restricting SID list | 11.7 | Cargo |
| 113 | `restricted_pass_owner_rights_suppression` | Restricted pass independently evaluates OWNER RIGHTS suppression | 11.7 | Cargo |
| 114 | `restricted_pass_fresh_tree` | Restricted pass starts with fresh decided=0/granted=0 per tree node | 11.17 | Cargo |
| 115 | `restricted_tree_merge_per_node` | Tree merge: per-node intersection between normal and restricted pass | 11.17 | Cargo |
| 116 | `restricted_tree_privilege_orback` | Tree merge: privilege_granted OR'd back into each node after intersection | 11.17 | Cargo |
| 117 | `write_restricted_tree_merge` | Write-restricted tree merge: intersection only on write-category bits per node | 11.17 | Cargo |
| 118 | `restricted_virtual_groups_injected` | Restricted pass injects S-1-3-4 if owner in restricting SIDs, S-1-5-10 if self_sid in restricting SIDs | 11.17 | Cargo |
| 119 | `restricted_device_groups_swapped` | Restricted pass: if token has restricted_device_groups, conditional expressions see restricted set | 11.17 | Cargo |
| 120 | `deny_only_group_in_restricted_context` | Deny-only groups reduce normal pass grants via deny ACEs (different from restricting SIDs which add a second eval) | 11.7 | Cargo |

### 11.8 Object ACEs and Property-Level Access

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 121 | `object_ace_without_guid_is_basic_ace` | Object ACE without ACE_OBJECT_TYPE_PRESENT behaves as a basic ACE (whole object) | 11.8 | Cargo |
| 122 | `object_ace_with_guid_targets_specific_node` | Object ACE with GUID updates only the targeted tree node (and propagation targets) | 11.8 | Cargo |
| 123 | `object_ace_guid_ignored_without_tree` | Object ACE with GUID but no object_tree: GUID ignored, treated as basic ACE | 11.8 | Cargo |
| 124 | `object_ace_guid_not_in_tree_skipped` | Object ACE whose GUID does not match any tree node is skipped (FindNode returns null) | 11.8, 11.17 | Cargo |
| 125 | `downward_grant_propagation` | Allow object ACE on property set grants to all child attributes | 11.8 | Cargo |
| 126 | `downward_grant_respects_first_writer_wins` | Downward grant does not override a child attribute that was already denied by an earlier ACE | 11.8 | Cargo |
| 127 | `upward_grant_aggregation` | When all siblings share a granted right, it propagates up to the parent node | 11.8 | Cargo |
| 128 | `upward_grant_per_bit_intersection` | Upward propagation uses per-bit intersection: right propagates to parent only if ALL siblings share it | 11.8 | Cargo |
| 129 | `upward_grant_propagation_to_root` | Aggregation continues upward to root: if every property set has a right, root gets it | 11.8 | Cargo |
| 130 | `upward_grant_stops_if_not_all_siblings` | Upward propagation stops if not all siblings share the granted right | 11.8, 11.17 | Cargo |
| 131 | `upward_deny_propagation_unconditional` | Deny object ACE on a child: denial propagates upward unconditionally to parent and root | 11.8 | Cargo |
| 132 | `upward_deny_does_not_affect_siblings` | Upward deny propagation does not affect sibling nodes | 11.8 | Cargo |
| 133 | `downward_deny_propagation` | Deny object ACE on property set: denial flows to all child attributes | 11.8 | Cargo |
| 134 | `downward_deny_respects_first_writer_wins` | Downward deny does not override child attributes already granted by earlier ACE | 11.8 | Cargo |
| 135 | `non_object_ace_affects_all_nodes` | Basic (non-object) ACE affects all tree nodes | 11.8 | Cargo |

#### PRINCIPAL_SELF

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 136 | `principal_self_matches_caller_who_is_object_principal` | ACE targeting S-1-5-10 matches when caller's token represents the same principal as object | 11.8 | Cargo |
| 137 | `principal_self_no_match_without_self_sid` | If self_sid is null, PRINCIPAL_SELF ACEs match nothing | 11.8 | Cargo |
| 138 | `principal_self_deny_only_allow_deny_asymmetry` | If caller matches self_sid via deny-only SID, S-1-5-10 matches for deny ACEs but not allow ACEs | 11.8 | Cargo |
| 139 | `principal_self_in_basic_ace` | PRINCIPAL_SELF (S-1-5-10) can appear in basic ACEs (not just object ACEs) | 11.8 | Cargo |
| 140 | `principal_self_inject_via_enrich_token` | EnrichToken injects S-1-5-10 as virtual group when self_sid matches caller | 11.17 | Cargo |
| 141 | `principal_self_deny_only_virtual_group` | EnrichToken: if self_sid matches only via deny SID match, S-1-5-10 injected as deny_only virtual group | 11.17 | Cargo |

#### Object Type List Validation

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 142 | `tree_empty_rejected` | Empty object_tree returns ERROR_INVALID_PARAMETER | 11.17 | Cargo |
| 143 | `tree_root_not_level_zero_rejected` | Object tree where first node is not level 0 returns ERROR_INVALID_PARAMETER | 11.17 | Cargo |
| 144 | `tree_negative_level_rejected` | Object tree with negative level returns ERROR_INVALID_PARAMETER | 11.17 | Cargo |
| 145 | `tree_multiple_level_zero_rejected` | Object tree with more than one level-0 node returns ERROR_INVALID_PARAMETER | 11.17 | Cargo |
| 146 | `tree_level_gap_rejected` | Object tree with node at level N+2 following level N (gap) returns ERROR_INVALID_PARAMETER | 11.17 | Cargo |
| 147 | `tree_duplicate_guids_rejected` | Object tree with duplicate GUIDs returns ERROR_INVALID_PARAMETER | 11.17 | Cargo |
| 148 | `tree_initialization_copies_scalar_state` | Tree initialization copies scalar decided/granted to each node | 11.17 | Cargo |

### 11.10 Auditing

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 149 | `audit_ace_does_not_affect_access_decision` | Audit ACE never grants or denies rights (purely observational) | 11.10 | Cargo |
| 150 | `audit_ace_success_flag_gates_success_audit` | SUCCESSFUL_ACCESS_ACE_FLAG controls whether successful access is audited | 11.10 | Cargo |
| 151 | `audit_ace_failure_flag_gates_failure_audit` | FAILED_ACCESS_ACE_FLAG controls whether failed access is audited | 11.10 | Cargo |
| 152 | `audit_ace_both_flags_audits_everything` | ACE with both success and failure flags audits all matching access attempts | 11.10 | Cargo |
| 153 | `audit_sid_matches_with_deny_polarity` | Audit ACE SID matching uses deny polarity (broadest identity view) | 11.10 | Cargo |
| 154 | `audit_inherit_only_skipped` | Audit ACE with INHERIT_ONLY is skipped | 11.10 | Cargo |
| 155 | `audit_no_flags_skipped` | Audit ACE with neither success nor failure flag is skipped | 11.10 | Cargo |
| 156 | `audit_conditional_unknown_fires` | Conditional audit ACE: UNKNOWN condition fires the event (when in doubt, audit) | 11.10, 11.12 | Cargo |
| 157 | `audit_conditional_false_skipped` | Conditional audit ACE: FALSE condition skips the event | 11.10, 11.12 | Cargo |
| 158 | `audit_object_per_node_success` | Object-scoped audit ACE: success computed per-node, not whole object | 11.10, 11.17 | Cargo |
| 159 | `continuous_audit_alarm_ace_builds_mask` | SYSTEM_ALARM ACE builds continuous_audit_mask on successful access | 11.10 | Cargo |
| 160 | `continuous_audit_only_on_success` | Continuous audit (alarm ACEs) only evaluated on successful access | 11.10 | Cargo |
| 161 | `continuous_audit_intersect_with_granted` | Continuous audit mask intersected with granted rights (only audit what the handle can do) | 11.10 | Cargo |
| 162 | `privilege_use_audit_only_when_necessary` | Privilege-use audit fires only when the privilege was actually necessary for the final result | 11.10, 11.17 | Cargo |
| 163 | `privilege_use_audit_not_in_max_allowed` | Privilege-use auditing does not fire in MAXIMUM_ALLOWED mode | 11.17 | Cargo |
| 164 | `privilege_use_audit_after_cap_and_pip` | Privilege-use audit fires after the complete pipeline (after CAP/PIP may have revoked bits) | 11.10, 11.17 | Cargo |
| 165 | `per_token_audit_policy_success` | Token audit_policy.object_access_success fires unconditionally regardless of SACL | 11.17 | Cargo |
| 166 | `per_token_audit_policy_failure` | Token audit_policy.object_access_failure fires unconditionally regardless of SACL | 11.17 | Cargo |

### 11.11 Resource Attributes

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 167 | `resource_attrs_extracted_before_dacl_walk` | Resource attributes from SACL are available when conditional expressions need them | 11.11 | Cargo |
| 168 | `resource_attr_first_name_wins` | If two resource attribute ACEs have the same name, the first one wins | 11.11 | Cargo |
| 169 | `resource_attr_does_not_grant_deny` | Resource attributes do not directly grant or deny access | 11.11 | Cargo |
| 170 | `resource_attr_available_to_conditional_dacl` | Resource attributes are available to conditional expressions in DACL ACEs | 11.11, 11.12 | Cargo |
| 171 | `resource_attr_available_to_conditional_audit` | Resource attributes are available to conditional audit ACEs in the SACL | 11.11, 11.10 | Cargo |

### 11.12 Conditional ACEs

#### Condition Evaluation Three-Value Logic

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 172 | `conditional_allow_fires_only_on_true` | Conditional allow ACE takes effect only when condition evaluates to TRUE | 11.12 | Cargo |
| 173 | `conditional_allow_skipped_on_false` | Conditional allow ACE skipped when condition is FALSE | 11.12 | Cargo |
| 174 | `conditional_allow_skipped_on_unknown` | Conditional allow ACE skipped when condition is UNKNOWN | 11.12 | Cargo |
| 175 | `conditional_deny_fires_on_true` | Conditional deny ACE takes effect when condition is TRUE | 11.12 | Cargo |
| 176 | `conditional_deny_fires_on_unknown` | Conditional deny ACE takes effect when condition is UNKNOWN (fail-safe) | 11.12 | Cargo |
| 177 | `conditional_deny_skipped_on_false` | Conditional deny ACE skipped only when condition is FALSE | 11.12 | Cargo |
| 178 | `three_value_and_false_false` | AND: both FALSE = FALSE | 11.12 | Cargo |
| 179 | `three_value_and_true_true` | AND: both TRUE = TRUE | 11.12 | Cargo |
| 180 | `three_value_and_true_false` | AND: TRUE and FALSE = FALSE | 11.12 | Cargo |
| 181 | `three_value_and_true_unknown` | AND: TRUE and UNKNOWN = UNKNOWN | 11.12 | Cargo |
| 182 | `three_value_and_false_unknown` | AND: FALSE and UNKNOWN = FALSE | 11.12 | Cargo |
| 183 | `three_value_and_unknown_unknown` | AND: UNKNOWN and UNKNOWN = UNKNOWN | 11.12 | Cargo |
| 184 | `three_value_or_true_true` | OR: both TRUE = TRUE | 11.12 | Cargo |
| 185 | `three_value_or_false_false` | OR: both FALSE = FALSE | 11.12 | Cargo |
| 186 | `three_value_or_true_false` | OR: TRUE and FALSE = TRUE | 11.12 | Cargo |
| 187 | `three_value_or_true_unknown` | OR: TRUE and UNKNOWN = TRUE | 11.12 | Cargo |
| 188 | `three_value_or_false_unknown` | OR: FALSE and UNKNOWN = UNKNOWN | 11.12 | Cargo |
| 189 | `three_value_or_unknown_unknown` | OR: UNKNOWN and UNKNOWN = UNKNOWN | 11.12 | Cargo |
| 190 | `three_value_not_true` | NOT TRUE = FALSE | 11.12 | Cargo |
| 191 | `three_value_not_false` | NOT FALSE = TRUE | 11.12 | Cargo |
| 192 | `three_value_not_unknown` | NOT UNKNOWN = UNKNOWN | 11.12 | Cargo |

#### Boolean Coercion

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 193 | `bool_coerce_int_nonzero_true` | INT64/UINT64 nonzero coerces to TRUE for logical operators | 11.12 | Cargo |
| 194 | `bool_coerce_int_zero_false` | INT64/UINT64 zero coerces to FALSE | 11.12 | Cargo |
| 195 | `bool_coerce_string_nonempty_true` | Non-empty STRING coerces to TRUE | 11.12 | Cargo |
| 196 | `bool_coerce_string_empty_false` | Empty STRING coerces to FALSE | 11.12 | Cargo |
| 197 | `bool_coerce_null_unknown` | NULL coerces to UNKNOWN | 11.12 | Cargo |
| 198 | `bool_coerce_sid_unknown` | SID coerces to UNKNOWN (not boolean) | 11.12 | Cargo |
| 199 | `bool_coerce_octet_unknown` | OCTET coerces to UNKNOWN (not boolean) | 11.12 | Cargo |
| 200 | `bool_coerce_composite_unknown` | COMPOSITE coerces to UNKNOWN (not boolean) | 11.12 | Cargo |
| 201 | `literal_in_logical_context_unknown` | Literal-origin values in logical operators produce UNKNOWN (literals are not boolean propositions) | 11.12 | Cargo |

#### Attribute Resolution

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 202 | `user_attr_resolves_from_token` | @User. prefix resolves from token.user_claims | 11.12 | Cargo |
| 203 | `device_attr_resolves_from_token` | @Device. prefix resolves from token.device_claims | 11.12 | Cargo |
| 204 | `resource_attr_resolves_from_sacl` | @Resource. prefix resolves from SACL resource attributes | 11.12, 11.11 | Cargo |
| 205 | `local_attr_resolves_from_parameter` | @Local. prefix resolves from AccessCheck parameter (not token) | 11.12 | Cargo |
| 206 | `missing_device_claims_resolve_absent` | @Device. references resolve as absent (NULL) when device claims not populated | 11.12 | Cargo |

#### Claim Flags

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 207 | `disabled_claim_invisible` | DISABLED flag (0x0010) makes attribute invisible to all conditions (resolves as NULL) | 11.12 | Cargo |
| 208 | `deny_only_claim_invisible_to_allow` | USE_FOR_DENY_ONLY (0x0004) claim resolves as absent for allow ACE conditions | 11.12 | Cargo |
| 209 | `deny_only_claim_visible_to_deny` | USE_FOR_DENY_ONLY claim is visible to deny ACE conditions | 11.12 | Cargo |
| 210 | `deny_only_resource_attr_invisible_to_allow` | USE_FOR_DENY_ONLY on a resource attribute: invisible to allow-ACE conditions | 11.12 | Cargo |
| 211 | `empty_attr_normalized_to_null` | Attribute with zero values normalized to absent (NULL) at resolution time | 11.12 | Cargo |
| 212 | `exists_false_for_empty_attr` | Exists returns FALSE for empty attributes (normalized to NULL) | 11.12 | Cargo |
| 213 | `empty_attr_deny_unknown_fires` | Empty attribute on deny ACE condition: evaluates to UNKNOWN, deny fires (fail-safe) | 11.12 | Cargo |

#### Conditional OWNER RIGHTS

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 214 | `conditional_owner_rights_suppresses_even_if_false` | Conditional ACE targeting S-1-3-4 suppresses implicit grant even if condition evaluates to FALSE | 11.12, 11.4 | Cargo |
| 215 | `conditional_owner_rights_lockout_scenario` | Conditional OWNER RIGHTS with FALSE condition: owner loses implicit rights AND gets nothing from ACE | 11.12 | Cargo |

#### Virtual Groups in Expressions

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 216 | `member_of_owner_rights_true_for_owner` | Member_of({S-1-3-4}) returns TRUE when caller is the owner (virtual group visible) | 11.12 | Cargo |
| 217 | `member_of_principal_self_true_for_self` | Member_of({S-1-5-10}) returns TRUE when caller matches self_sid | 11.12 | Cargo |
| 218 | `virtual_groups_visible_to_expressions` | Conditional expressions see virtual groups injected by EnrichToken | 11.12 | Cargo |

#### Expression Evaluation Edge Cases

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 219 | `sid_match_before_condition_eval` | SID is matched first; condition expression evaluated only if SID matches | 11.12 | Cargo |
| 220 | `conditional_object_ace_combines_condition_and_guid` | ACCESS_ALLOWED_CALLBACK_OBJECT combines conditional expression with property-level GUID targeting | 11.12, 11.8 | Cargo |
| 221 | `callback_ace_no_condition_data_returns_unknown` | Callback allow ACE with null condition data evaluates as UNKNOWN (skipped) | 11.12, 11.17 | Cargo |
| 222 | `callback_ace_means_conditional` | Callback ACE types exist solely to carry conditional expressions in Peios (no Windows callback mechanism) | 11.12 | Cargo |
| 223 | `int64_uint64_promotion` | INT64 vs UINT64 comparison: negative INT64 always less than any UINT64, overlapping range compared as integers (Peios divergence) | 11.12 | Cargo |
| 224 | `member_of_polarity_aware` | Member_of filters deny-only groups by ACE polarity (Peios divergence from MS-DTYP) | 11.12 | Cargo |
| 225 | `exists_extended_to_all_namespaces` | Exists/Not_Exists extended to all four namespaces (@User., @Device., @Local., @Resource.) | 11.12 | Cargo |
| 226 | `composite_equality_element_wise` | Composite-vs-composite equality uses element-wise ordering (same length, order, elements) | 11.12 | Cargo |
| 227 | `expression_magic_header_required` | Expression must start with artx magic bytes [0x61, 0x72, 0x74, 0x78]; else UNKNOWN | 11.17 | Cargo |
| 228 | `expression_stack_not_one_at_end_unknown` | If stack does not have exactly one element after full evaluation, return UNKNOWN | 11.17 | Cargo |
| 229 | `expression_final_literal_returns_unknown` | If final stack element has origin=LITERAL, return UNKNOWN | 11.17 | Cargo |
| 230 | `expression_bounds_violation_unknown` | Any read beyond condition buffer bounds returns UNKNOWN | 11.17 | Cargo |
| 231 | `expression_unknown_opcode_unknown` | Unknown opcode returns UNKNOWN | 11.17 | Cargo |
| 232 | `expression_insufficient_stack_unknown` | Operator with insufficient stack operands returns UNKNOWN | 11.17 | Cargo |
| 233 | `exists_requires_attr_origin` | Exists/Not_Exists: operand must have attribute origin (LOCAL_ATTR, RESOURCE_ATTR, USER_ATTR, DEVICE_ATTR); else UNKNOWN | 11.17 | Cargo |
| 234 | `member_of_all_sids_required` | Member_of requires ALL SIDs in the list to match the token (conjunction) | 11.17 | Cargo |
| 235 | `member_of_any_any_sid_sufficient` | Member_of_Any requires ANY SID in the list to match (disjunction) | 11.17 | Cargo |
| 236 | `device_member_of_null_device_groups_unknown` | Device_Member_of with null device_groups: returns UNKNOWN | 11.17 | Cargo |
| 237 | `not_member_of_negates_member_of` | Not_Member_of is logical negation of Member_of | 11.17 | Cargo |
| 238 | `to_sid_list_empty_composite_error` | to_sid_list with empty composite returns error (UNKNOWN in context) | 11.17 | Cargo |
| 239 | `to_sid_list_non_sid_element_error` | to_sid_list with non-SID element in composite returns error | 11.17 | Cargo |
| 240 | `compare_equal_null_unknown` | compare_equal: NULL operand returns UNKNOWN | 11.17 | Cargo |
| 241 | `compare_equal_scalar_vs_composite_unknown` | compare_equal: scalar vs composite returns UNKNOWN | 11.17 | Cargo |
| 242 | `compare_equal_type_mismatch_unknown` | compare_equal: incompatible types return UNKNOWN | 11.17 | Cargo |
| 243 | `string_compare_case_insensitive_default` | String comparison is case-insensitive by default (ASCII folding only) | 11.17 | Cargo |
| 244 | `string_compare_case_sensitive_flag` | CASE_SENSITIVE flag (0x0002) on either operand forces case-sensitive comparison | 11.17 | Cargo |
| 245 | `boolean_normalized_on_resolution` | BOOLEAN values normalized to 1/0 at resolution time regardless of wire encoding | 11.17 | Cargo |
| 246 | `resolve_claim_case_insensitive_lookup` | Claim resolution uses case-insensitive name lookup | 11.17 | Cargo |
| 247 | `resolve_claim_null_claims_returns_null` | resolve_claim with null claims source returns Value(NULL) | 11.17 | Cargo |
| 248 | `resolve_claim_name_not_found_returns_null` | resolve_claim for missing name returns Value(NULL) | 11.17 | Cargo |
| 249 | `multi_valued_claim_returns_composite` | Claim with multiple values resolves as COMPOSITE | 11.17 | Cargo |
| 250 | `single_valued_claim_returns_scalar` | Claim with single value resolves as scalar of the appropriate type | 11.17 | Cargo |
| 251 | `integer_literal_sign_byte_determines_signedness` | Int literal: sign byte (0x02) alone determines negative; magnitude is unsigned | 11.17 | Cargo |

### 11.13 Mandatory Integrity Control (MIC)

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 252 | `mic_no_write_up_default` | Default MIC: no-write-up blocks write-mapped bits for non-dominant callers | 11.13 | Cargo |
| 253 | `mic_dominant_caller_bypasses` | Caller at or above object's integrity level: MIC imposes no restrictions | 11.13 | Cargo |
| 254 | `mic_non_dominant_blocks_writes` | Non-dominant caller (integrity below object): write bits blocked regardless of DACL | 11.13 | Cargo |
| 255 | `mic_no_read_up_flag` | SYSTEM_MANDATORY_LABEL_NO_READ_UP: read bits blocked for non-dominant callers | 11.13 | Cargo |
| 256 | `mic_no_execute_up_flag` | SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP: execute bits blocked for non-dominant callers | 11.13 | Cargo |
| 257 | `mic_all_three_flags` | All three MIC flags set: non-dominant caller gets no read, write, or execute access | 11.13 | Cargo |
| 258 | `mic_default_label_medium` | Object without mandatory label ACE: default is Medium integrity with NO_WRITE_UP | 11.13 | Cargo |
| 259 | `mic_default_protects_from_low` | Default Medium label: Low-integrity process cannot write to unlabeled objects | 11.13 | Cargo |
| 260 | `mic_default_protects_from_untrusted` | Default Medium label: Untrusted process cannot write to unlabeled objects | 11.13 | Cargo |
| 261 | `mic_does_not_constrain_privileges` | MIC does not revoke privilege-granted bits (privileges resolved before MIC) | 11.13 | Cargo |
| 262 | `mic_token_mandatory_policy_flag` | MIC enforced only when TOKEN_MANDATORY_POLICY_NO_WRITE_UP flag is set | 11.13 | Cargo |
| 263 | `mic_policy_cleared_disables_mic` | TOKEN_MANDATORY_POLICY_NO_WRITE_UP cleared: MIC not enforced (token can write up) | 11.13 | Cargo |
| 264 | `mic_policy_bitmask_check` | Mandatory policy checked as bitmask (& NO_WRITE_UP), not equality | 11.13 | Cargo |
| 265 | `mic_policy_immutable` | Mandatory policy is set at token creation, cannot be modified at runtime (Peios divergence) | 11.13 | Provium |
| 266 | `mic_only_first_label_matters` | Multiple mandatory label ACEs: only the first one is used | 11.13 | Cargo |
| 267 | `mic_inherit_only_label_skipped` | Mandatory label ACE with INHERIT_ONLY is skipped (not used for MIC evaluation) | 11.13, 11.17 | Cargo |
| 268 | `mic_non_dominant_allowed_starts_read_execute` | Non-dominant MIC: allowed starts with R+E, then stripped by flags | 11.17 | Cargo |
| 269 | `mic_serelabel_allows_write_owner_through` | SeRelabelPrivilege allows WRITE_OWNER in MIC allowed set even for non-dominant callers | 11.13 | Cargo |
| 270 | `mic_decided_bits_tracked_in_mandatory_decided` | MIC-decided bits are tracked in mandatory_decided for SeTakeOwnershipPrivilege gating | 11.17 | Cargo |
| 271 | `mic_integrity_levels_total_order` | System > High > Medium > Low > Untrusted is a strict total order | 11.13 | Cargo |
| 272 | `mic_equal_level_dominates` | Caller at same integrity level as object dominates (>= comparison) | 11.13 | Cargo |

### 11.14 Application Confinement

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 273 | `confinement_starts_from_nothing` | Confined token: default is deny; only confinement SID / capability SID ACEs grant access | 11.14 | Cargo |
| 274 | `confinement_intersection_with_normal` | Confinement result is intersection with normal evaluation (AND) | 11.14 | Cargo |
| 275 | `confinement_no_privilege_bypass` | Privileges do NOT bypass confinement (absolute boundary) | 11.14 | Cargo |
| 276 | `confinement_no_owner_implicit_rights` | Owner implicit rights skipped in confinement evaluation (skip_owner_implicit=true) | 11.14 | Cargo |
| 277 | `confinement_backup_privilege_blocked` | SeBackupPrivilege does NOT grant access through confinement boundary | 11.14 | Cargo |
| 278 | `confinement_take_ownership_blocked` | SeTakeOwnershipPrivilege does NOT grant WRITE_OWNER through confinement | 11.14 | Cargo |
| 279 | `confinement_security_privilege_blocked` | SeSecurityPrivilege / ACCESS_SYSTEM_SECURITY unreachable for confined tokens | 11.14 | Cargo |
| 280 | `confinement_exempt_skips_check` | confinement_exempt=true: confinement restrictions not evaluated | 11.14 | Cargo |
| 281 | `confinement_null_sid_means_not_confined` | confinement_sid=null: token is not confined, confinement not evaluated | 11.14 | Cargo |
| 282 | `confinement_matches_package_sid` | Confinement pass matches the token's confinement_sid against ACEs | 11.14 | Cargo |
| 283 | `confinement_matches_capability_sids` | Confinement pass matches confinement_capabilities against ACEs | 11.14 | Cargo |
| 284 | `confinement_matches_all_app_packages` | ALL_APPLICATION_PACKAGES SID in capabilities: normal confined token matches broad ACEs | 11.14 | Cargo |
| 285 | `strict_confinement_no_all_app_packages` | Strict confinement: token without ALL_APPLICATION_PACKAGES has much narrower access surface | 11.14 | Cargo |
| 286 | `confinement_null_dacl_grants_access` | Confined token with NULL DACL on object: confinement pass grants all valid bits (object opted in) | 11.14 | Cargo |
| 287 | `confinement_principal_self_isolated` | Confinement pass: S-1-5-10 injected only if self_sid matches a confinement SID, not user identity | 11.14 | Cargo |
| 288 | `confinement_conditional_sees_full_token` | Confinement pass: conditional expressions inside matched ACEs see user's real groups/claims | 11.14 | Cargo |
| 289 | `confinement_after_restricted_merge` | Confinement runs AFTER restricted token merge and privilege OR-back (step 8a after step 8) | 11.14, 11.17 | Cargo |
| 290 | `confinement_ordering_prevents_privilege_resurrection` | Ordering: privilege OR-back in step 8 cannot resurrect bits blocked by confinement in step 8a | 11.17 | Cargo |
| 291 | `confinement_tree_fresh_copy` | Confinement pass uses fresh tree copy (decided=0, granted=0 per node) | 11.17 | Cargo |
| 292 | `confinement_tree_intersection` | Confinement tree merge: per-node intersection with normal tree | 11.17 | Cargo |
| 293 | `confinement_virtual_groups_owner_in_sids` | Confinement pass injects S-1-3-4 if owner SID is in confinement SID list | 11.17 | Cargo |
| 294 | `confinement_virtual_groups_self_in_sids` | Confinement pass injects S-1-5-10 if self_sid is in confinement SID list | 11.17 | Cargo |

### 11.15 Process Integrity Protection (PIP)

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 295 | `pip_dominant_caller_unrestricted` | Caller dominates trust label: PIP imposes no restrictions | 11.15 | Cargo |
| 296 | `pip_non_dominant_restricted_to_ace_mask` | Non-dominant caller: only rights in trust label ACE mask are permitted | 11.15 | Cargo |
| 297 | `pip_dominance_requires_both_dimensions` | Dominance requires pip_type >= ace_type AND pip_trust >= ace_trust | 11.15 | Cargo |
| 298 | `pip_partial_order_incomparable` | Isolated trust-2 vs Protected trust-5: neither dominates (incomparable) | 11.15 | Cargo |
| 299 | `pip_higher_type_lower_trust_not_dominant` | Higher pip_type but lower pip_trust: does not dominate | 11.15 | Cargo |
| 300 | `pip_higher_trust_lower_type_not_dominant` | Higher pip_trust but lower pip_type: does not dominate | 11.15 | Cargo |
| 301 | `pip_equal_type_and_trust_dominates` | Equal pip_type and pip_trust: dominates (>= on both) | 11.15 | Cargo |
| 302 | `pip_revokes_privilege_granted_bits` | PIP revokes privilege-granted bits outside the allowed set (clears from granted AND privilege_granted) | 11.15 | Cargo |
| 303 | `pip_revokes_backup_privilege` | PIP strips SeBackupPrivilege-granted read access for non-dominant callers | 11.15 | Cargo |
| 304 | `pip_revokes_security_privilege` | PIP strips SeSecurityPrivilege-granted ACCESS_SYSTEM_SECURITY for non-dominant callers | 11.15 | Cargo |
| 305 | `pip_revokes_take_ownership_privilege` | PIP strips SeTakeOwnershipPrivilege-granted WRITE_OWNER for non-dominant callers | 11.15 | Cargo |
| 306 | `pip_no_default_label` | Objects without trust label ACE: PIP imposes no restrictions (any process can access) | 11.15 | Cargo |
| 307 | `pip_no_relabel_equivalent` | No privilege can compensate for insufficient PIP trust (no carve-out) | 11.15 | Cargo |
| 308 | `pip_only_first_trust_label` | Multiple trust label ACEs: only the first is used | 11.15 | Cargo |
| 309 | `pip_inherit_only_trust_label_skipped` | Trust label ACE with INHERIT_ONLY is skipped | 11.15, 11.17 | Cargo |
| 310 | `pip_mask_zero_total_lockout` | Trust label ACE mask of 0: non-dominant callers get no access at all | 11.15 | Cargo |
| 311 | `pip_ace_mask_generic_mapped` | Trust label ACE mask is mapped through MapGenericBits for concrete allowed set | 11.17 | Cargo |
| 312 | `pip_all_bits_include_ass` | PIP all_bits includes ACCESS_SYSTEM_SECURITY (to prevent SACL access for non-dominant callers) | 11.17 | Cargo |
| 313 | `pip_decided_tracked_in_mandatory_decided` | PIP-decided bits tracked in mandatory_decided | 11.17 | Cargo |
| 314 | `pip_from_psb_not_token` | PIP evaluation uses pip_type/pip_trust from PSB, not from the token (impersonation-independent) | 11.15 | Provium |
| 315 | `pip_type_total_order` | pip_type: Isolated(1024) > Protected(512) > None(0) | 11.15 | Cargo |
| 316 | `pip_trust_total_order` | pip_trust values form total order: PeiosTcb(8192) > Peios(4096) > App(2048) > AntiMalware(1536) > Authenticode(1024) > None(0) | 11.15 | Cargo |

### 11.16 Central Access Policy (CAP)

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 317 | `cap_intersects_with_normal_result` | CAP result is AND (intersection) with normal DACL evaluation | 11.16 | Cargo |
| 318 | `cap_can_only_restrict_never_expand` | CAP can only further restrict access, never expand beyond DACL result | 11.16 | Cargo |
| 319 | `cap_multiple_policies_compose_safely` | Multiple scoped policy ACEs: each further restricts (AND of all) | 11.16 | Cargo |
| 320 | `cap_missing_policy_uses_recovery` | Unknown policy SID (not in kernel cache): recovery policy used | 11.16 | Cargo |
| 321 | `cap_recovery_grants_owner_admin_system` | Recovery policy grants GENERIC_ALL to owner (S-1-3-4), Administrators (S-1-5-32-544), SYSTEM (S-1-5-18) | 11.16 | Cargo |
| 322 | `cap_recovery_no_worse_than_no_cap` | Recovery policy with DACL intersection: effective access no worse than having no CAP | 11.16 | Cargo |
| 323 | `cap_error_in_rule_fail_closed` | CAP rule evaluation error: denies all access except privilege-granted rights | 11.16 | Cargo |
| 324 | `cap_error_preserves_privilege_escape` | CAP rule error: SeSecurityPrivilege-granted bits preserved (admin can fix broken policy) | 11.16 | Cargo |
| 325 | `cap_applies_to_condition` | CAP rule applies_to condition gates which rules fire (TRUE = applies, else skip) | 11.16 | Cargo |
| 326 | `cap_applies_to_deny_polarity` | CAP applies_to condition uses deny polarity (deny-only groups/claims visible) | 11.16, 11.17 | Cargo |
| 327 | `cap_rule_full_pipeline` | Each CAP rule evaluated with full EvaluateSecurityDescriptor pipeline | 11.16, 11.17 | Cargo |
| 328 | `cap_no_backup_restore_intent` | CAP rule evaluation passes privilege_intent=0 (no backup/restore) | 11.16, 11.17 | Cargo |
| 329 | `cap_staging_effective_and_staged` | CAP rules can have both effective_dacl and staged_dacl | 11.16 | Cargo |
| 330 | `cap_staging_difference_logged` | If effective and staged results differ, the difference is logged | 11.16 | Cargo |
| 331 | `cap_staging_no_access_impact` | Staged DACL is shadow-evaluated only; does not affect actual access decision | 11.16 | Cargo |
| 332 | `cap_rules_without_staged_contribute_to_both` | Rules without staged DACL: effective result used for both effective and staged running totals | 11.16 | Cargo |
| 333 | `cap_staged_error_fallback_to_effective` | If staged evaluation fails, fallback to effective result for staged total | 11.17 | Cargo |
| 334 | `cap_enriched_token_for_applies_to` | CAP applies_to expressions see enriched token (virtual groups S-1-3-4, S-1-5-10) | 11.17 | Cargo |
| 335 | `cap_scoped_policy_ace_inherit_only_skipped` | SYSTEM_SCOPED_POLICY_ID_ACE with INHERIT_ONLY is skipped | 11.17 | Cargo |
| 336 | `cap_non_intent_privileges_survive_and` | SeSecurityPrivilege/SeTakeOwnershipPrivilege survive CAP AND (present in both normal and CAP eval) | 11.17 | Cargo |
| 337 | `cap_intent_privileges_stripped` | Backup/restore privileges stripped in CAP rule evaluation (privilege_intent=0) | 11.17 | Cargo |
| 338 | `cap_staging_diff_property_level` | CAP staging differences detected at per-property (tree node) level | 11.17 | Cargo |

### Pipeline / EvaluateSecurityDescriptor Integration

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 339 | `impersonation_identification_denied` | Impersonation token at Identification level: AccessCheck returns ERROR_ACCESS_DENIED | 11.17 | Cargo |
| 340 | `anonymous_token_proceeds_through_pipeline` | Anonymous token (S-1-5-7) is NOT blocked; proceeds through full pipeline | 11.17 | Cargo |
| 341 | `null_sd_rejected` | Null SecurityDescriptor: returns ERROR_INVALID_PARAMETER | 11.17 | Cargo |
| 342 | `sd_without_owner_rejected` | SD with null owner: returns ERROR_INVALID_SECURITY_DESCR | 11.17 | Cargo |
| 343 | `sd_without_group_rejected` | SD with null group: returns ERROR_INVALID_SECURITY_DESCR | 11.17 | Cargo |
| 344 | `pipeline_order_privilege_before_mic` | Privilege grants (step 3) happen before MIC enforcement (step 4) | 11.17 | Cargo |
| 345 | `pipeline_order_mic_before_dacl` | MIC enforcement (step 4) happens before DACL walk (step 7) | 11.17 | Cargo |
| 346 | `pipeline_order_pip_before_dacl` | PIP enforcement (step 4) happens before DACL walk (step 7) | 11.17 | Cargo |
| 347 | `pipeline_order_owner_implicit_before_walk` | Owner implicit rights evaluated before DACL ACE walk | 11.17 | Cargo |
| 348 | `pipeline_order_restricted_after_normal_dacl` | Restricted token pass (step 8) after normal DACL evaluation (step 7) | 11.17 | Cargo |
| 349 | `pipeline_order_confinement_after_restricted` | Confinement (step 8a) after restricted merge and privilege OR-back (step 8) | 11.17 | Cargo |
| 350 | `pipeline_order_cap_after_confinement` | CAP evaluation (step 9) after confinement (step 8a) | 11.17 | Cargo |
| 351 | `virtual_group_injection_before_dacl` | EnrichToken (step 5) injects S-1-3-4/S-1-5-10 before DACL walk | 11.17 | Cargo |
| 352 | `enrich_token_idempotent` | EnrichToken is idempotent: calling twice does not double-inject virtual groups | 11.17 | Cargo |
| 353 | `enrich_token_owner_check_uses_allow_polarity` | EnrichToken: caller_is_owner uses SidMatchesToken with for_allow=true | 11.17 | Cargo |
| 354 | `write_owner_not_decided_in_step_3` | WRITE_OWNER is NOT decided in step 3 (deferred to step 7a for DACL-first evaluation) | 11.17 | Cargo |

### Helper Functions

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 355 | `sid_matches_token_user_sid` | SidMatchesToken: matches user SID (respects deny_only for allow) | 11.17 | Cargo |
| 356 | `sid_matches_token_enabled_group` | SidMatchesToken: matches enabled group | 11.17 | Cargo |
| 357 | `sid_matches_token_deny_only_group_allow` | SidMatchesToken: deny-only group does NOT match for for_allow=true | 11.17 | Cargo |
| 358 | `sid_matches_token_deny_only_group_deny` | SidMatchesToken: deny-only group DOES match for for_allow=false | 11.17 | Cargo |
| 359 | `sid_matches_token_disabled_group_skipped` | SidMatchesToken: group with neither enabled nor deny_only is skipped | 11.17 | Cargo |
| 360 | `find_node_returns_matching_guid` | FindNode returns node matching GUID, or null if not found | 11.17 | Cargo |
| 361 | `descendants_returns_subsequent_deeper_nodes` | Descendants returns all subsequent nodes at deeper levels until a same-or-higher level is found | 11.17 | Cargo |
| 362 | `siblings_returns_same_level_under_parent` | Siblings returns all nodes at same level under the same parent | 11.17 | Cargo |
| 363 | `siblings_of_root_is_empty` | Siblings of a level-0 node returns empty list | 11.17 | Cargo |
| 364 | `ancestors_returns_parents_up_to_root` | Ancestors returns parent chain from immediate parent to root | 11.17 | Cargo |

### Provium-Only Tests (require booted KACS kernel)

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 365 | `syscall_access_check_basic` | kacs_access_check syscall returns granted mask to userspace | 11.17 | Provium |
| 366 | `file_open_triggers_access_check` | Opening a file triggers AccessCheck through FACS LSM hook | 11.17 | Provium |
| 367 | `registry_read_triggers_access_check` | Reading a registry key triggers AccessCheck through registryd | 11.17 | Provium |
| 368 | `impersonation_level_enforced_on_open` | File open with Identification-level impersonation token: access denied | 11.17, 12.1 | Provium |
| 369 | `mic_policy_immutable_at_runtime` | TOKEN_MANDATORY_POLICY cannot be modified after token creation | 11.13 | Provium |
| 370 | `pip_from_psb_not_token_at_runtime` | PIP evaluation reads pip_type/pip_trust from PSB, not impersonation token | 11.15 | Provium |
| 371 | `file_backup_intent_flag` | FACS passes BACKUP_INTENT for backup-context file opens | 11.6 | Provium |
| 372 | `file_restore_intent_flag` | FACS passes RESTORE_INTENT for restore-context file opens | 11.6 | Provium |
| 373 | `null_dacl_file_access` | File with no DACL (SE_DACL_PRESENT clear): grants all valid file rights | 11.3 | Provium |
| 374 | `empty_dacl_file_access` | File with empty DACL: grants only owner implicit rights (READ_CONTROL+WRITE_DAC) | 11.3, 11.4 | Provium |
| 375 | `continuous_audit_per_operation` | SYSTEM_ALARM ACE: continuous audit mask recorded on file handle, events emitted per-operation | 11.10 | Provium |
| 376 | `privilege_use_audit_emitted` | Privilege-use audit event emitted when SeBackupPrivilege exercised for final result | 11.10 | Provium |
| 377 | `pip_blocks_admin_with_privileges` | Admin process with SeBackupPrivilege+SeSecurityPrivilege cannot access PIP-protected file (non-dominant) | 11.15 | Provium |
| 378 | `confinement_blocks_privileged_access` | Confined process with SeBackupPrivilege: still blocked from non-ACEd objects | 11.14 | Provium |
| 379 | `cap_policy_loaded_at_boot` | Central access policies loaded from registry into kernel cache at boot | 11.16 | Provium |
| 380 | `cap_policy_restricts_file_access` | File with scoped policy ACE: CAP rule restricts beyond DACL grant | 11.16 | Provium |
| 381 | `cap_recovery_on_missing_policy` | Scoped policy ACE referencing unknown SID: recovery policy applied at runtime | 11.16 | Provium |
| 382 | `access_check_synchronous_in_thread` | AccessCheck runs synchronously in requesting thread's context (hard invariant) | 11.17 | Provium |
| 383 | `signal_delivery_access_check` | Signal delivery to a process passes through AccessCheck | 11.17 | Provium |
| 384 | `ipc_connection_access_check` | IPC endpoint connection passes through AccessCheck | 11.17 | Provium |

---

## Summary

**Total tests: 384**

- **Cargo tests (pure Rust logic, no kernel): 364**
- **Provium tests (require booted KACS kernel): 20**

Coverage by pipeline stage:
- API variants (11.1): 7
- Generic mapping (11.2): 11
- DACL walk core (11.3): 20
- Owner implicit rights (11.4): 14
- MAXIMUM_ALLOWED (11.5): 11
- Privileges (11.6): 31
- Restricted tokens (11.7): 17
- Object ACEs / trees (11.8): 22
- Auditing (11.10): 18
- Resource attributes (11.11): 5
- Conditional ACEs (11.12): 80
- MIC (11.13): 21
- Confinement (11.14): 22
- PIP (11.15): 22
- CAP (11.16): 22
- Pipeline integration / helpers (11.17): 41
- Provium-only: 20

The overwhelming majority are Cargo tests because the AccessCheck pipeline is pure evaluation logic operating on data structures (tokens, SDs, masks) -- exactly what can be tested in userspace with a kacs-core crate. Provium tests cover the kernel integration surface: syscall entry points, LSM hooks, FACS/registryd callers passing intent flags, runtime immutability invariants, and the CAP policy cache lifecycle.


---

# Section 11: AccessCheck (Second Half)

## 1. Restricted Token Two-Pass (ss11.7, lines 6247-6310)

### Scalar Merge

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 1 | `restricted_normal_intersection` | When a token has restricted SIDs and is NOT write-restricted, granted = normal_granted AND restricted_granted (bitwise intersection) | ss11.7 line 6292 | Cargo |
| 2 | `restricted_write_only_intersection` | When a token is write-restricted, only write-mapped bits are intersected; non-write bits pass from the normal pass unmodified | ss11.7 lines 6287-6290 | Cargo |
| 3 | `restricted_write_bits_from_generic_mapping` | Write bits for write-restricted merge are computed via MapGenericBits(GENERIC_WRITE, mapping) | ss11.7 line 6288 | Cargo |
| 4 | `restricted_write_restricted_formula` | Write-restricted merge: granted = (normal_granted AND NOT write_bits) OR (normal_granted AND restricted_granted AND write_bits) | ss11.7 lines 6289-6290 | Cargo |
| 5 | `restricted_privilege_granted_or_back` | After intersection, privilege_granted bits are OR'd back into granted (privileges bypass the restricted pass) | ss11.7 lines 6293-6294 | Cargo |
| 6 | `restricted_privilege_or_back_after_intersection` | Privilege OR-back happens after the intersection, not before -- bits denied by restricted pass are restored by privilege | ss11.7 lines 6293-6294 | Cargo |
| 7 | `restricted_no_privilege_or_back_without_privileges` | When privilege_granted is 0, OR-back adds nothing after intersection | ss11.7 line 6294 | Cargo |

### Virtual Groups in Restricted Pass

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 8 | `restricted_owner_virtual_group` | If sd.owner is in restricting_sids, SID_OWNER_RIGHTS is added to the restricted SID set | ss11.7 lines 6263-6264 | Cargo |
| 9 | `restricted_owner_not_in_restricting_sids` | If sd.owner is NOT in restricting_sids, SID_OWNER_RIGHTS is NOT added to the restricted set | ss11.7 lines 6263-6264 | Cargo |
| 10 | `restricted_principal_self_injection` | If self_sid is in restricting_sids, SID_PRINCIPAL_SELF is added to the restricted SID set | ss11.7 lines 6265-6267 | Cargo |
| 11 | `restricted_principal_self_not_in_restricting_sids` | If self_sid is NOT in restricting_sids, SID_PRINCIPAL_SELF is NOT added | ss11.7 lines 6265-6267 | Cargo |
| 12 | `restricted_principal_self_null_self_sid` | If self_sid is null, PRINCIPAL_SELF is never added to restricted set | ss11.7 lines 6265-6267 | Cargo |

### Restricted Device Groups

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 13 | `restricted_device_groups_swapped` | If token has restricted_device_groups, the restricted pass uses them instead of normal device_groups for conditional expression evaluation | ss11.7 lines 6257-6259 | Cargo |
| 14 | `restricted_device_groups_null_no_swap` | If restricted_device_groups is null, restricted pass uses normal device_groups | ss11.7 lines 6257-6259 | Cargo |

### Restricted Pass SID Matching

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 15 | `restricted_sid_match_uses_sid_list` | Restricted pass SID matching uses SidInRestrictingSids (list membership), not SidMatchesToken (group/deny-only filtering) | ss11.7 lines 6278-6279 | Cargo |
| 16 | `restricted_sid_match_ignores_for_allow` | Restricted pass SID matching ignores the for_allow parameter (both allow and deny ACEs matched the same way) | ss11.7 line 6278 | Cargo |

### Tree Merge

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 17 | `restricted_tree_fresh_copy` | Restricted pass uses a deep copy of the object tree with decided=0, granted=0 on each node | ss11.7 lines 6270-6276 | Cargo |
| 18 | `restricted_tree_normal_intersection` | Non-write-restricted: each node.granted = normal_node.granted AND restricted_node.granted | ss11.7 lines 6305-6307 | Cargo |
| 19 | `restricted_tree_write_only_intersection` | Write-restricted: each node uses the write-bit formula for intersection | ss11.7 lines 6298-6303 | Cargo |
| 20 | `restricted_tree_privilege_or_back` | After tree merge, privilege_granted is OR'd back into every node's granted | ss11.7 lines 6308-6309 | Cargo |
| 21 | `restricted_tree_null_no_tree_merge` | When object_tree is null, tree merge is skipped | ss11.7 lines 6270-6276, 6297 | Cargo |

### Owner Implicit Rights in Restricted Pass

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 22 | `restricted_owner_implicit_rights` | Restricted pass evaluates owner implicit rights independently (skip_owner_implicit=false) | ss11.7 line 6283 | Cargo |
| 23 | `restricted_owner_in_restricting_sids_gets_implicit` | If owner SID is a restricting SID, restricted pass grants READ_CONTROL and WRITE_DAC implicitly | ss11.7 narrative 4740-4747 | Cargo |
| 24 | `restricted_owner_not_in_restricting_sids_no_implicit` | If owner SID is NOT a restricting SID, restricted pass does not grant implicit rights, reducing effective owner access via intersection | ss11.7 narrative 4745-4747 | Cargo |

---

## 2. Confinement (ss11.14, lines 6311-6352)

### Core Behavior

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 25 | `confinement_absolute_intersection` | Confinement intersects with NO privilege bypass: granted = granted AND c_granted | ss11.14 lines 6346-6347 | Cargo |
| 26 | `confinement_no_privilege_bypass` | Privilege-granted bits are NOT OR'd back after confinement intersection (unlike restricted tokens) | ss11.14 lines 6346-6347, narrative 5473 | Cargo |
| 27 | `confinement_runs_after_restricted_merge` | Confinement runs AFTER restricted merge and its privilege OR-back (ordering critical) | ss11.14 lines 6311-6316 | Cargo |
| 28 | `confinement_ordering_prevents_privilege_resurrection` | If confinement ran before restricted, the privilege OR-back in step 8 would resurrect bits that confinement blocked | ss11.14 lines 6314-6316 | Cargo |
| 29 | `confinement_skip_owner_implicit` | Confinement evaluation calls EvaluateDACL with skip_owner_implicit=true (owner does not get implicit rights in confinement pass) | ss11.14 line 6343 | Cargo |
| 30 | `confinement_not_active_when_null` | When confinement_sid is null, confinement is not evaluated | ss11.14 line 6317 | Cargo |
| 31 | `confinement_exempt_skips_evaluation` | When confinement_exempt is true, confinement is not evaluated even if confinement_sid is set | ss11.14 line 6317 | Cargo |

### Confinement SID Set

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 32 | `confinement_sid_set_package_plus_capabilities` | Confinement SID set = [confinement_sid] + confinement_capabilities | ss11.14 lines 6321-6322 | Cargo |
| 33 | `confinement_owner_rights_injection` | If sd.owner is in confinement_sids list, SID_OWNER_RIGHTS is added to confinement set | ss11.14 lines 6323-6324 | Cargo |
| 34 | `confinement_principal_self_injection` | If self_sid is in confinement_sids list, SID_PRINCIPAL_SELF is added to confinement set | ss11.14 lines 6325-6327 | Cargo |
| 35 | `confinement_principal_self_null_no_injection` | If self_sid is null, PRINCIPAL_SELF is not added to confinement set | ss11.14 lines 6325-6327 | Cargo |
| 36 | `confinement_sid_match_uses_sid_in_list` | Confinement SID matching uses SidInList (simple list membership), not SidMatchesToken | ss11.14 lines 6329-6330 | Cargo |

### Confinement Tree Handling

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 37 | `confinement_tree_deep_copy` | Confinement pass uses a deep copy of the object tree with decided=0, granted=0 | ss11.14 lines 6332-6338 | Cargo |
| 38 | `confinement_tree_intersection` | Each node: object_tree[i].granted = normal_tree[i].granted AND c_tree[i].granted | ss11.14 lines 6349-6351 | Cargo |
| 39 | `confinement_tree_null_no_tree` | When object_tree is null, tree intersection is skipped | ss11.14 lines 6332-6338, 6348 | Cargo |

### Known Consequences (narrative)

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 40 | `confinement_sacl_access_unreachable` | ACCESS_SYSTEM_SECURITY is unreachable for confined tokens (privilege-only, privileges don't bypass confinement) | ss11.14 narrative 5519-5521 | Cargo |
| 41 | `confinement_null_dacl_grants_access` | Object with NULL DACL grants access even in confinement pass (follows standard evaluation) | ss11.14 narrative 5529-5535 | Cargo |
| 42 | `confinement_principal_self_isolated_from_user` | PRINCIPAL_SELF is only injected if self_sid matches a confinement SID; user SID match alone does not trigger it | ss11.14 narrative 5537-5543 | Cargo |
| 43 | `confinement_conditional_sees_full_token` | Conditional expressions in confinement pass evaluate against the user's full token (groups, claims, device_claims) | ss11.14 narrative 5545-5553 | Cargo |
| 44 | `confinement_all_app_packages_sid_match` | ACE with ALL_APPLICATION_PACKAGES SID matches when that SID is in confinement_capabilities | ss11.14 narrative 5431-5432 | Cargo |
| 45 | `confinement_strict_no_all_app_packages` | Strictly confined token (no ALL_APPLICATION_PACKAGES in capabilities) does not match ALL_APPLICATION_PACKAGES ACEs | ss11.14 narrative 5491-5497 | Cargo |

---

## 3. SeTakeOwnershipPrivilege Post-DACL (ss11.6/11.17, lines 6224-6246)

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 46 | `take_ownership_grants_write_owner_when_dacl_denies` | SeTakeOwnershipPrivilege grants WRITE_OWNER even when DACL denied it (deny-proof) | ss11.6 lines 6233-6240 | Cargo |
| 47 | `take_ownership_noop_when_dacl_grants` | SeTakeOwnershipPrivilege does not fire when DACL already granted WRITE_OWNER | ss11.6 lines 6235-6236 | Cargo |
| 48 | `take_ownership_respects_mandatory_mic` | SeTakeOwnershipPrivilege does NOT override MIC-decided WRITE_OWNER (checks mandatory_decided) | ss11.6 lines 6235-6236 | Cargo |
| 49 | `take_ownership_respects_mandatory_pip` | SeTakeOwnershipPrivilege does NOT override PIP-decided WRITE_OWNER (checks mandatory_decided) | ss11.6 lines 6235-6236 | Cargo |
| 50 | `take_ownership_sets_privilege_granted` | When fired, SeTakeOwnershipPrivilege sets privilege_granted and take_ownership_granted | ss11.6 lines 6238-6240 | Cargo |
| 51 | `take_ownership_updates_tree_nodes` | When object_tree is present, SeTakeOwnershipPrivilege grants WRITE_OWNER on each node that doesn't already have it | ss11.6 lines 6241-6245 | Cargo |
| 52 | `take_ownership_only_on_desired_or_max_allowed` | SeTakeOwnershipPrivilege only fires when desired includes WRITE_OWNER or in MAXIMUM_ALLOWED mode | ss11.6 line 6233 | Cargo |
| 53 | `take_ownership_without_privilege_noop` | Without SeTakeOwnershipPrivilege enabled, step 7a does nothing | ss11.6 line 6234 | Cargo |

---

## 4. Central Access Policy (ss11.16, lines 6396-6524)

### CAP AND Semantics

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 54 | `cap_intersects_with_normal_result` | CAP result is AND'd with normal DACL result (cap can only further restrict) | ss11.16 lines 6455, 6520 | Cargo |
| 55 | `cap_multiple_policies_compound_and` | Multiple scoped policy SIDs compound via AND (each further restricts) | ss11.16 lines 6410-6496 | Cargo |
| 56 | `cap_never_expands_access` | Even if CAP rule DACL is broader than object DACL, granted cannot exceed object DACL result | ss11.16 narrative 5856-5860 | Cargo |

### Recovery Policy

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 57 | `cap_unknown_policy_uses_recovery` | When policy SID lookup returns null, RECOVERY_POLICY is used | ss11.16 line 6413 | Cargo |
| 58 | `cap_recovery_policy_grants_admin` | RECOVERY_POLICY grants GENERIC_ALL to BUILTIN_ADMINISTRATORS (S-1-5-32-544) | ss11.16 lines 7728-7731 | Cargo |
| 59 | `cap_recovery_policy_grants_system` | RECOVERY_POLICY grants GENERIC_ALL to LOCAL_SYSTEM (S-1-5-18) | ss11.16 lines 7728-7731 | Cargo |
| 60 | `cap_recovery_policy_grants_owner` | RECOVERY_POLICY grants GENERIC_ALL to OWNER_RIGHTS (S-1-3-4) | ss11.16 lines 7728-7731 | Cargo |
| 61 | `cap_recovery_generic_all_mapped` | RECOVERY_POLICY uses GENERIC_ALL in ACE masks, mapped via MapGenericBits for each object type | ss11.16 lines 7732-7734 | Cargo |

### Applies-To Evaluation

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 62 | `cap_applies_to_null_matches_all` | Rule with null applies_to condition matches all objects | ss11.16 lines 6420-6421 | Cargo |
| 63 | `cap_applies_to_true_matches` | Rule with applies_to that evaluates to TRUE is applied | ss11.16 lines 6421-6425 | Cargo |
| 64 | `cap_applies_to_false_skips` | Rule with applies_to that evaluates to FALSE is skipped | ss11.16 lines 6425-6426 | Cargo |
| 65 | `cap_applies_to_unknown_skips` | Rule with applies_to that evaluates to UNKNOWN is skipped (only TRUE matches) | ss11.16 lines 6425-6426 | Cargo |
| 66 | `cap_applies_to_uses_deny_polarity` | applies_to evaluation uses for_allow=false (deny polarity so deny-only groups/claims are visible) | ss11.16 lines 6417-6419, 6424 | Cargo |
| 67 | `cap_applies_to_uses_enriched_token` | applies_to evaluation uses enriched token (with virtual groups S-1-3-4, S-1-5-10) | ss11.16 lines 6399-6400 | Cargo |

### CAP Rule Evaluation

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 68 | `cap_rule_uses_full_pipeline` | Each CAP rule runs through the full EvaluateSecurityDescriptor pipeline | ss11.16 lines 6440-6443 | Cargo |
| 69 | `cap_rule_no_privilege_intent` | CAP rule evaluation passes privilege_intent=0 (no backup/restore intent) | ss11.16 line 6443 | Cargo |
| 70 | `cap_rule_replaces_dacl` | CAP rule evaluation uses rule's effective_dacl replacing the SD's DACL | ss11.16 lines 6429-6431 | Cargo |
| 71 | `cap_non_intent_privileges_survive_and` | SeSecurityPrivilege and SeTakeOwnershipPrivilege survive the AND (same token, same privileges in both evaluations) | ss11.16 lines 6513-6519 | Cargo |
| 72 | `cap_intent_privileges_stripped` | Backup/restore privileges are stripped in CAP rule evaluation (privilege_intent=0) | ss11.16 lines 6516-6519 | Cargo |

### Error Handling

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 73 | `cap_rule_error_fail_closed` | On CAP rule evaluation error, cap_effective is AND'd with privilege_granted only (fail-closed) | ss11.16 lines 6444-6452 | Cargo |
| 74 | `cap_rule_error_preserves_privilege_escape` | On error, privilege-granted rights are preserved as an escape hatch | ss11.16 lines 6446-6447, narrative 5920-5930 | Cargo |

### Staging

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 75 | `cap_staged_dacl_evaluated_parallel` | When staged_dacl is present, it is evaluated in parallel with effective_dacl | ss11.16 lines 6461-6496 | Cargo |
| 76 | `cap_staged_no_affect_on_granted` | Staged DACL result does not affect the actual granted mask (only effective does) | ss11.16 line 6520 | Cargo |
| 77 | `cap_staging_difference_logged` | When effective and staged results differ, LogStagingDifference is called | ss11.16 lines 6502-6510 | Cargo |
| 78 | `cap_staging_no_difference_not_logged` | When effective and staged results are identical, no logging occurs | ss11.16 lines 6502-6510 | Cargo |
| 79 | `cap_staged_null_uses_effective` | When staged_dacl is null, effective result is used for staged total | ss11.16 lines 6491-6496 | Cargo |
| 80 | `cap_staged_error_falls_back_to_effective` | When staged evaluation errors, cap_staged uses effective result | ss11.16 lines 6476-6483 | Cargo |
| 81 | `cap_staging_tree_level_difference` | Staging difference detection checks per-property tree nodes, not just scalar | ss11.16 lines 6503-6507 | Cargo |

---

## 5. Conditional ACE Evaluation (ss11.12, lines 7219-7513)

### Expression Header and Envelope

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 82 | `cond_expression_too_short_returns_unknown` | Expression shorter than 4 bytes returns UNKNOWN | ss11.12 lines 7234-7236 | Cargo |
| 83 | `cond_expression_bad_magic_returns_unknown` | Expression not starting with [0x61, 0x72, 0x74, 0x78] ("artx") returns UNKNOWN | ss11.12 lines 7235-7236 | Cargo |
| 84 | `cond_expression_valid_magic_proceeds` | Expression starting with "artx" magic proceeds to evaluation | ss11.12 lines 7234-7236 | Cargo |
| 85 | `cond_empty_stack_after_eval_unknown` | If stack has != 1 element after evaluation, return UNKNOWN | ss11.12 lines 7508-7509 | Cargo |
| 86 | `cond_literal_on_stack_final_unknown` | If final stack element has origin LITERAL, return UNKNOWN | ss11.12 lines 7510-7511 | Cargo |
| 87 | `cond_unknown_opcode_returns_unknown` | Unknown opcode returns UNKNOWN immediately | ss11.12 lines 7505-7506 | Cargo |

### Literal Values

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 88 | `cond_int8_literal` | Opcode 0x01: reads 8-byte LE QWORD + sign byte + base byte, pushes INT64 | ss11.12 lines 7256-7267 | Cargo |
| 89 | `cond_int16_literal` | Opcode 0x02: same encoding as Int8 | ss11.12 lines 7256-7267 | Cargo |
| 90 | `cond_int32_literal` | Opcode 0x03: same encoding | ss11.12 lines 7256-7267 | Cargo |
| 91 | `cond_int64_literal` | Opcode 0x04: same encoding | ss11.12 lines 7256-7267 | Cargo |
| 92 | `cond_negative_sign_byte` | Sign byte 0x02 produces negative value: -(magnitude as INT64) | ss11.12 lines 7263-7264 | Cargo |
| 93 | `cond_positive_sign_byte` | Sign byte != 0x02 produces positive value (unsigned magnitude) | ss11.12 lines 7265-7266 | Cargo |
| 94 | `cond_unicode_string_literal` | Opcode 0x10: reads uint32 LE length, then UTF-16LE string | ss11.12 lines 7269-7273 | Cargo |
| 95 | `cond_octet_string_literal` | Opcode 0x18: reads uint32 LE length, then raw bytes | ss11.12 lines 7275-7278 | Cargo |
| 96 | `cond_composite_literal` | Opcode 0x50: reads uint32 LE length, then parsed composite elements | ss11.12 lines 7280-7284 | Cargo |
| 97 | `cond_sid_literal` | Opcode 0x51: reads uint32 LE length, then parses SID | ss11.12 lines 7286-7289 | Cargo |
| 98 | `cond_literal_origin_set` | All literal values have origin=LITERAL | ss11.12 lines 7267, 7273, 7278, 7284, 7289 | Cargo |

### Attribute References

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 99 | `cond_local_attr_reference` | Opcode 0xf8: resolves @Local. attribute from local_claims with LOCAL_ATTR origin | ss11.12 lines 7293-7297 | Cargo |
| 100 | `cond_user_attr_reference` | Opcode 0xf9: resolves @User. attribute from token.user_claims with USER_ATTR origin | ss11.12 lines 7299-7303 | Cargo |
| 101 | `cond_resource_attr_reference` | Opcode 0xfa: resolves @Resource. attribute from resource_attributes with RESOURCE_ATTR origin | ss11.12 lines 7305-7310 | Cargo |
| 102 | `cond_device_attr_reference` | Opcode 0xfb: resolves @Device. attribute from token.device_claims with DEVICE_ATTR origin | ss11.12 lines 7312-7316 | Cargo |
| 103 | `cond_missing_attr_returns_null` | Missing attribute in any namespace returns Value(NULL) | ss11.12 resolve_claim line 7773, 7803 | Cargo |

### Relational Operators

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 104 | `cond_equal_op` | Opcode 0x80 (==): pops two, pushes compare_equal result | ss11.12 lines 7321-7324 | Cargo |
| 105 | `cond_not_equal_op` | Opcode 0x81 (!=): pops two, pushes negate_tv(compare_equal) | ss11.12 lines 7326-7329 | Cargo |
| 106 | `cond_less_than_op` | Opcode 0x82 (<): pops two, pushes compare_ordered(LT) | ss11.12 lines 7331-7334 | Cargo |
| 107 | `cond_less_equal_op` | Opcode 0x83 (<=): pops two, pushes compare_ordered(LE) | ss11.12 lines 7336-7339 | Cargo |
| 108 | `cond_greater_than_op` | Opcode 0x84 (>): pops two, pushes compare_ordered(GT) | ss11.12 lines 7341-7344 | Cargo |
| 109 | `cond_greater_equal_op` | Opcode 0x85 (>=): pops two, pushes compare_ordered(GE) | ss11.12 lines 7346-7349 | Cargo |
| 110 | `cond_relational_null_lhs_unknown` | Any relational op with NULL lhs returns UNKNOWN | ss11.12 line 7860 | Cargo |
| 111 | `cond_relational_null_rhs_unknown` | Any relational op with NULL rhs returns UNKNOWN | ss11.12 line 7860 | Cargo |
| 112 | `cond_relational_type_mismatch_unknown` | Relational op with incompatible types returns UNKNOWN | ss11.12 line 7864 | Cargo |
| 113 | `cond_relational_insufficient_stack_unknown` | Relational op with <2 stack elements returns UNKNOWN | ss11.12 line 7322 | Cargo |
| 114 | `cond_ordered_composite_unknown` | Ordered comparison (<, <=, >, >=) with composite operand returns UNKNOWN | ss11.12 line 7892 | Cargo |
| 115 | `cond_ordered_boolean_unknown` | Ordered comparison with BOOLEAN operand returns UNKNOWN | ss11.12 lines 7894-7895 | Cargo |
| 116 | `cond_int64_uint64_promotion` | INT64 vs UINT64 comparison: values are promoted (negative INT64 < any UINT64) | ss11.12 narrative 5284-5286 | Cargo |

### Set Operators

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 117 | `cond_contains_op` | Opcode 0x86 (Contains): pops two, pushes set_contains(lhs, rhs) | ss11.12 lines 7351-7354 | Cargo |
| 118 | `cond_any_of_op` | Opcode 0x88 (Any_of): pops two, pushes set_any_of(lhs, rhs) | ss11.12 lines 7356-7359 | Cargo |
| 119 | `cond_not_contains_op` | Opcode 0x8e (Not_Contains): pushes negate_tv(set_contains) | ss11.12 lines 7361-7364 | Cargo |
| 120 | `cond_not_any_of_op` | Opcode 0x8f (Not_Any_of): pushes negate_tv(set_any_of) | ss11.12 lines 7366-7369 | Cargo |
| 121 | `cond_contains_null_lhs_unknown` | Contains with NULL lhs returns UNKNOWN | ss11.12 line 7915 | Cargo |
| 122 | `cond_contains_null_rhs_unknown` | Contains with NULL rhs returns UNKNOWN | ss11.12 line 7916 | Cargo |
| 123 | `cond_contains_empty_rhs_unknown` | Contains with empty rhs set returns UNKNOWN (vacuous truth prevention) | ss11.12 lines 7919-7920 | Cargo |
| 124 | `cond_contains_all_found_true` | Contains returns TRUE when all RHS values are found in LHS | ss11.12 lines 7921-7935 | Cargo |
| 125 | `cond_contains_one_missing_false` | Contains returns FALSE when any RHS value is definitively not in LHS | ss11.12 lines 7931-7934 | Cargo |
| 126 | `cond_contains_indeterminate_unknown` | Contains returns UNKNOWN when element comparison is indeterminate and value not found | ss11.12 lines 7929-7933 | Cargo |
| 127 | `cond_any_of_null_lhs_unknown` | Any_of with NULL lhs returns UNKNOWN | ss11.12 line 7945 | Cargo |
| 128 | `cond_any_of_null_rhs_unknown` | Any_of with NULL rhs returns UNKNOWN | ss11.12 line 7946 | Cargo |
| 129 | `cond_any_of_empty_lhs_unknown` | Any_of with empty LHS returns UNKNOWN | ss11.12 line 7949 | Cargo |
| 130 | `cond_any_of_empty_rhs_unknown` | Any_of with empty RHS returns UNKNOWN | ss11.12 line 7950 | Cargo |
| 131 | `cond_any_of_one_match_true` | Any_of returns TRUE when any LHS value is found in RHS | ss11.12 lines 7952-7955 | Cargo |
| 132 | `cond_any_of_none_match_false` | Any_of returns FALSE when no LHS values match RHS and no UNKNOWN comparisons | ss11.12 line 7961 | Cargo |
| 133 | `cond_any_of_indeterminate_unknown` | Any_of returns UNKNOWN when no TRUE found but some comparison was indeterminate | ss11.12 lines 7959-7960 | Cargo |

### Existence Operators

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 134 | `cond_exists_present_true` | Opcode 0x87 (Exists): non-NULL attribute returns TRUE | ss11.12 lines 7373-7379 | Cargo |
| 135 | `cond_exists_absent_false` | Exists: NULL attribute returns FALSE | ss11.12 line 7379 | Cargo |
| 136 | `cond_exists_non_attr_origin_unknown` | Exists on non-attribute-origin value (LITERAL) returns UNKNOWN | ss11.12 lines 7376-7378 | Cargo |
| 137 | `cond_not_exists_present_false` | Opcode 0x8d (Not_Exists): non-NULL attribute returns FALSE | ss11.12 lines 7381-7387 | Cargo |
| 138 | `cond_not_exists_absent_true` | Not_Exists: NULL attribute returns TRUE | ss11.12 line 7387 | Cargo |
| 139 | `cond_not_exists_non_attr_origin_unknown` | Not_Exists on non-attribute-origin value returns UNKNOWN | ss11.12 lines 7384-7386 | Cargo |
| 140 | `cond_exists_insufficient_stack_unknown` | Exists with empty stack returns UNKNOWN | ss11.12 line 7374 | Cargo |

### Membership Operators

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 141 | `cond_member_of_all_match_true` | Opcode 0x89 (Member_of): TRUE when all SIDs in operand match token | ss11.12 lines 7392-7398 | Cargo |
| 142 | `cond_member_of_one_missing_false` | Member_of: FALSE when any SID does not match token | ss11.12 lines 7392-7398 | Cargo |
| 143 | `cond_member_of_any_one_match_true` | Opcode 0x8b (Member_of_Any): TRUE when any SID matches token | ss11.12 lines 7400-7406 | Cargo |
| 144 | `cond_member_of_any_none_match_false` | Member_of_Any: FALSE when no SIDs match token | ss11.12 lines 7400-7406 | Cargo |
| 145 | `cond_device_member_of_all_match_true` | Opcode 0x8a (Device_Member_of): TRUE when all SIDs match token device groups | ss11.12 lines 7408-7416 | Cargo |
| 146 | `cond_device_member_of_null_device_unknown` | Device_Member_of with null device_groups returns UNKNOWN | ss11.12 lines 7413-7414 | Cargo |
| 147 | `cond_device_member_of_any_one_match_true` | Opcode 0x8c (Device_Member_of_Any): TRUE when any SID matches device groups | ss11.12 lines 7418-7426 | Cargo |
| 148 | `cond_device_member_of_any_null_device_unknown` | Device_Member_of_Any with null device_groups returns UNKNOWN | ss11.12 lines 7423-7424 | Cargo |
| 149 | `cond_not_member_of_all_match_false` | Opcode 0x90 (Not_Member_of): FALSE when all SIDs match (negation of Member_of) | ss11.12 lines 7428-7434 | Cargo |
| 150 | `cond_not_member_of_one_missing_true` | Not_Member_of: TRUE when any SID does not match | ss11.12 lines 7428-7434 | Cargo |
| 151 | `cond_not_member_of_any_one_match_false` | Opcode 0x92 (Not_Member_of_Any): FALSE when any SID matches (negation of Member_of_Any) | ss11.12 lines 7436-7442 | Cargo |
| 152 | `cond_not_member_of_any_none_match_true` | Not_Member_of_Any: TRUE when no SIDs match | ss11.12 lines 7436-7442 | Cargo |
| 153 | `cond_not_device_member_of_all_match_false` | Opcode 0x91 (Not_Device_Member_of): FALSE when all SIDs match device groups | ss11.12 lines 7444-7452 | Cargo |
| 154 | `cond_not_device_member_of_null_device_unknown` | Not_Device_Member_of with null device_groups returns UNKNOWN | ss11.12 lines 7449-7450 | Cargo |
| 155 | `cond_not_device_member_of_any_one_match_false` | Opcode 0x93 (Not_Device_Member_of_Any): FALSE when any SID matches device groups | ss11.12 lines 7454-7462 | Cargo |
| 156 | `cond_not_device_member_of_any_null_device_unknown` | Not_Device_Member_of_Any with null device_groups returns UNKNOWN | ss11.12 lines 7459-7460 | Cargo |
| 157 | `cond_membership_invalid_sid_list_unknown` | Membership op with non-SID/non-composite operand returns UNKNOWN | ss11.12 line 7396 | Cargo |
| 158 | `cond_membership_empty_composite_unknown` | Membership op with empty composite returns UNKNOWN (error from to_sid_list) | ss11.12 lines 7845-7846 | Cargo |
| 159 | `cond_membership_mixed_types_unknown` | Membership op with composite containing non-SID elements returns UNKNOWN | ss11.12 lines 7848-7850 | Cargo |
| 160 | `cond_membership_polarity_allow_filters_deny_only` | Membership with for_allow=true filters out deny-only groups from matching | ss11.12 narrative 5293-5294 | Cargo |
| 161 | `cond_membership_polarity_deny_includes_deny_only` | Membership with for_allow=false includes deny-only groups in matching | ss11.12 narrative 5293-5294 | Cargo |

### Three-Value Logic (Kleene)

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 162 | `cond_and_true_true_is_true` | AND(TRUE, TRUE) = TRUE | ss11.12 lines 7476-7477 | Cargo |
| 163 | `cond_and_true_false_is_false` | AND(TRUE, FALSE) = FALSE | ss11.12 line 7474 | Cargo |
| 164 | `cond_and_true_unknown_is_unknown` | AND(TRUE, UNKNOWN) = UNKNOWN | ss11.12 lines 7478-7479 | Cargo |
| 165 | `cond_and_false_true_is_false` | AND(FALSE, TRUE) = FALSE | ss11.12 line 7474 | Cargo |
| 166 | `cond_and_false_false_is_false` | AND(FALSE, FALSE) = FALSE | ss11.12 line 7474 | Cargo |
| 167 | `cond_and_false_unknown_is_false` | AND(FALSE, UNKNOWN) = FALSE | ss11.12 line 7474 | Cargo |
| 168 | `cond_and_unknown_true_is_unknown` | AND(UNKNOWN, TRUE) = UNKNOWN | ss11.12 lines 7478-7479 | Cargo |
| 169 | `cond_and_unknown_false_is_false` | AND(UNKNOWN, FALSE) = FALSE | ss11.12 line 7474 | Cargo |
| 170 | `cond_and_unknown_unknown_is_unknown` | AND(UNKNOWN, UNKNOWN) = UNKNOWN | ss11.12 lines 7478-7479 | Cargo |
| 171 | `cond_or_true_true_is_true` | OR(TRUE, TRUE) = TRUE | ss11.12 line 7488 | Cargo |
| 172 | `cond_or_true_false_is_true` | OR(TRUE, FALSE) = TRUE | ss11.12 line 7488 | Cargo |
| 173 | `cond_or_true_unknown_is_true` | OR(TRUE, UNKNOWN) = TRUE | ss11.12 line 7488 | Cargo |
| 174 | `cond_or_false_true_is_true` | OR(FALSE, TRUE) = TRUE | ss11.12 line 7488 | Cargo |
| 175 | `cond_or_false_false_is_false` | OR(FALSE, FALSE) = FALSE | ss11.12 lines 7490-7491 | Cargo |
| 176 | `cond_or_false_unknown_is_unknown` | OR(FALSE, UNKNOWN) = UNKNOWN | ss11.12 lines 7492-7493 | Cargo |
| 177 | `cond_or_unknown_true_is_true` | OR(UNKNOWN, TRUE) = TRUE | ss11.12 line 7488 | Cargo |
| 178 | `cond_or_unknown_false_is_unknown` | OR(UNKNOWN, FALSE) = UNKNOWN | ss11.12 lines 7492-7493 | Cargo |
| 179 | `cond_or_unknown_unknown_is_unknown` | OR(UNKNOWN, UNKNOWN) = UNKNOWN | ss11.12 lines 7492-7493 | Cargo |
| 180 | `cond_not_true_is_false` | NOT(TRUE) = FALSE | ss11.12 line 7501 | Cargo |
| 181 | `cond_not_false_is_true` | NOT(FALSE) = TRUE | ss11.12 line 7502 | Cargo |
| 182 | `cond_not_unknown_is_unknown` | NOT(UNKNOWN) = UNKNOWN | ss11.12 line 7503 | Cargo |
| 183 | `cond_logical_literal_operand_unknown` | Logical operator with LITERAL-origin operand returns UNKNOWN (entire expression) | ss11.12 lines 7470-7471, 7484-7485, 7498-7499 | Cargo |
| 184 | `cond_logical_insufficient_stack_unknown` | Logical operator with insufficient stack returns UNKNOWN | ss11.12 lines 7468, 7482, 7496 | Cargo |

### Boolean Coercion (to_three_value)

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 185 | `cond_coerce_int64_nonzero_true` | INT64 nonzero coerces to TRUE | ss11.12 line 7978 | Cargo |
| 186 | `cond_coerce_int64_zero_false` | INT64 zero coerces to FALSE | ss11.12 line 7978 | Cargo |
| 187 | `cond_coerce_uint64_nonzero_true` | UINT64 nonzero coerces to TRUE | ss11.12 line 7977 | Cargo |
| 188 | `cond_coerce_uint64_zero_false` | UINT64 zero coerces to FALSE | ss11.12 line 7977 | Cargo |
| 189 | `cond_coerce_boolean_nonzero_true` | BOOLEAN nonzero coerces to TRUE | ss11.12 line 7977 | Cargo |
| 190 | `cond_coerce_boolean_zero_false` | BOOLEAN zero coerces to FALSE | ss11.12 line 7977 | Cargo |
| 191 | `cond_coerce_string_nonempty_true` | STRING non-empty coerces to TRUE | ss11.12 line 7980 | Cargo |
| 192 | `cond_coerce_string_empty_false` | STRING empty coerces to FALSE | ss11.12 line 7980 | Cargo |
| 193 | `cond_coerce_null_unknown` | NULL value coerces to UNKNOWN | ss11.12 lines 7975-7976 | Cargo |
| 194 | `cond_coerce_sid_unknown` | SID value coerces to UNKNOWN | ss11.12 line 7981 | Cargo |
| 195 | `cond_coerce_octet_unknown` | OCTET value coerces to UNKNOWN | ss11.12 line 7981 | Cargo |
| 196 | `cond_coerce_composite_unknown` | COMPOSITE value coerces to UNKNOWN | ss11.12 line 7981 | Cargo |

### negate_tv

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 197 | `cond_negate_true_is_false` | negate_tv(TRUE) = FALSE | ss11.12 line 7966 | Cargo |
| 198 | `cond_negate_false_is_true` | negate_tv(FALSE) = TRUE | ss11.12 line 7967 | Cargo |
| 199 | `cond_negate_unknown_is_unknown` | negate_tv(UNKNOWN) = UNKNOWN | ss11.12 line 7968 | Cargo |

### Padding (0x00)

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 200 | `cond_padding_zero_skip` | Opcode 0x00 is treated as skip (no-op) | ss11.12 line 7251 | Cargo |
| 201 | `cond_padding_interior_zero_should_return_unknown` | Implementation SHOULD treat interior 0x00 before logical end of expression as error -> UNKNOWN | ss11.12 lines 7533-7537 | Cargo |

### Bounds Checks

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 202 | `cond_bounds_integer_too_short` | Integer literal with < 10 bytes remaining returns UNKNOWN | ss11.12 lines 7519-7520 | Cargo |
| 203 | `cond_bounds_length_prefix_too_short` | Length prefix with < 4 bytes remaining returns UNKNOWN | ss11.12 lines 7521-7522 | Cargo |
| 204 | `cond_bounds_data_exceeds_buffer` | Data extending past buffer end returns UNKNOWN | ss11.12 lines 7523-7525 | Cargo |
| 205 | `cond_bounds_overflow_safe_length` | Length prefix overflow check uses subtraction form (length <= len - pos), not addition form | ss11.12 lines 7523-7525 | Cargo |

---

## 6. Callback ACEs in DACL Walk (ss11.12, lines 6919-7068)

### Allow Callback ACEs

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 206 | `callback_allow_true_grants` | ACCESS_ALLOWED_CALLBACK: condition TRUE -> ACE grants access | ss11.12 lines 6920-6942 | Cargo |
| 207 | `callback_allow_false_skips` | ACCESS_ALLOWED_CALLBACK: condition FALSE -> ACE is skipped | ss11.12 lines 6930-6931 | Cargo |
| 208 | `callback_allow_unknown_skips` | ACCESS_ALLOWED_CALLBACK: condition UNKNOWN -> ACE is skipped (when in doubt, don't grant) | ss11.12 lines 6930-6931 | Cargo |
| 209 | `callback_allow_null_condition_skips` | ACCESS_ALLOWED_CALLBACK with null condition data -> UNKNOWN -> skip | ss11.12 lines 6923-6925 | Cargo |
| 210 | `callback_allow_object_true_grants` | ACCESS_ALLOWED_CALLBACK_OBJECT: same TRUE-only semantics | ss11.12 lines 6968-6985 | Cargo |
| 211 | `callback_allow_object_null_condition_skips` | ACCESS_ALLOWED_CALLBACK_OBJECT with null condition -> skip | ss11.12 lines 6971-6972 | Cargo |

### Deny Callback ACEs

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 212 | `callback_deny_true_denies` | ACCESS_DENIED_CALLBACK: condition TRUE -> ACE denies access | ss11.12 lines 6949-6966 | Cargo |
| 213 | `callback_deny_unknown_denies` | ACCESS_DENIED_CALLBACK: condition UNKNOWN -> ACE denies access (when in doubt, deny) | ss11.12 lines 6951-6958 | Cargo |
| 214 | `callback_deny_false_skips` | ACCESS_DENIED_CALLBACK: condition FALSE -> ACE is skipped | ss11.12 lines 6957-6958 | Cargo |
| 215 | `callback_deny_object_true_denies` | ACCESS_DENIED_CALLBACK_OBJECT: same TRUE-or-UNKNOWN semantics | ss11.12 lines 7029-7058 | Cargo |
| 216 | `callback_deny_object_false_skips` | ACCESS_DENIED_CALLBACK_OBJECT: condition FALSE -> skip | ss11.12 lines 7036-7038 | Cargo |

### Non-Callback ACEs with Conditions (Peios extension)

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 217 | `basic_allow_with_condition_true_grants` | ACCESS_ALLOWED with ace.condition (non-null, non-callback): condition TRUE -> grants | ss11.12 lines 6932-6938 | Cargo |
| 218 | `basic_allow_with_condition_false_skips` | ACCESS_ALLOWED with ace.condition: condition FALSE -> skips | ss11.12 lines 6932-6938 | Cargo |

---

## 7. Claim Resolution (lines 7755-7835)

### resolve_claim

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 219 | `resolve_claim_null_claims_returns_null` | Null claims list returns Value(NULL) | ss11.12 lines 7772-7773 | Cargo |
| 220 | `resolve_claim_name_case_insensitive` | Claim name matching is case-insensitive | ss11.12 line 7776 | Cargo |
| 221 | `resolve_claim_disabled_returns_null` | Claim with DISABLED flag (0x0010) returns Value(NULL) | ss11.12 lines 7777-7778 | Cargo |
| 222 | `resolve_claim_deny_only_allow_returns_null` | Claim with USE_FOR_DENY_ONLY (0x0004) returns NULL when for_allow=true | ss11.12 lines 7779-7780 | Cargo |
| 223 | `resolve_claim_deny_only_deny_returns_value` | Claim with USE_FOR_DENY_ONLY returns the value when for_allow=false | ss11.12 lines 7779-7780 | Cargo |
| 224 | `resolve_claim_empty_values_returns_null` | Claim with zero values returns Value(NULL) | ss11.12 lines 7781-7782 | Cargo |
| 225 | `resolve_claim_single_value_scalar` | Single-valued claim returns scalar Value with correct type | ss11.12 lines 7790-7794 | Cargo |
| 226 | `resolve_claim_multi_value_composite` | Multi-valued claim returns COMPOSITE Value with elements | ss11.12 lines 7795-7801 | Cargo |
| 227 | `resolve_claim_boolean_normalized` | BOOLEAN values are normalized: nonzero -> 1, zero -> 0 | ss11.12 lines 7792-7793, 7798-7799 | Cargo |
| 228 | `resolve_claim_not_found_returns_null` | Claim not found in list returns Value(NULL) | ss11.12 line 7803 | Cargo |
| 229 | `resolve_claim_flags_carried` | Resolved value carries attr.Flags (for CASE_SENSITIVE detection) | ss11.12 line 7794 | Cargo |

### resolve_resource_attr

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 230 | `resolve_resource_disabled_returns_null` | Resource attr with DISABLED flag returns NULL | ss11.12 lines 7812-7813 | Cargo |
| 231 | `resolve_resource_deny_only_allow_null` | Resource attr with USE_FOR_DENY_ONLY returns NULL when for_allow=true | ss11.12 lines 7814-7815 | Cargo |
| 232 | `resolve_resource_empty_values_null` | Resource attr with zero values returns NULL | ss11.12 lines 7816-7817 | Cargo |
| 233 | `resolve_resource_not_found_null` | Resource attr not in map returns NULL | ss11.12 line 7834 | Cargo |

### claim_type_to_value_type

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 234 | `claim_type_int64_maps` | CLAIM_TYPE_INT64 (0x0001) -> VALUE_TYPE INT64 | ss11.12 line 7761 | Cargo |
| 235 | `claim_type_uint64_maps` | CLAIM_TYPE_UINT64 (0x0002) -> VALUE_TYPE UINT64 | ss11.12 line 7762 | Cargo |
| 236 | `claim_type_string_maps` | CLAIM_TYPE_STRING (0x0003) -> VALUE_TYPE STRING | ss11.12 line 7763 | Cargo |
| 237 | `claim_type_sid_maps` | CLAIM_TYPE_SID (0x0005) -> VALUE_TYPE SID | ss11.12 line 7764 | Cargo |
| 238 | `claim_type_boolean_maps` | CLAIM_TYPE_BOOLEAN (0x0006) -> VALUE_TYPE BOOLEAN | ss11.12 line 7765 | Cargo |
| 239 | `claim_type_octet_maps` | CLAIM_TYPE_OCTET (0x0010) -> VALUE_TYPE OCTET | ss11.12 line 7766 | Cargo |

---

## 8. Comparison and Set Operator Helpers (lines 7837-7982)

### compare_equal

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 240 | `compare_equal_null_lhs_unknown` | compare_equal with NULL lhs returns UNKNOWN | ss11.12 line 7860 | Cargo |
| 241 | `compare_equal_null_rhs_unknown` | compare_equal with NULL rhs returns UNKNOWN | ss11.12 line 7860 | Cargo |
| 242 | `compare_equal_scalar_vs_composite_unknown` | compare_equal with one scalar one composite returns UNKNOWN | ss11.12 lines 7862-7863 | Cargo |
| 243 | `compare_equal_incompatible_types_unknown` | compare_equal with incompatible types returns UNKNOWN | ss11.12 lines 7864-7865 | Cargo |
| 244 | `compare_equal_int64_int64_match` | compare_equal(INT64(5), INT64(5)) = TRUE | ss11.12 line 7867 | Cargo |
| 245 | `compare_equal_int64_int64_mismatch` | compare_equal(INT64(5), INT64(6)) = FALSE | ss11.12 lines 7879-7882 | Cargo |
| 246 | `compare_equal_int64_uint64_promoted` | compare_equal(INT64, UINT64) promotes for comparison | ss11.12 line 7868 | Cargo |
| 247 | `compare_equal_boolean_int_equality` | compare_equal supports BOOLEAN vs INT (== and != only) | ss11.12 line 7869 | Cargo |
| 248 | `compare_equal_string_case_insensitive_default` | String equality is case-insensitive by default (ASCII fold only) | ss11.12 lines 7872-7878 | Cargo |
| 249 | `compare_equal_string_case_sensitive_flag` | If either operand has CASE_SENSITIVE flag (0x0002), string comparison is case-sensitive | ss11.12 line 7872 | Cargo |
| 250 | `compare_equal_string_ascii_fold_only` | Case folding is ASCII only (A-Z -> a-z), no Unicode case folding | ss11.12 lines 7874-7878 | Cargo |
| 251 | `compare_equal_sid_match` | SID vs SID equality comparison works | ss11.12 line 7870 | Cargo |
| 252 | `compare_equal_octet_match` | OCTET vs OCTET equality comparison works | ss11.12 line 7870 | Cargo |
| 253 | `compare_equal_composite_elementwise` | COMPOSITE vs COMPOSITE: element-wise, same length, same order | ss11.12 lines 7870, narrative 5301-5303 | Cargo |
| 254 | `compare_equal_composite_different_length_false` | COMPOSITE with different lengths returns FALSE | ss11.12 narrative 5301-5303 | Cargo |
| 255 | `compare_equal_composite_different_order_false` | COMPOSITE with same elements different order returns FALSE (strict ordering) | ss11.12 narrative 5301-5306 | Cargo |

### compare_ordered

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 256 | `compare_ordered_null_unknown` | compare_ordered with NULL operand returns UNKNOWN | ss11.12 lines 7890-7891 | Cargo |
| 257 | `compare_ordered_composite_unknown` | compare_ordered with composite operand returns UNKNOWN | ss11.12 lines 7892-7893 | Cargo |
| 258 | `compare_ordered_boolean_unknown` | compare_ordered with BOOLEAN operand returns UNKNOWN | ss11.12 lines 7894-7895 | Cargo |
| 259 | `compare_ordered_incompatible_unknown` | compare_ordered with incompatible types returns UNKNOWN | ss11.12 lines 7896-7897 | Cargo |
| 260 | `compare_ordered_lt_true` | LT: cmp < 0 -> TRUE | ss11.12 line 7902 | Cargo |
| 261 | `compare_ordered_lt_false` | LT: cmp >= 0 -> FALSE | ss11.12 line 7902 | Cargo |
| 262 | `compare_ordered_le_true` | LE: cmp <= 0 -> TRUE | ss11.12 line 7903 | Cargo |
| 263 | `compare_ordered_le_false` | LE: cmp > 0 -> FALSE | ss11.12 line 7903 | Cargo |
| 264 | `compare_ordered_gt_true` | GT: cmp > 0 -> TRUE | ss11.12 line 7904 | Cargo |
| 265 | `compare_ordered_gt_false` | GT: cmp <= 0 -> FALSE | ss11.12 line 7904 | Cargo |
| 266 | `compare_ordered_ge_true` | GE: cmp >= 0 -> TRUE | ss11.12 line 7905 | Cargo |
| 267 | `compare_ordered_ge_false` | GE: cmp < 0 -> FALSE | ss11.12 line 7905 | Cargo |
| 268 | `compare_ordered_int64_uint64_negative_lt` | Negative INT64 is always less than any UINT64 in ordered comparison | ss11.12 line 7889, narrative 5284-5286 | Cargo |
| 269 | `compare_ordered_string_case_flag` | String ordered comparison respects CASE_SENSITIVE flag | ss11.12 line 7900 | Cargo |

### to_sid_list

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 270 | `to_sid_list_single_sid` | Single SID value returns [sid] | ss11.12 lines 7842-7843 | Cargo |
| 271 | `to_sid_list_composite_sids` | Composite of SIDs returns all sids | ss11.12 lines 7844-7852 | Cargo |
| 272 | `to_sid_list_empty_composite_error` | Empty composite returns error | ss11.12 lines 7845-7846 | Cargo |
| 273 | `to_sid_list_mixed_types_error` | Composite with non-SID element returns error | ss11.12 lines 7848-7850 | Cargo |
| 274 | `to_sid_list_non_sid_scalar_error` | Non-SID scalar value returns error | ss11.12 line 7853 | Cargo |

---

## 9. PRINCIPAL_SELF Substitution (lines 7542-7559)

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 275 | `enrich_token_owner_injects_owner_rights` | If caller is owner (SidMatchesToken with for_allow=true), S-1-3-4 is added as virtual group | ss11.17 lines 7548-7551 | Cargo |
| 276 | `enrich_token_owner_not_owner_no_injection` | If caller is not owner, S-1-3-4 is NOT added | ss11.17 lines 7548-7551 | Cargo |
| 277 | `enrich_token_self_sid_allow_match` | If self_sid matches token with for_allow=true, S-1-5-10 is added as normal virtual group | ss11.17 lines 7553-7555 | Cargo |
| 278 | `enrich_token_self_sid_deny_only_match` | If self_sid matches token with for_allow=false but not true, S-1-5-10 is added as deny-only virtual group | ss11.17 lines 7556-7558 | Cargo |
| 279 | `enrich_token_self_sid_null_no_injection` | If self_sid is null, S-1-5-10 is NOT added | ss11.17 lines 7553-7558 | Cargo |
| 280 | `enrich_token_self_sid_no_match_no_injection` | If self_sid does not match token at all, S-1-5-10 is NOT added | ss11.17 lines 7553-7558 | Cargo |
| 281 | `enrich_token_idempotent` | EnrichToken returns a new token view; original is not modified | ss11.17 line 7547 | Cargo |

---

## 10. OWNER RIGHTS Virtual Group (ss11.4, lines 6869-6907)

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 282 | `owner_implicit_read_control_write_dac` | Owner gets implicit READ_CONTROL and WRITE_DAC when no OWNER RIGHTS ACE present | ss11.4 lines 6886-6894 | Cargo |
| 283 | `owner_implicit_suppressed_by_owner_rights_ace` | When any non-inherit-only access-control ACE targets S-1-3-4, implicit grant is suppressed | ss11.4 lines 6871-6884 | Cargo |
| 284 | `owner_implicit_allow_ace_s134_suppresses` | ACCESS_ALLOWED ACE targeting S-1-3-4 suppresses implicit rights | ss11.4 lines 6876-6884 | Cargo |
| 285 | `owner_implicit_deny_ace_s134_suppresses` | ACCESS_DENIED ACE targeting S-1-3-4 suppresses implicit rights | ss11.4 lines 6876-6884 | Cargo |
| 286 | `owner_implicit_callback_allow_s134_suppresses` | ACCESS_ALLOWED_CALLBACK ACE targeting S-1-3-4 suppresses implicit rights | ss11.4 lines 6877-6884 | Cargo |
| 287 | `owner_implicit_callback_deny_s134_suppresses` | ACCESS_DENIED_CALLBACK ACE targeting S-1-3-4 suppresses implicit rights | ss11.4 lines 6877-6884 | Cargo |
| 288 | `owner_implicit_object_ace_s134_suppresses` | Object ACE variants targeting S-1-3-4 suppress implicit rights | ss11.4 lines 6878-6881 | Cargo |
| 289 | `owner_implicit_inherit_only_s134_no_suppress` | Inherit-only ACE targeting S-1-3-4 does NOT suppress implicit rights | ss11.4 lines 6874-6875 | Cargo |
| 290 | `owner_implicit_only_when_sid_matches` | Implicit rights only apply when sid_match(sd.owner, true) returns true | ss11.4 line 6870 | Cargo |
| 291 | `owner_implicit_decided_bits_not_regranted` | Implicit rights only apply to undecided bits (& ~decided) | ss11.4 line 6887 | Cargo |
| 292 | `owner_implicit_tree_propagation` | With object_tree, implicit rights are granted to every node (undecided bits only) | ss11.4 lines 6890-6894 | Cargo |
| 293 | `owner_implicit_skipped_in_confinement` | Confinement pass calls EvaluateDACL with skip_owner_implicit=true | ss11.4/ss11.14 line 6343 | Cargo |
| 294 | `owner_implicit_conditional_s134_suppresses_regardless_of_condition` | Conditional ACE targeting S-1-3-4 suppresses implicit grant even if condition evaluates to FALSE | ss11.12 narrative 5246-5253 | Cargo |

---

## 11. NULL DACL (lines 6896-6907)

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 295 | `null_dacl_grants_all_valid_bits` | NULL DACL grants all valid bits (MapGenericBits(GENERIC_ALL)) not yet decided | ss11.3 lines 6897-6907 | Cargo |
| 296 | `null_dacl_respects_decided` | NULL DACL only grants undecided bits (& ~decided) | ss11.3 lines 6899, 6904 | Cargo |
| 297 | `null_dacl_tree_propagation` | With object_tree, NULL DACL grants to every node | ss11.3 lines 6902-6906 | Cargo |

---

## 12. AccessCheckResultList (lines 6794-6852)

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 298 | `result_list_requires_tree` | AccessCheckResultList with null tree returns ERROR_INVALID_PARAMETER | ss11.1 lines 6817-6818 | Cargo |
| 299 | `result_list_per_node_verdict` | Each node produces an independent status (OK or ACCESS_DENIED) | ss11.1 lines 6834-6840 | Cargo |
| 300 | `result_list_node_ok_all_desired` | Node status is OK when (node.granted AND mapped_desired) == mapped_desired | ss11.1 lines 6837-6838 | Cargo |
| 301 | `result_list_node_denied_partial` | Node status is ACCESS_DENIED when not all desired bits are granted | ss11.1 lines 6839-6840 | Cargo |
| 302 | `result_list_zero_desired_all_ok` | When mapped_desired is 0, all nodes are OK | ss11.1 lines 6835-6836 | Cargo |
| 303 | `result_list_max_allowed_returns_node_granted` | In MAXIMUM_ALLOWED mode, node_granted = node.granted (raw grant mask) | ss11.1 lines 6842-6843 | Cargo |
| 304 | `result_list_normal_mode_ok_returns_desired` | In normal mode, OK node returns mapped_desired | ss11.1 line 6845 | Cargo |
| 305 | `result_list_normal_mode_denied_returns_zero` | In normal mode, denied node returns 0 | ss11.1 line 6845 | Cargo |
| 306 | `result_list_denial_on_one_not_all` | A denial on one property fails that property only, not the whole request | ss11.1 narrative 6797-6798 | Cargo |

---

## 13. AccessCheck Single-Result Wrapper (lines 6731-6793)

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 307 | `access_check_tree_uses_root_granted` | When tree is present, granted = object_tree[0].granted | ss11.1 lines 6767-6768 | Cargo |
| 308 | `access_check_zero_desired_always_succeeds` | When mapped_desired is 0, allowed = true (asked for nothing, got nothing) | ss11.1 lines 6771-6773, narrative 6789-6790 | Cargo |
| 309 | `access_check_maximum_allowed_zero_grant_succeeds` | Pure MAXIMUM_ALLOWED request with zero granted returns allowed=true | ss11.1 narrative 6789-6792 | Cargo |
| 310 | `access_check_desired_fully_granted_succeeds` | allowed = true when (granted AND mapped_desired) == mapped_desired | ss11.1 line 6774 | Cargo |
| 311 | `access_check_desired_partially_granted_fails` | allowed = false when not all desired bits are in granted | ss11.1 line 6774 | Cargo |
| 312 | `access_check_returns_raw_granted` | Always returns the raw granted mask, not just the requested subset | ss11.1 lines 6776-6781 | Cargo |
| 313 | `access_check_max_allowed_combined_with_specific` | MAXIMUM_ALLOWED | specific bits: allowed reflects specific bits; granted reflects full effective access | ss11.5 narrative 4574-4579 | Cargo |

---

## 14. SidMatchesToken (lines 7562-7577)

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 314 | `sid_match_user_sid_match` | SID matches token.user_sid -> true | ss11.3 line 7565 | Cargo |
| 315 | `sid_match_user_deny_only_allow_false` | User SID marked deny_only does not match for_allow=true | ss11.3 lines 7566-7567 | Cargo |
| 316 | `sid_match_user_deny_only_deny_true` | User SID marked deny_only matches for_allow=false | ss11.3 lines 7565-7568 | Cargo |
| 317 | `sid_match_group_enabled_allow_true` | Enabled group matches for_allow=true | ss11.3 lines 7569-7576 | Cargo |
| 318 | `sid_match_group_deny_only_allow_false` | Deny-only group does not match for_allow=true | ss11.3 lines 7572-7573 | Cargo |
| 319 | `sid_match_group_deny_only_deny_true` | Deny-only group matches for_allow=false | ss11.3 lines 7569-7575 | Cargo |
| 320 | `sid_match_group_neither_enabled_nor_deny_skipped` | Group with neither enabled nor deny_only set is skipped entirely | ss11.3 lines 7570-7571 | Cargo |
| 321 | `sid_match_no_match_false` | SID not in user SID or any group -> false | ss11.3 line 7576 | Cargo |

---

## 15. MapGenericBits (lines 7597-7609)

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 322 | `map_generic_read` | GENERIC_READ bit cleared, mapping.read bits OR'd in | ss11.2 lines 7600-7601 | Cargo |
| 323 | `map_generic_write` | GENERIC_WRITE bit cleared, mapping.write bits OR'd in | ss11.2 lines 7602-7603 | Cargo |
| 324 | `map_generic_execute` | GENERIC_EXECUTE bit cleared, mapping.execute bits OR'd in | ss11.2 lines 7604-7605 | Cargo |
| 325 | `map_generic_all` | GENERIC_ALL bit cleared, mapping.all bits OR'd in | ss11.2 lines 7606-7607 | Cargo |
| 326 | `map_no_generic_bits_passthrough` | Mask with no generic bits passes through unchanged | ss11.2 lines 7600-7607 | Cargo |
| 327 | `map_multiple_generic_bits` | Multiple generic bits are all expanded in one call | ss11.2 lines 7600-7607 | Cargo |

---

## 16. Tree Helpers (lines 7611-7667)

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 328 | `find_node_found` | FindNode returns node with matching GUID | ss11.8 lines 7613-7617 | Cargo |
| 329 | `find_node_not_found` | FindNode returns null for missing GUID | ss11.8 line 7617 | Cargo |
| 330 | `descendants_of_node` | Descendants returns all subsequent nodes with Level > node.Level until same-or-lower level | ss11.8 lines 7621-7629 | Cargo |
| 331 | `descendants_of_leaf` | Descendants of leaf node returns empty | ss11.8 lines 7621-7629 | Cargo |
| 332 | `siblings_of_node` | Siblings returns nodes at same level with same parent, excluding self | ss11.8 lines 7631-7652 | Cargo |
| 333 | `siblings_of_root` | Siblings of root (Level 0) returns empty | ss11.8 lines 7634-7635 | Cargo |
| 334 | `ancestors_of_node` | Ancestors returns nodes walking up from parent to root, one per level | ss11.8 lines 7654-7667 | Cargo |
| 335 | `ancestors_of_root` | Ancestors of root returns empty | ss11.8 lines 7654-7667 | Cargo |

---

## 17. Object ACE DACL Walk (ss11.8, lines 6967-7068)

### Allow Object ACEs

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 336 | `object_allow_no_guid_treated_as_basic` | Object allow ACE without object_type_present or without tree: treated as basic allow | ss11.8 lines 6987-6996 | Cargo |
| 337 | `object_allow_guid_grants_target_and_descendants` | Object allow ACE with GUID: grants target node + all descendants | ss11.8 lines 6999-7008 | Cargo |
| 338 | `object_allow_guid_sibling_aggregation_upward` | After granting, sibling aggregation promotes common bits to parent | ss11.8 lines 7010-7027 | Cargo |
| 339 | `object_allow_guid_not_found_noop` | Object allow ACE with GUID not in tree: no-op | ss11.8 lines 6999-7000 | Cargo |
| 340 | `object_allow_sibling_aggregation_per_bit` | Sibling aggregation is per-bit intersection (bitwise AND of all siblings) | ss11.8 lines 7014-7016, narrative 7011 | Cargo |
| 341 | `object_allow_sibling_aggregation_stops_at_zero` | Sibling aggregation early-exits when common bits are zero | ss11.8 lines 7017-7020 | Cargo |
| 342 | `object_allow_sibling_aggregation_recursive_to_root` | Sibling aggregation walks from target's parent up to root | ss11.8 lines 7012-7027 | Cargo |

### Deny Object ACEs

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 343 | `object_deny_no_guid_treated_as_basic` | Object deny ACE without object_type_present or without tree: treated as basic deny | ss11.8 lines 7040-7048 | Cargo |
| 344 | `object_deny_guid_denies_target_and_descendants` | Object deny ACE with GUID: denies target node + all descendants | ss11.8 lines 7050-7057 | Cargo |
| 345 | `object_deny_ancestor_propagation_unconditional` | After deny, ancestor deny propagation marks ace_mask as decided on all ancestors unconditionally | ss11.8 lines 7059-7063 | Cargo |
| 346 | `object_deny_ancestor_propagation_prevents_future_grants` | Ancestor deny propagation prevents future allow ACEs from granting those bits at higher levels | ss11.8 lines 7059-7063 | Cargo |
| 347 | `object_deny_guid_not_found_noop` | Object deny ACE with GUID not in tree: no-op | ss11.8 lines 7050-7051 | Cargo |

### DACL Walk Short-Circuit

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 348 | `dacl_short_circuit_all_decided` | When all desired bits are decided and no tree and not max_allowed, walk stops | ss11.3 lines 7065-7068 | Cargo |
| 349 | `dacl_no_short_circuit_with_tree` | Short-circuit does not apply when object_tree is present | ss11.3 line 7066 | Cargo |
| 350 | `dacl_no_short_circuit_max_allowed` | Short-circuit does not apply in MAXIMUM_ALLOWED mode | ss11.3 line 7066 | Cargo |
| 351 | `dacl_no_short_circuit_zero_desired` | Short-circuit requires desired != 0 | ss11.3 line 7067 | Cargo |

---

## 18. PreSACLWalk (lines 7071-7125)

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 352 | `presacl_first_mic_ace_used` | Only the first SYSTEM_MANDATORY_LABEL ACE is used; subsequent ignored | ss11.13 lines 7088-7091 | Cargo |
| 353 | `presacl_mic_inherit_only_ignored` | MIC ACE with INHERIT_ONLY flag is stored as found but not enforced | ss11.13 lines 7090-7091 | Cargo |
| 354 | `presacl_default_mic_when_none` | When no MIC ACE present, default Medium/NO_WRITE_UP is used | ss11.13 lines 7112-7115 | Cargo |
| 355 | `presacl_resource_attr_first_wins` | Duplicate resource attribute names: first one wins | ss11.11 lines 7093-7096 | Cargo |
| 356 | `presacl_first_pip_ace_used` | Only the first SYSTEM_PROCESS_TRUST_LABEL ACE is used | ss11.15 lines 7098-7102 | Cargo |
| 357 | `presacl_pip_inherit_only_ignored` | PIP ACE with INHERIT_ONLY flag is stored as found but not enforced | ss11.15 lines 7101-7102 | Cargo |
| 358 | `presacl_no_pip_default` | When no PIP ACE present, PIP is not enforced (no default) | ss11.15 lines 7118-7119 | Cargo |
| 359 | `presacl_scoped_policy_collected` | SYSTEM_SCOPED_POLICY_ID ACEs have their SIDs collected (inherit-only excluded) | ss11.16 lines 7104-7106 | Cargo |
| 360 | `presacl_mandatory_decided_tracks_mic` | mandatory_decided is populated with bits decided by MIC | ss11.17 line 7116 | Cargo |
| 361 | `presacl_mandatory_decided_tracks_pip` | mandatory_decided is populated with bits decided by PIP | ss11.17 line 7124 | Cargo |

---

## 19. EnforceMIC (lines 7127-7167)

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 362 | `mic_no_write_up_policy_off_noop` | If TOKEN_MANDATORY_POLICY_NO_WRITE_UP is not set, MIC is not enforced | ss11.13 lines 7132-7134 | Cargo |
| 363 | `mic_dominant_caller_bypass` | If token.integrity_level >= ace.sid (dominant), MIC imposes no restrictions | ss11.13 lines 7136-7146 | Cargo |
| 364 | `mic_non_dominant_default_read_execute` | Non-dominant caller starts with read + execute allowed | ss11.13 lines 7148-7151 | Cargo |
| 365 | `mic_no_read_up_strips_read` | ACE mask with SYSTEM_MANDATORY_LABEL_NO_READ_UP strips read from allowed | ss11.13 lines 7152-7153 | Cargo |
| 366 | `mic_no_write_up_strips_write` | ACE mask with SYSTEM_MANDATORY_LABEL_NO_WRITE_UP strips write from allowed | ss11.13 lines 7154-7155 | Cargo |
| 367 | `mic_no_execute_up_strips_execute` | ACE mask with SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP strips execute from allowed | ss11.13 lines 7156-7157 | Cargo |
| 368 | `mic_se_relabel_allows_write_owner` | SeRelabelPrivilege adds WRITE_OWNER to allowed set for non-dominant callers | ss11.13 lines 7162-7163 | Cargo |
| 369 | `mic_decided_set_to_blocked_bits` | decided is updated with all bits NOT in allowed (all_bits AND NOT allowed) | ss11.13 lines 7165-7166 | Cargo |
| 370 | `mic_no_se_relabel_no_write_owner` | Without SeRelabelPrivilege, WRITE_OWNER is blocked by MIC for non-dominant callers | ss11.13 lines 7162-7163 | Cargo |

---

## 20. EnforcePIP (lines 7169-7217)

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 371 | `pip_dominant_caller_bypass` | If pip_type >= ace_type AND pip_trust >= ace_trust, PIP imposes no restrictions | ss11.15 lines 7181-7189 | Cargo |
| 372 | `pip_non_dominant_lower_type` | Non-dominant (lower type): access restricted to ACE mask | ss11.15 lines 7194-7196 | Cargo |
| 373 | `pip_non_dominant_lower_trust` | Non-dominant (lower trust): access restricted to ACE mask | ss11.15 lines 7181-7196 | Cargo |
| 374 | `pip_non_dominant_incomparable` | Incomparable (higher type, lower trust or vice versa): non-dominant, restricted | ss11.15 lines 7181-7182 | Cargo |
| 375 | `pip_ace_mask_zero_total_lockout` | ACE mask of 0 means total lockout for non-dominant callers | ss11.15 line 7195, narrative 5754 | Cargo |
| 376 | `pip_ace_mask_maps_generic` | ACE mask generic bits are mapped via MapGenericBits | ss11.15 lines 7199-7200 | Cargo |
| 377 | `pip_denied_includes_access_system_security` | PIP denied set includes ACCESS_SYSTEM_SECURITY (prevents SACL access by non-PIP callers) | ss11.15 lines 7206-7210 | Cargo |
| 378 | `pip_revokes_privilege_granted` | PIP clears bits from both granted AND privilege_granted | ss11.15 lines 7214-7216 | Cargo |
| 379 | `pip_revokes_decided_bits` | PIP marks denied bits in decided | ss11.15 line 7212 | Cargo |
| 380 | `pip_uses_psb_not_token` | PIP uses pip_type and pip_trust from PSB parameters, not the token | ss11.15 lines 7175-7176 | Cargo |

---

## 21. Auditing (lines 6572-6728)

### Privilege-Use Auditing

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 381 | `audit_security_privilege_survived` | SeSecurityPrivilege audit fires if (security_granted AND granted) != 0 | ss11.10 lines 6538-6541 | Cargo |
| 382 | `audit_take_ownership_survived` | SeTakeOwnershipPrivilege audit fires if (take_ownership_granted AND granted) != 0 | ss11.10 lines 6544-6547 | Cargo |
| 383 | `audit_backup_privilege_survived` | SeBackupPrivilege audit fires if (backup_granted AND granted) != 0 | ss11.10 lines 6551-6554 | Cargo |
| 384 | `audit_restore_privilege_survived` | SeRestorePrivilege audit fires if (restore_granted AND granted) != 0 | ss11.10 lines 6556-6559 | Cargo |
| 385 | `audit_relabel_privilege_write_owner` | SeRelabelPrivilege audit fires if enabled AND WRITE_OWNER granted AND NOT take_ownership_granted | ss11.10 lines 6565-6570 | Cargo |
| 386 | `audit_privilege_not_in_max_allowed` | Privilege-use audits do not fire in MAXIMUM_ALLOWED mode | ss11.10 line 6535 | Cargo |
| 387 | `audit_privilege_updates_token_used` | Fired privilege audits set token.privileges_used bit | ss11.10 lines 6539, 6545, 6552, 6558, 6568 | Cargo |

### Access Auditing (SACL walk)

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 388 | `audit_sacl_inherit_only_skipped` | SACL ACEs with INHERIT_ONLY flag are skipped | ss11.10 lines 6597-6598 | Cargo |
| 389 | `audit_no_success_no_failure_skipped` | Audit ACE with neither success nor failure flag is skipped | ss11.10 lines 6609-6610 | Cargo |
| 390 | `audit_success_only_on_success` | Audit ACE with only success flag: fires only on successful access | ss11.10 lines 6612-6613 | Cargo |
| 391 | `audit_failure_only_on_failure` | Audit ACE with only failure flag: fires only on failed access | ss11.10 lines 6614-6615 | Cargo |
| 392 | `audit_sid_mismatch_skipped` | Audit ACE skipped when SID doesn't match token | ss11.10 lines 6617-6618 | Cargo |
| 393 | `audit_sid_uses_deny_polarity` | Audit SID matching uses deny polarity (broadest identity view) | ss11.10 line 6593-6594 | Cargo |
| 394 | `audit_callback_condition_false_skipped` | Conditional audit ACE with condition FALSE is skipped | ss11.10 lines 6621-6629 | Cargo |
| 395 | `audit_callback_condition_unknown_fires` | Conditional audit ACE with condition UNKNOWN fires (when in doubt, audit) | ss11.10 lines 6621-6629 | Cargo |
| 396 | `audit_success_mask_overlap_required` | On success: audit fires only if (granted AND ace_mask) != 0 | ss11.10 lines 6665-6667 | Cargo |
| 397 | `audit_failure_mask_overlap_required` | On failure: audit fires only if (ace_mask AND desired AND NOT granted) != 0 | ss11.10 lines 6669-6670 | Cargo |
| 398 | `audit_object_type_per_node` | Object audit ACE: success computed per node, not whole object | ss11.10 lines 6634-6661 | Cargo |
| 399 | `audit_object_guid_not_found_skipped` | Object audit ACE with GUID not in tree is skipped | ss11.10 lines 6637-6638 | Cargo |

### Per-Token Audit Policy

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 400 | `audit_token_policy_success` | Token audit policy success flag fires unconditionally (regardless of SACL) | ss11.10 lines 6585-6587 | Cargo |
| 401 | `audit_token_policy_failure` | Token audit policy failure flag fires unconditionally | ss11.10 lines 6588-6590 | Cargo |

### Continuous Auditing (Alarm ACEs)

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 402 | `continuous_audit_only_on_success` | Alarm ACEs only evaluated on successful access (handle must be opened) | ss11.10 lines 6683-6684 | Cargo |
| 403 | `continuous_audit_sid_match_required` | Alarm ACE requires SID match | ss11.10 lines 6686-6687 | Cargo |
| 404 | `continuous_audit_callback_condition_false_skipped` | Callback alarm ACE with FALSE condition is skipped | ss11.10 lines 6689-6696 | Cargo |
| 405 | `continuous_audit_scalar_mask_intersect_granted` | Scalar alarm: continuous_audit_mask |= (ace_mask AND granted) | ss11.10 line 6722 | Cargo |
| 406 | `continuous_audit_object_per_node` | Object alarm ACE: per-node continuous mask recorded | ss11.10 lines 6701-6718 | Cargo |
| 407 | `continuous_audit_object_accumulates` | Multiple alarm ACEs for same GUID accumulate (OR mask) | ss11.10 lines 6711-6714 | Cargo |

---

## 22. Access Success Determination (lines 6577-6580)

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 408 | `access_success_zero_desired_true` | mapped_desired == 0 -> access_success = true | ss11.17 lines 6577-6578 | Cargo |
| 409 | `access_success_all_granted_true` | (granted AND mapped_desired) == mapped_desired -> success | ss11.17 line 6580 | Cargo |
| 410 | `access_success_partial_grant_false` | (granted AND mapped_desired) != mapped_desired -> failure | ss11.17 line 6580 | Cargo |

---

## 23. Type Definitions (lines 7669-7735)

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 411 | `claim_type_values` | CLAIM_TYPE enum values: INT64=0x0001, UINT64=0x0002, STRING=0x0003, SID=0x0005, BOOLEAN=0x0006, OCTET=0x0010 | ss11.17 lines 7689-7694 | Cargo |
| 412 | `claim_flags_case_sensitive` | CASE_SENSITIVE flag value = 0x0002 | ss11.17 line 7683 | Cargo |
| 413 | `claim_flags_deny_only` | USE_FOR_DENY_ONLY flag value = 0x0004 | ss11.17 line 7684 | Cargo |
| 414 | `claim_flags_disabled` | DISABLED flag value = 0x0010 | ss11.17 line 7685 | Cargo |
| 415 | `claim_attributes_map_case_insensitive` | CLAIM_ATTRIBUTES_MAP lookup is case-insensitive by default | ss11.17 lines 7696-7698 | Cargo |

---

## 24. Input Validation (lines 6101-6133)

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 416 | `input_identification_token_denied` | Impersonation token at Identification level returns ERROR_ACCESS_DENIED | ss11.17 lines 6108-6110 | Cargo |
| 417 | `input_anonymous_token_allowed` | Anonymous impersonation token proceeds through pipeline (NOT blocked) | ss11.17 lines 6017-6021 | Cargo |
| 418 | `input_null_sd_error` | Null SD returns ERROR_INVALID_PARAMETER | ss11.17 lines 6113-6114 | Cargo |
| 419 | `input_sd_no_owner_error` | SD without owner returns ERROR_INVALID_SECURITY_DESCR | ss11.17 line 6115 | Cargo |
| 420 | `input_sd_no_group_error` | SD without group returns ERROR_INVALID_SECURITY_DESCR | ss11.17 line 6115 | Cargo |
| 421 | `input_empty_tree_error` | Empty object_tree returns ERROR_INVALID_PARAMETER | ss11.17 lines 6118-6119 | Cargo |
| 422 | `input_tree_root_not_level_zero_error` | Tree with root not at level 0 returns ERROR_INVALID_PARAMETER | ss11.17 lines 6120-6121 | Cargo |
| 423 | `input_tree_negative_level_error` | Tree with negative level returns ERROR_INVALID_PARAMETER | ss11.17 lines 6124-6125 | Cargo |
| 424 | `input_tree_multiple_roots_error` | Tree with multiple level-0 nodes returns ERROR_INVALID_PARAMETER | ss11.17 lines 6126-6129 | Cargo |
| 425 | `input_tree_level_gap_error` | Tree with level gap (node at level 3 following level 1) returns ERROR_INVALID_PARAMETER | ss11.17 line 6130-6131 | Cargo |
| 426 | `input_tree_duplicate_guids_error` | Tree with duplicate GUIDs returns ERROR_INVALID_PARAMETER | ss11.17 lines 6132-6133 | Cargo |

---

## 25. Provium Tests (Require Booted KACS Kernel)

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 427 | `provium_restricted_token_file_open` | File open with restricted token: access is intersection of normal and restricted pass | ss11.7 | Provium |
| 428 | `provium_write_restricted_token_read_passes` | Write-restricted token: read access passes without restriction | ss11.7 | Provium |
| 429 | `provium_write_restricted_token_write_restricted` | Write-restricted token: write access requires both passes | ss11.7 | Provium |
| 430 | `provium_confinement_blocks_ungranted_file` | Confined process cannot open file lacking ACE for confinement SID | ss11.14 | Provium |
| 431 | `provium_confinement_allows_granted_file` | Confined process can open file with ACE for confinement SID | ss11.14 | Provium |
| 432 | `provium_confinement_privilege_no_bypass` | SeBackupPrivilege does not bypass confinement on file open | ss11.14 | Provium |
| 433 | `provium_confinement_exempt_bypasses` | Token with confinement_exempt=true bypasses confinement | ss11.14 | Provium |
| 434 | `provium_take_ownership_overrides_dacl_deny` | SeTakeOwnershipPrivilege grants WRITE_OWNER despite DACL deny | ss11.6 | Provium |
| 435 | `provium_take_ownership_blocked_by_mic` | SeTakeOwnershipPrivilege does not override MIC block on WRITE_OWNER | ss11.6/11.13 | Provium |
| 436 | `provium_take_ownership_blocked_by_pip` | SeTakeOwnershipPrivilege does not override PIP block on WRITE_OWNER | ss11.6/11.15 | Provium |
| 437 | `provium_cap_restricts_file_access` | Central Access Policy further restricts file access beyond DACL | ss11.16 | Provium |
| 438 | `provium_cap_recovery_on_missing_policy` | Missing CAP uses recovery policy (admin/SYSTEM/owner can access) | ss11.16 | Provium |
| 439 | `provium_cap_staging_logged` | CAP staged vs effective difference is logged | ss11.16 | Provium |
| 440 | `provium_conditional_ace_allow_true` | Callback allow ACE with TRUE condition grants access via file open | ss11.12 | Provium |
| 441 | `provium_conditional_ace_allow_unknown_denies` | Callback allow ACE with UNKNOWN condition denies access (missing claim) | ss11.12 | Provium |
| 442 | `provium_conditional_ace_deny_unknown_denies` | Callback deny ACE with UNKNOWN condition denies access | ss11.12 | Provium |
| 443 | `provium_mic_no_write_up` | Low-integrity process cannot write to Medium-integrity file | ss11.13 | Provium |
| 444 | `provium_mic_dominant_bypasses` | High-integrity process writes to Medium-integrity file normally | ss11.13 | Provium |
| 445 | `provium_pip_non_dominant_blocked` | Non-PIP process cannot access PIP-protected object | ss11.15 | Provium |
| 446 | `provium_pip_dominant_allowed` | PIP-dominant process accesses PIP-protected object normally | ss11.15 | Provium |
| 447 | `provium_pip_revokes_privileges` | PIP strips SeBackupPrivilege-granted read from non-dominant process | ss11.15 | Provium |
| 448 | `provium_zero_desired_succeeds` | kacs_access_check with desired=0 returns success | ss11.1 | Provium |
| 449 | `provium_maximum_allowed_returns_full_grant` | kacs_access_check with MAXIMUM_ALLOWED returns accumulated grant mask | ss11.5 | Provium |
| 450 | `provium_maximum_allowed_zero_grant_succeeds` | kacs_access_check with MAXIMUM_ALLOWED and nothing grantable returns success with granted=0 | ss11.5 | Provium |
| 451 | `provium_identification_token_denied` | Impersonation at Identification level: access check returns ACCESS_DENIED | ss12.1 | Provium |
| 452 | `provium_anonymous_token_proceeds` | Anonymous impersonation token proceeds through pipeline (S-1-5-7) | ss12.1 | Provium |
| 453 | `provium_null_dacl_grants_all` | File with NULL DACL: all rights granted regardless of caller identity | ss11.3 | Provium |
| 454 | `provium_empty_dacl_only_owner_implicit` | File with empty DACL: only owner gets READ_CONTROL/WRITE_DAC | ss11.3/11.4 | Provium |
| 455 | `provium_owner_rights_ace_suppresses_implicit` | OWNER RIGHTS ACE in DACL suppresses owner's implicit rights | ss11.4 | Provium |
| 456 | `provium_access_audit_event_emitted` | SYSTEM_AUDIT ACE causes audit event emission on matching access | ss11.10 | Provium |
| 457 | `provium_continuous_audit_mask_on_handle` | SYSTEM_ALARM ACE produces continuous audit mask on opened handle | ss11.10 | Provium |
| 458 | `provium_privilege_use_audit_emitted` | Privilege-granted access emits privilege-use audit event | ss11.10 | Provium |
| 459 | `provium_resource_attribute_extraction` | Resource attributes parsed from SACL and available to conditional ACEs | ss11.11 | Provium |
| 460 | `provium_result_list_per_property` | AccessCheckResultList returns per-node verdicts for object tree | ss11.1 | Provium |

---

**Summary:** 460 total tests extracted.
- **426 Cargo tests** (pure evaluation logic, data structures, conditional expression parsing, comparison operators, three-value logic, tree helpers, SID matching, claim resolution, all merge/intersection algorithms)
- **34 Provium tests** (syscalls, LSM hooks, file operations, process management, credential lifecycle, audit event emission, handle-level behavior)


---

# Section 12: Impersonation + Section 13: Process Integrity Protection

## Section 12: Impersonation

### 12.1 Impersonation Levels

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 1 | `anonymous_level_token_contains_only_anonymous_sid` | When impersonation level is Anonymous, `kacs_impersonate_peer` and `kacs_open_peer_token` return a token containing only the Anonymous SID (`S-1-5-7`) -- no user SID, no groups, no privileges. | 12.1, 12.3 | Provium |
| 2 | `anonymous_level_hides_client_identity` | At Anonymous level, both `kacs_impersonate_peer` and `kacs_open_peer_token` return a token that does not contain the client's actual user SID, group SIDs, or privileges. | 12.1, 12.3 | Provium |
| 3 | `identification_level_allows_sid_query` | A server impersonating an Identification-level token can read the client's SIDs and query their groups. | 12.1 | Provium |
| 4 | `identification_level_blocks_access_check` | An Identification-level impersonation token cannot be used for AccessCheck against resources. A file open under Identification-level impersonation fails. | 12.1 | Provium |
| 5 | `impersonation_level_allows_local_file_access` | A server impersonating at Impersonation level can open files and the access check evaluates against the client's identity. | 12.1 | Provium |
| 6 | `impersonation_level_cascades_across_local_ipc` | If service A impersonates client B at Impersonation level and connects to local service C, service C sees client B's identity (identity cascades freely across local IPC). | 12.1 | Provium |
| 7 | `delegation_level_identical_to_impersonation_locally` | For local operations, Delegation-level behaves identically to Impersonation-level: file access, registry reads, and local IPC connections all evaluate against the client's identity. | 12.1 | Provium |
| 8 | `delegation_level_cascades_across_local_ipc` | Identity cascades across local IPC at Delegation level, same as Impersonation level. | 12.1 | Provium |
| 9 | `delegation_level_flag_on_token` | A Delegation-level impersonation token carries a flag indicating cross-machine Kerberos delegation is authorized. An Impersonation-level token does not carry this flag. | 12.1, 12.6 | Cargo |
| 10 | `default_impersonation_level_is_impersonation` | If the client does not call `kacs_set_impersonation_level`, the default level on the socket is Impersonation. | 12.1 | Provium |
| 11 | `client_can_set_level_to_anonymous` | The client can explicitly set the impersonation level to Anonymous via `kacs_set_impersonation_level` before `connect()`. | 12.1 | Provium |
| 12 | `client_can_set_level_to_identification` | The client can explicitly set the impersonation level to Identification via `kacs_set_impersonation_level` before `connect()`. | 12.1 | Provium |
| 13 | `client_can_set_level_to_delegation` | The client can explicitly set the impersonation level to Delegation via `kacs_set_impersonation_level` before `connect()`. | 12.1 | Provium |
| 14 | `impersonation_level_ordering` | The four levels are ordered: Anonymous < Identification < Impersonation < Delegation. | 12.1 | Cargo |

### 12.2 The Two Gates

#### Identity Gate

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 15 | `identity_gate_same_user_same_restriction_passes` | If the server's primary token and client's token share the same user SID, and both are either restricted or both unrestricted, the identity gate passes. | 12.2 | Cargo |
| 16 | `identity_gate_same_user_restricted_vs_unrestricted_fails` | If the server and client share the same user SID but the server has a restricted token while the client has an unrestricted token (or vice versa), the identity gate fails. | 12.2 | Cargo |
| 17 | `identity_gate_restricted_cannot_impersonate_unrestricted_same_user` | A restricted (sandboxed) token cannot impersonate an unrestricted token of the same user -- prevents sandbox escape. | 12.2 | Provium |
| 18 | `identity_gate_se_impersonate_privilege_passes` | If the server's primary token holds `SeImpersonatePrivilege` and it is enabled, the identity gate passes regardless of user SID match. | 12.2 | Cargo |
| 19 | `identity_gate_se_impersonate_disabled_fails` | If the server holds `SeImpersonatePrivilege` but it is not enabled, the identity gate fails (treated as if privilege is absent). | 12.2 | Cargo |
| 20 | `identity_gate_failure_caps_to_identification` | If neither same-user-same-restriction nor SeImpersonatePrivilege holds, impersonation level is silently capped to Identification. No error is returned; the call succeeds. | 12.2 | Provium |
| 21 | `identity_gate_failure_no_error_returned` | When the identity gate fails, `kacs_impersonate_peer` succeeds (returns success), but the resulting token is Identification-level regardless of client's permitted level. | 12.2 | Provium |
| 22 | `identity_gate_checks_primary_token_not_effective` | The identity gate is checked against the server's primary token (`real_cred`), not the effective/impersonation token. If the server is currently impersonating, its primary identity governs the gate. | 12.2 | Provium |

#### Integrity Ceiling

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 23 | `integrity_ceiling_client_leq_server_passes` | If the client's token integrity level is less than or equal to the server's primary token integrity level, the integrity ceiling passes. | 12.2 | Cargo |
| 24 | `integrity_ceiling_client_gt_server_caps_to_identification` | If the client's token integrity level is greater than the server's primary token integrity level, the effective level is capped to Identification. | 12.2 | Cargo |
| 25 | `integrity_ceiling_medium_server_low_client_passes` | A Medium-integrity server can impersonate a Low-integrity client at full level. | 12.2 | Cargo |
| 26 | `integrity_ceiling_medium_server_medium_client_passes` | A Medium-integrity server can impersonate a Medium-integrity client at full level. | 12.2 | Cargo |
| 27 | `integrity_ceiling_medium_server_high_client_fails` | A Medium-integrity server cannot impersonate a High-integrity client at Impersonation level -- capped to Identification. | 12.2 | Cargo |
| 28 | `integrity_ceiling_not_bypassed_by_privilege` | `SeImpersonatePrivilege` does not bypass the integrity ceiling. A privileged Medium-integrity server impersonating a High-integrity token is still capped to Identification. | 12.2 | Cargo |
| 29 | `integrity_ceiling_checks_primary_token_not_effective` | The integrity ceiling is checked against the server's primary token, not the effective/impersonation token. | 12.2 | Provium |
| 30 | `integrity_ceiling_unconditionally_enforced` | The integrity ceiling is always enforced, regardless of any privileges held. Even SYSTEM-integrity services cannot impersonate above their own integrity level. | 12.2 | Cargo |

#### Gate Composition

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 31 | `gate_composition_both_pass_preserves_client_level` | When both gates pass, the effective impersonation level equals the level the client set on the socket. | 12.2 | Cargo |
| 32 | `gate_composition_identity_fails_caps_to_identification` | When the identity gate fails but integrity ceiling passes, effective level is Identification. | 12.2 | Cargo |
| 33 | `gate_composition_integrity_fails_caps_to_identification` | When the identity gate passes but integrity ceiling fails, effective level is Identification. | 12.2 | Cargo |
| 34 | `gate_composition_both_fail_caps_to_identification` | When both gates fail, effective level is Identification. | 12.2 | Cargo |
| 35 | `gate_composition_starts_from_client_level` | The effective level computation starts with the level the client set, not a fixed maximum. If the client set Identification, both gates passing still yields Identification. | 12.2 | Cargo |
| 36 | `gate_composition_never_escalates` | The two gates can only reduce the impersonation level, never increase it above what the client set. | 12.2 | Cargo |
| 37 | `gate_composition_privilege_passes_identity_but_integrity_still_caps` | A server with SeImpersonatePrivilege (identity gate passes) at Medium integrity, impersonating a High-integrity client (integrity ceiling fails): effective level is Identification. | 12.2 | Cargo |

### 12.3 Anonymous Semantics

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 38 | `anonymous_socket_captures_no_real_identity` | When the client sets Anonymous level, the socket's LSM blob stores a token containing only the Anonymous SID; the client's actual user SID, groups, and privileges are not recorded. | 12.3 | Provium |
| 39 | `anonymous_no_api_bypasses_client_choice` | There is no API that bypasses the client's Anonymous choice. If the client chooses Anonymous, the server cannot discover their identity through any mechanism. | 12.3 | Provium |
| 40 | `anonymous_impersonation_skips_both_gates` | Any thread can impersonate the Anonymous identity without passing either the identity gate or the integrity ceiling. | 12.3 | Provium |
| 41 | `anonymous_impersonation_no_privilege_needed` | Impersonating Anonymous requires no privilege (no SeImpersonatePrivilege needed). | 12.3 | Provium |
| 42 | `anonymous_token_access_limited_to_anonymous_sid_and_everyone` | An Anonymous token has no access rights beyond what is explicitly granted to the Anonymous SID or Everyone. | 12.3 | Cargo |

### 12.4 The Impersonation Lifecycle

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 43 | `lifecycle_client_sets_level_before_connect` | The impersonation level must be set via `kacs_set_impersonation_level` before `connect()`. | 12.4 | Provium |
| 44 | `lifecycle_identity_capture_at_connect_hook` | At `unix_stream_connect`, the LSM hook captures the client thread's effective credential and the socket's max impersonation level and stores the result on the socket's LSM blob. | 12.4 | Provium |
| 45 | `lifecycle_anonymous_capture_stores_anonymous_token` | If the socket level is Anonymous, identity capture stores a token containing only `S-1-5-7` on the socket blob. | 12.4 | Provium |
| 46 | `lifecycle_impersonation_capture_stores_effective_token` | For Impersonation or Delegation level, identity capture stores the connecting thread's effective token. If the thread is itself impersonating, the impersonated identity flows through. | 12.4 | Provium |
| 47 | `lifecycle_identity_cascades_through_impersonating_connector` | If a connecting thread is itself impersonating client X, the downstream socket captures client X's identity (not the connector's primary identity), enabling identity cascade. | 12.4 | Provium |
| 48 | `lifecycle_identification_capture_tagged` | For Identification level, the thread's effective token is stored but tagged at Identification level -- downstream server can inspect but not act as client. | 12.4 | Provium |
| 49 | `lifecycle_impersonate_peer_evaluates_gates` | `kacs_impersonate_peer` retrieves the stored token from the socket blob and evaluates both gates against the server thread's primary token. | 12.4 | Provium |
| 50 | `lifecycle_effective_level_is_minimum` | The effective impersonation level is the minimum of the stored level and whatever the gates permit. | 12.4 | Cargo |
| 51 | `lifecycle_override_creds_installs_impersonation` | After gate evaluation, `override_creds()` installs the impersonation token on the thread at the resulting level. | 12.4 | Provium |
| 52 | `lifecycle_access_check_uses_impersonation_token` | All AccessCheck evaluations after impersonation use the impersonation token. | 12.4 | Provium |
| 53 | `lifecycle_mic_uses_impersonation_integrity` | MIC uses the impersonation token's integrity level (not the primary token's). | 12.4 | Provium |
| 54 | `lifecycle_pip_uses_psb_not_token` | PIP uses the PSB (unchanged by impersonation), not the impersonation token. | 12.4 | Provium |
| 55 | `lifecycle_revert_restores_primary` | `kacs_revert()` restores the thread's `cred` to `real_cred`, returning to the service identity. | 12.4 | Provium |
| 56 | `lifecycle_revert_noop_when_not_impersonating` | `kacs_revert()` is a no-op if the thread is not currently impersonating. | 12.4 | Provium |
| 57 | `lifecycle_double_impersonation_replaces` | If a thread calls `kacs_impersonate_peer` while already impersonating, the kernel internally reverts and re-impersonates. The new impersonation replaces the old one. | 12.4 | Provium |
| 58 | `lifecycle_double_impersonation_gates_use_primary` | During double impersonation, the gates are evaluated against the primary token (unaffected by previous impersonation), so the result is correct regardless of old impersonation. | 12.4 | Provium |

### 12.5 Interaction with MIC and PIP

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 59 | `mic_uses_effective_token_under_impersonation` | MIC in AccessCheck compares the effective (impersonation) token's integrity level against the object's mandatory label, not the primary token's. | 12.5 | Provium |
| 60 | `mic_impersonation_lowers_not_raises_integrity` | Because of the integrity ceiling, the effective token's integrity is always <= the primary token's integrity. A thread can never hold an impersonation token with higher integrity than its primary. | 12.5 | Cargo |
| 61 | `pip_reads_psb_not_effective_token` | PIP enforcement uses pip_type and pip_trust from the PSB, not from the impersonation token. | 12.5 | Provium |
| 62 | `pip_immune_to_impersonation` | Impersonating a token carrying higher PIP values does not change the process's PIP enforcement. The PSB is fixed and immune to impersonation. | 12.5 | Provium |
| 63 | `high_integrity_service_impersonating_low_client_gets_low_mic` | A High-integrity service impersonating a Low-integrity client: MIC evaluates at Low integrity (the client's), not High (the server's). | 12.5 | Provium |

### 12.6 Delegation and the Network Boundary

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 64 | `delegation_token_carries_kerberos_authorization` | A Delegation-level impersonation token carries the authorization for the server to forward the client's identity to services on other machines. | 12.6 | Cargo |
| 65 | `impersonation_token_confined_to_local` | An Impersonation-level token is confined to the local machine -- it does not carry Kerberos credential forwarding authorization. | 12.6 | Cargo |
| 66 | `kacs_tracks_level_authd_acts_on_it` | KACS tracks the impersonation level on the token and socket. KACS has no Kerberos or network awareness -- the level is a flag that authd interprets. | 12.6 | Cargo |

### 12.7 SeImpersonatePrivilege

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 67 | `se_impersonate_privilege_allows_different_user` | With `SeImpersonatePrivilege` enabled, a service can impersonate tokens with different user SIDs at Impersonation level (assuming integrity ceiling passes). | 12.7 | Provium |
| 68 | `without_se_impersonate_privilege_only_same_user` | Without `SeImpersonatePrivilege`, a process can only impersonate tokens that match its own user SID (and restriction status). | 12.7 | Provium |
| 69 | `se_impersonate_checked_against_primary_token` | The privilege is checked against the server's primary token (`real_cred`), not the effective/impersonation token. | 12.7 | Cargo |
| 70 | `se_impersonate_does_not_bypass_integrity_ceiling` | `SeImpersonatePrivilege` bypasses only the identity gate. It does not bypass the integrity ceiling. A Medium-integrity service with the privilege cannot impersonate a High-integrity token at Impersonation level. | 12.7 | Cargo |
| 71 | `se_impersonate_must_be_enabled` | The privilege must be enabled at the time of the impersonation call. Holding but not enabling `SeImpersonatePrivilege` fails the identity gate. | 12.7 | Cargo |
| 72 | `se_impersonate_exercise_recorded_in_privileges_used` | When `SeImpersonatePrivilege` is exercised, it is recorded in the token's `privileges_used` field. | 12.7 | Cargo |
| 73 | `se_impersonate_exercise_emits_audit_event` | When `SeImpersonatePrivilege` is exercised, an audit event is emitted. | 12.7 | Provium |
| 74 | `se_impersonate_during_double_impersonation_checks_primary` | A thread already impersonating client A tries to impersonate client B: the privilege check uses the server's primary token, not client A's token. Prevents leveraging impersonated privileges. | 12.7 | Provium |

---

## Section 13: Process Integrity Protection

### 13.1 The Dominance Check

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 75 | `pip_dominance_requires_both_dimensions` | `pip_dominates(caller, target)` returns true iff `caller.pip_type >= target.pip_type AND caller.pip_trust >= target.pip_trust`. Both dimensions must pass. | 13.1 | Cargo |
| 76 | `pip_dominance_type_ge_trust_ge` | A caller with pip_type=Protected, pip_trust=5 dominates a target with pip_type=Protected, pip_trust=3. | 13.1 | Cargo |
| 77 | `pip_dominance_fails_if_type_lt` | A caller with pip_type=None dominates nothing with pip_type=Protected, regardless of pip_trust values. | 13.1 | Cargo |
| 78 | `pip_dominance_fails_if_trust_lt` | A caller with pip_type=Protected, pip_trust=3 does not dominate a target with pip_type=Protected, pip_trust=5 (trust dimension fails). | 13.1 | Cargo |
| 79 | `pip_none_target_trivially_dominated` | If the target has `pip_type = None`, dominance is trivially true for any caller -- unprotected processes are accessible to everyone. | 13.1 | Cargo |
| 80 | `pip_isolation_is_binary` | Process isolation is binary: dominate or don't. There is no partial access (no "can signal but not read memory" granularity at the process isolation level). | 13.1 | Cargo |
| 81 | `pip_dominance_equal_values_passes` | A caller with identical pip_type and pip_trust to the target dominates the target (>= on both dimensions). | 13.1 | Cargo |

### 13.2 Enforcement Points

#### ptrace

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 82 | `pip_ptrace_dominant_allowed` | A process that dominates the target can ptrace (attach, read, etc.) the target. | 13.2 | Provium |
| 83 | `pip_ptrace_non_dominant_denied` | A process that does not dominate the target receives `-EACCES` on ptrace, regardless of ptrace mode. | 13.2 | Provium |
| 84 | `pip_ptrace_se_debug_does_not_bypass` | `SeDebugPrivilege` does not bypass the PIP ptrace check. A process needs both the privilege (to bypass SD) AND PIP dominance (to bypass process isolation). | 13.2 | Provium |
| 85 | `pip_ptrace_se_debug_without_dominance_denied` | A process with SeDebugPrivilege but without PIP dominance cannot ptrace a PIP-protected process. | 13.2 | Provium |

#### Process Memory Access

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 86 | `pip_proc_mem_non_dominant_denied` | Reading `/proc/pid/mem` of a PIP-protected process from a non-dominant process is denied. | 13.2 | Provium |
| 87 | `pip_process_vm_readv_non_dominant_denied` | `process_vm_readv()` against a PIP-protected process from a non-dominant process is denied. | 13.2 | Provium |
| 88 | `pip_process_vm_writev_non_dominant_denied` | `process_vm_writev()` against a PIP-protected process from a non-dominant process is denied. | 13.2 | Provium |
| 89 | `pip_proc_mem_dominant_allowed` | A dominant process can read `/proc/pid/mem` of a PIP-protected target. | 13.2 | Provium |

#### Signal Delivery

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 90 | `pip_signal_non_dominant_denied` | A non-dominant process cannot send any signal to a PIP-protected process; `kill()` returns `-EACCES`. | 13.2 | Provium |
| 91 | `pip_signal_all_signals_blocked_uniformly` | All signals are blocked uniformly for non-dominant callers -- no distinction between SIGTERM, SIGKILL, SIGSTOP, etc. | 13.2 | Provium |
| 92 | `pip_signal_dominant_allowed` | A dominant process (e.g., peinit) can send signals to PIP-protected processes. | 13.2 | Provium |
| 93 | `pip_signal_peinit_can_signal_all` | peinit (highest trust level) can signal any PIP-protected process because it dominates all of them. | 13.2 | Provium |
| 94 | `pip_signal_sigterm_blocked_non_dominant` | SIGTERM to a PIP-protected process from a non-dominant process is denied. | 13.2 | Provium |
| 95 | `pip_signal_sigkill_blocked_non_dominant` | SIGKILL to a PIP-protected process from a non-dominant process is denied. | 13.2 | Provium |
| 96 | `pip_signal_sigstop_blocked_non_dominant` | SIGSTOP to a PIP-protected process from a non-dominant process is denied. | 13.2 | Provium |

#### /proc Metadata

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 97 | `pip_proc_cmdline_non_dominant_denied` | A non-dominant process cannot read `/proc/pid/cmdline` of a PIP-protected process (returns `-EACCES`). | 13.2 | Provium |
| 98 | `pip_proc_status_non_dominant_denied` | A non-dominant process cannot read `/proc/pid/status` of a PIP-protected process. | 13.2 | Provium |
| 99 | `pip_proc_stat_non_dominant_denied` | A non-dominant process cannot read `/proc/pid/stat` of a PIP-protected process. | 13.2 | Provium |
| 100 | `pip_proc_io_non_dominant_denied` | A non-dominant process cannot read `/proc/pid/io` of a PIP-protected process. | 13.2 | Provium |
| 101 | `pip_proc_cgroup_non_dominant_denied` | A non-dominant process cannot read `/proc/pid/cgroup` of a PIP-protected process. | 13.2 | Provium |
| 102 | `pip_proc_maps_non_dominant_denied` | A non-dominant process cannot read `/proc/pid/maps` of a PIP-protected process. | 13.2 | Provium |
| 103 | `pip_proc_environ_non_dominant_denied` | A non-dominant process cannot read `/proc/pid/environ` of a PIP-protected process. | 13.2 | Provium |
| 104 | `pip_proc_fd_non_dominant_denied` | A non-dominant process cannot read `/proc/pid/fd/` of a PIP-protected process. | 13.2 | Provium |
| 105 | `pip_proc_metadata_dominant_allowed` | A dominant process can read all `/proc/pid/` metadata of a PIP-protected target. | 13.2 | Provium |
| 106 | `pip_proc_pid_visible_in_directory_listing` | The PID directory is still visible in `ls /proc` (via `getdents`) even for PIP-protected processes -- only the contents are inaccessible, not the PID itself. | 13.2 | Provium |
| 107 | `pip_proc_not_faceable` | `/proc` is not FACSable -- no SDs can be attached to procfs entries. PIP enforcement on /proc is a direct kernel check, not an AccessCheck evaluation. | 13.2 | Provium |

#### /dev/mem and /dev/kmem

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 108 | `strict_devmem_enabled` | Peios builds with `CONFIG_STRICT_DEVMEM=y` -- physical RAM is inaccessible through `/dev/mem`. | 13.2 | Provium |
| 109 | `dev_mem_restricted_sd` | FACS places a restrictive SD on `/dev/mem` and `/dev/kmem` that limits access to SYSTEM with appropriate privileges. | 13.2 | Provium |

### 13.3 What PIP Does Not Protect Against

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 110 | `pip_kernel_module_bypasses_pip` | A loaded kernel module runs in ring 0 and can bypass PIP entirely (design fact, not a test per se -- but validates that SeLoadDriverPrivilege is the ceiling). | 13.3 | Provium |
| 111 | `module_sig_force_enabled` | Kernel is built with `CONFIG_MODULE_SIG_FORCE=y` -- unsigned modules cannot load. | 13.3 | Provium |
| 112 | `se_load_driver_stripped_from_non_peinit` | `SeLoadDriverPrivilege` is stripped from all tokens except peinit's. Only peinit can load kernel modules. | 13.3 | Provium |

### 13.4 PIP and Impersonation

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 113 | `pip_process_isolation_uses_psb_under_impersonation` | When service A (Protected, trust 5) impersonates client B (whose token was created for a None-type process), process isolation checks still use service A's PSB. Service A can still signal/ptrace other PIP-protected processes it dominates. | 13.4 | Provium |
| 114 | `pip_impersonation_does_not_grant_process_protection` | If a None-type process impersonates a token created for a Protected-type process, the process's PSB is still None -- it cannot touch PIP-protected processes regardless of the impersonated token. | 13.4 | Provium |
| 115 | `pip_impersonation_ptrace_still_uses_psb` | A Protected service impersonating a None-type client can still ptrace PIP-protected targets it dominates (PSB governs, not impersonation token). | 13.4 | Provium |
| 116 | `pip_impersonation_signal_still_uses_psb` | A Protected service impersonating a None-type client can still signal PIP-protected targets it dominates. | 13.4 | Provium |

### 13.5 Coredumps

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 117 | `pip_protected_process_not_dumpable` | PIP-protected processes have the dumpable flag cleared at exec time (Option A). No core dump is generated on crash. | 13.5 | Provium |
| 118 | `pip_coredump_not_readable_by_non_dominant` | Core dumps of PIP-protected processes (if generated via Option B crash handler) must not be readable by non-dominant processes. | 13.5 | Provium |

---

## Summary

| Category | Cargo Tests | Provium Tests | Total |
|----------|------------|---------------|-------|
| 12.1 Impersonation Levels | 2 | 12 | 14 |
| 12.2 Two Gates (Identity) | 4 | 4 | 8 |
| 12.2 Two Gates (Integrity) | 6 | 2 | 8 |
| 12.2 Gate Composition | 7 | 0 | 7 |
| 12.3 Anonymous Semantics | 1 | 4 | 5 |
| 12.4 Impersonation Lifecycle | 1 | 15 | 16 |
| 12.5 MIC and PIP Interaction | 1 | 4 | 5 |
| 12.6 Delegation/Network | 3 | 0 | 3 |
| 12.7 SeImpersonatePrivilege | 5 | 3 | 8 |
| 13.1 Dominance Check | 7 | 0 | 7 |
| 13.2 ptrace | 0 | 4 | 4 |
| 13.2 Process Memory | 0 | 4 | 4 |
| 13.2 Signal Delivery | 0 | 7 | 7 |
| 13.2 /proc Metadata | 0 | 11 | 11 |
| 13.2 /dev/mem | 0 | 2 | 2 |
| 13.3 PIP Limits | 0 | 3 | 3 |
| 13.4 PIP + Impersonation | 0 | 4 | 4 |
| 13.5 Coredumps | 0 | 2 | 2 |
| **TOTAL** | **37** | **81** | **118** |

Key classification rationale:
- **Cargo tests** (37): Pure evaluation logic -- dominance check function, gate composition logic, impersonation level ordering, privilege state checks, token field assertions. All testable with data structures in userspace without a running kernel.
- **Provium tests** (81): Require LSM hooks firing, syscall behavior, procfs access, signal delivery, socket-based identity capture, `override_creds`/`revert_creds` lifecycle, kernel build configuration checks. All require a booted KACS kernel.


---

# Section 14: FACS (First Half)

## 1. KACS Open Syscall — Basic Semantics

| Test name | Assertion | Spec ref | Type |
|---|---|---|---|
| `kacs_open_read_data_grants_fmode_read` | kacs_open with FILE_READ_DATA in desired_access produces an fd with FMODE_READ | L9723, L11163 | Provium |
| `kacs_open_write_data_grants_fmode_write` | kacs_open with FILE_WRITE_DATA produces an fd with FMODE_WRITE | L9724, L11164 | Provium |
| `kacs_open_append_data_grants_fmode_write` | kacs_open with FILE_APPEND_DATA produces an fd with FMODE_WRITE | L9724, L11164 | Provium |
| `kacs_open_execute_alone_grants_fmode_exec` | kacs_open with only FILE_EXECUTE produces an fd with FMODE_EXEC (no data rights) | L9738, L11165 | Provium |
| `kacs_open_strict_mode_all_rights_required` | kacs_open fails if any bit in desired_access is denied by the SD | L9714, L11159 | Provium |
| `kacs_open_partial_deny_fails` | kacs_open requesting FILE_READ_DATA + WRITE_DAC fails if SD grants read but denies WRITE_DAC | L9714, L11159-11161 | Provium |
| `kacs_open_granted_mask_equals_requested` | On success, the fd's granted mask equals exactly the requested desired_access | L9713-9714 | Provium |
| `kacs_open_requires_at_least_one_data_or_execute_right` | kacs_open with only WRITE_DAC (no data/execute rights) fails because f_mode would be invalid | L9731-9734 | Provium |
| `kacs_open_read_data_satisfies_data_right_requirement` | kacs_open with FILE_READ_DATA + WRITE_DAC succeeds (FILE_READ_DATA satisfies the data-right minimum) | L9731-9734 | Provium |
| `kacs_open_execute_satisfies_data_right_requirement` | kacs_open with FILE_EXECUTE + READ_CONTROL succeeds (FILE_EXECUTE satisfies the minimum) | L9731-9734 | Provium |
| `kacs_open_metadata_only_rejected` | kacs_open with only READ_CONTROL or WRITE_DAC (no data/execute) returns error | L9765-9770 | Provium |
| `kacs_open_execute_only_no_read_data` | An execute-only handle cannot read file contents (read returns EACCES) | L9742-9744 | Provium |
| `kacs_open_execute_only_no_write_data` | An execute-only handle cannot write file contents | L9742-9744 | Provium |
| `kacs_open_execute_only_execveat_works` | An execute-only handle works with execveat(fd, "", ..., AT_EMPTY_PATH) | L9747-9749 | Provium |
| `kacs_open_directory_list_directory_maps_to_fmode_read` | kacs_open on a directory with FILE_LIST_DIRECTORY maps to FMODE_READ (bit alias with FILE_READ_DATA) | L9779-9787 | Provium |
| `kacs_open_directory_add_file_maps_to_fmode_write` | kacs_open on a directory with FILE_ADD_FILE maps to FMODE_WRITE (bit alias with FILE_WRITE_DATA) | L9781 | Provium |

## 2. Create Dispositions

| Test name | Assertion | Spec ref | Type |
|---|---|---|---|
| `disposition_file_open_exists_succeeds` | FILE_OPEN (1) on existing file returns fd successfully | L11120 | Provium |
| `disposition_file_open_missing_fails` | FILE_OPEN (1) on nonexistent file fails | L11120 | Provium |
| `disposition_file_create_exists_fails` | FILE_CREATE (2) on existing file fails | L11121 | Provium |
| `disposition_file_create_missing_creates` | FILE_CREATE (2) on nonexistent file creates it | L11121 | Provium |
| `disposition_file_open_if_exists_opens` | FILE_OPEN_IF (3) on existing file opens it | L11122 | Provium |
| `disposition_file_open_if_missing_creates` | FILE_OPEN_IF (3) on nonexistent file creates it | L11122 | Provium |
| `disposition_file_overwrite_exists_truncates` | FILE_OVERWRITE (4) on existing file truncates to zero, same inode | L11123, L11131 | Provium |
| `disposition_file_overwrite_missing_fails` | FILE_OVERWRITE (4) on nonexistent file fails | L11123 | Provium |
| `disposition_file_overwrite_requires_write_data` | FILE_OVERWRITE requires FILE_WRITE_DATA in desired_access | L11123 | Provium |
| `disposition_file_overwrite_if_exists_truncates` | FILE_OVERWRITE_IF (5) on existing file truncates to zero | L11124 | Provium |
| `disposition_file_overwrite_if_missing_creates` | FILE_OVERWRITE_IF (5) on nonexistent file creates it | L11124 | Provium |
| `disposition_file_overwrite_preserves_sd` | FILE_OVERWRITE preserves the existing file's SD (same inode) | L11131 | Provium |
| `disposition_file_overwrite_preserves_hardlinks` | FILE_OVERWRITE preserves existing hardlinks (same inode) | L11131 | Provium |
| `disposition_file_supersede_exists_creates_new_inode` | FILE_SUPERSEDE (0) on existing file deletes old inode, creates new inode | L11133-11134 | Provium |
| `disposition_file_supersede_missing_creates` | FILE_SUPERSEDE (0) on nonexistent file creates it | L11119 | Provium |
| `disposition_file_supersede_requires_delete_on_old` | FILE_SUPERSEDE requires DELETE on existing file or FILE_DELETE_CHILD on parent | L11134-11136 | Provium |
| `disposition_file_supersede_requires_add_file_on_parent` | FILE_SUPERSEDE requires FILE_ADD_FILE on parent directory | L11136-11137 | Provium |
| `disposition_file_supersede_old_handles_orphaned` | After FILE_SUPERSEDE, already-open fds reference the old (unlinked) inode | L11143-11145 | Provium |
| `disposition_file_supersede_atomic` | FILE_SUPERSEDE is atomic from userspace's perspective (holds inode_lock) | L11147-11154 | Provium |
| `disposition_file_supersede_new_sd_inherited` | FILE_SUPERSEDE with sd=NULL inherits SD from parent, not from old file | L11141-11142 | Provium |
| `disposition_file_supersede_explicit_sd` | FILE_SUPERSEDE with sd != NULL uses the caller-supplied SD (merged with parent inheritable ACEs) | L11139-11141 | Provium |
| `disposition_status_out_created` | status_out reports KACS_STATUS_CREATED when a new file is created | L11190 | Provium |
| `disposition_status_out_opened` | status_out reports KACS_STATUS_OPENED when an existing file is opened | L11191 | Provium |
| `disposition_status_out_overwritten` | status_out reports KACS_STATUS_OVERWRITTEN when existing file is truncated | L11192 | Provium |
| `disposition_status_out_superseded` | status_out reports KACS_STATUS_SUPERSEDED when existing file is superseded | L11193-11194 | Provium |
| `disposition_status_out_null_no_crash` | status_out = NULL does not crash; no status is reported | L11197 | Provium |

## 3. Legacy open() Compatibility — Core Rights Mapping

| Test name | Assertion | Spec ref | Type |
|---|---|---|---|
| `legacy_rdonly_core_read_data_plus_read_attrs` | O_RDONLY on regular file requires FILE_READ_DATA and FILE_READ_ATTRIBUTES as core | L8822 | Cargo (mapping logic) + Provium (end-to-end) |
| `legacy_wronly_core_write_data_plus_read_attrs` | O_WRONLY on regular file requires FILE_WRITE_DATA and FILE_READ_ATTRIBUTES as core | L8823 | Cargo + Provium |
| `legacy_rdwr_core_all_data_plus_read_attrs` | O_RDWR on regular file requires FILE_READ_DATA, FILE_WRITE_DATA, FILE_READ_ATTRIBUTES as core | L8824 | Cargo + Provium |
| `legacy_read_attrs_always_core` | FILE_READ_ATTRIBUTES is core for all legacy open modes | L8889-8893 | Cargo |
| `legacy_open_fails_if_read_attrs_denied` | Legacy open fails with EACCES if SD denies FILE_READ_ATTRIBUTES | L8889-8893 | Provium |
| `legacy_append_replaces_write_with_append` | O_APPEND replaces FILE_WRITE_DATA with FILE_APPEND_DATA in core | L8843 | Cargo |
| `legacy_append_rdonly_no_effect` | O_APPEND with O_RDONLY has no effect (no write right to replace) | L8863-8879 | Cargo |
| `legacy_trunc_adds_write_data` | O_TRUNC adds FILE_WRITE_DATA to core (truncation = overwrite) | L8844 | Cargo |
| `legacy_append_trunc_both_rights` | O_APPEND + O_TRUNC: core includes both FILE_APPEND_DATA and FILE_WRITE_DATA | L8873-8878 | Cargo |
| `legacy_accmode_3_regular_file_rejected` | Access mode 3 on regular files returns EINVAL | L8869-8870 | Provium |
| `legacy_accmode_3_directory_rejected` | Access mode 3 on directories returns EINVAL | L8884 | Provium |
| `legacy_accmode_3_device_allowed` | Access mode 3 on device nodes is allowed, sets KACS_FILE_IOCTL_ONLY | L8885-8887 | Provium |

## 4. Legacy open() — Directory Core Rights

| Test name | Assertion | Spec ref | Type |
|---|---|---|---|
| `legacy_dir_rdonly_core_read_attrs_traverse` | O_RDONLY on directory has core = FILE_READ_ATTRIBUTES + FILE_TRAVERSE | L8830-8831 | Cargo + Provium |
| `legacy_dir_core_no_list_directory` | Directory core does NOT include FILE_LIST_DIRECTORY | L8832 | Cargo |
| `legacy_dir_wronly_rejected` | O_WRONLY on directory returns EISDIR | L8856 | Provium |
| `legacy_dir_rdwr_rejected` | O_RDWR on directory returns EISDIR | L8856 | Provium |
| `legacy_dir_append_rejected` | O_APPEND on directory returns EISDIR | L8858 | Provium |
| `legacy_dir_trunc_rejected` | O_TRUNC on directory returns EISDIR | L8858 | Provium |
| `legacy_dir_open_without_list_succeeds` | Directory open O_RDONLY succeeds even if SD denies FILE_LIST_DIRECTORY (it is compat, not core) | L8835-8837 | Provium |
| `legacy_dir_readdir_fails_without_list` | readdir() on a directory fd fails with EACCES if FILE_LIST_DIRECTORY was not granted at open time | L8837 | Provium |
| `legacy_dir_fchdir_works_with_traverse` | fchdir() succeeds on directory fd that has FILE_TRAVERSE in granted mask | L8833-8834 | Provium |
| `legacy_dir_fstat_works_with_read_attrs` | fstat() succeeds on directory fd because FILE_READ_ATTRIBUTES is core | L8833-8834 | Provium |

## 5. Legacy open() — Compat Rights

| Test name | Assertion | Spec ref | Type |
|---|---|---|---|
| `compat_read_ea_granted_if_sd_allows` | FILE_READ_EA is in compat set; if SD grants it, fd carries it | L8909 | Provium |
| `compat_read_ea_omitted_if_denied` | FILE_READ_EA is silently omitted from granted mask if SD denies it | L8909 | Provium |
| `compat_read_control_granted_if_allowed` | READ_CONTROL is compat; if SD grants it, fd carries it | L8911 | Provium |
| `compat_write_attributes_granted_if_allowed` | FILE_WRITE_ATTRIBUTES is compat; granted if SD allows | L8912 | Provium |
| `compat_write_ea_granted_if_allowed` | FILE_WRITE_EA is compat; granted if SD allows | L8913 | Provium |
| `compat_write_dac_granted_if_allowed` | WRITE_DAC is compat; granted if SD allows | L8917 | Provium |
| `compat_write_owner_granted_if_allowed` | WRITE_OWNER is compat; granted if SD allows | L8918 | Provium |
| `compat_synchronize_granted_if_allowed` | SYNCHRONIZE is compat; granted if SD allows | L8919 | Provium |
| `compat_open_succeeds_without_compat_rights` | Legacy open() succeeds even if ALL compat rights are denied (only core matters) | L8955-8957 | Provium |
| `compat_dir_list_directory_in_compat` | FILE_LIST_DIRECTORY is compat for directory opens | L8920-8923 | Cargo + Provium |
| `compat_file_execute_in_compat` | FILE_EXECUTE is compat for regular file opens | L8924-8930 | Cargo + Provium |
| `compat_file_execute_enables_fexecve` | If SD grants FILE_EXECUTE, legacy O_RDONLY fd carries it and fexecve works | L8928-8930 | Provium |
| `compat_file_execute_denied_fexecve_fails` | If SD denies FILE_EXECUTE, fexecve on legacy O_RDONLY fd fails | L8930 | Provium |
| `compat_append_write_data_in_compat` | For O_APPEND opens, FILE_WRITE_DATA is in compat set (for ftruncate) | L8915 | Cargo |
| `compat_append_ftruncate_works_if_write_data_granted` | O_APPEND fd can ftruncate if SD grants FILE_WRITE_DATA | L8932-8940 | Provium |
| `compat_append_ftruncate_fails_if_write_data_denied` | O_APPEND fd cannot ftruncate if SD denies FILE_WRITE_DATA (append-only log pattern) | L8938-8940 | Provium |

## 6. Open-Time Flow (AccessCheck Modes)

| Test name | Assertion | Spec ref | Type |
|---|---|---|---|
| `legacy_open_accesscheck_subset_mode` | Legacy open uses subset mode: core|compat is requested, only core must be fully present | L8948-8963 | Cargo (mode logic) + Provium |
| `kacs_open_accesscheck_strict_mode` | kacs_open uses strict mode: (granted & requested) == requested or fail | L8960-8961 | Cargo + Provium |
| `legacy_open_granted_mask_is_actual_subset` | The fd's granted mask equals what the SD actually allowed, not the full core|compat request | L8956-8957 | Provium |
| `open_fd_is_complete_capability_snapshot` | The fd is a complete capability snapshot — no right is left undecided | L8967-8971 | Provium |

## 7. Handle Model — Granted Mask Immutability

| Test name | Assertion | Spec ref | Type |
|---|---|---|---|
| `granted_mask_immutable_after_open` | The fd's granted mask never changes after open, regardless of any action | L8675 | Provium |
| `sd_change_does_not_affect_open_handle` | Modifying the SD after open does not change existing handles' granted masks | L9022-9025 | Provium |
| `sd_change_next_open_uses_new_sd` | After SD modification, the NEXT open evaluates the new SD | L9024 | Provium |
| `sd_change_existing_handle_still_works` | An fd opened before SD change retains its original rights and can still operate | L9022-9025 | Provium |
| `sd_change_remove_right_existing_handle_keeps_it` | If a right is removed from the SD, existing handles with that right still work | L9022-9025 | Provium |
| `sd_change_add_right_existing_handle_lacks_it` | If a right is added to the SD, existing handles do NOT gain it retroactively | L9022-9025 | Provium |

## 8. Handle Model — Use-Time Semantics

| Test name | Assertion | Spec ref | Type |
|---|---|---|---|
| `use_time_read_requires_read_data` | read() requires FILE_READ_DATA in granted mask | L9002 | Provium |
| `use_time_append_write_requires_append_data` | Sequential write on O_APPEND fd requires FILE_APPEND_DATA | L9003-9004 | Provium |
| `use_time_positioned_overwrite_requires_write_data` | Positioned overwrite requires FILE_WRITE_DATA | L9005 | Provium |
| `use_time_append_only_allows_append_denies_overwrite` | Handle with FILE_APPEND_DATA but not FILE_WRITE_DATA: append allowed, pwrite denied | L9006-9007 | Provium |
| `use_time_fchmod_requires_write_dac` | fchmod requires WRITE_DAC in granted mask | L9008 | Provium |
| `use_time_fchown_requires_write_owner` | fchown requires WRITE_OWNER in granted mask | L9009 | Provium |
| `use_time_futimens_requires_write_attrs` | futimens requires FILE_WRITE_ATTRIBUTES in granted mask | L9010 | Provium |
| `use_time_checks_are_bitmask_not_accesscheck` | Use-time checks are bitmask tests, not full AccessCheck calls (performance assertion) | L9012-9014 | Cargo (unit test on the check function) |

## 9. Handle Acquisition / FD Transfer

| Test name | Assertion | Spec ref | Type |
|---|---|---|---|
| `dup_preserves_granted_mask` | dup()/dup3() preserves the granted mask | L9051 | Provium |
| `fork_preserves_granted_mask` | fork()/clone() child inherits fd with same granted mask | L9052 | Provium |
| `scm_rights_preserves_granted_mask` | SCM_RIGHTS transfer preserves the granted mask | L9053-9056 | Provium |
| `scm_rights_allowed_unconditionally` | security_file_receive allows SCM_RIGHTS unconditionally (fd is capability token) | L9055-9056 | Provium |
| `scm_rights_cross_identity_works` | SCM_RIGHTS to a different-identity process works; receiver exercises opener's rights | L9079-9081 | Provium |
| `pidfd_getfd_preserves_granted_mask` | pidfd_getfd() extracts fd with full granted mask | L9069-9071 | Provium |
| `pidfd_getfd_requires_process_dup_handle` | pidfd_getfd() requires PROCESS_DUP_HANDLE on target process SD | L9065-9066 | Provium |
| `exec_preserves_granted_mask_no_cloexec` | Fds without FD_CLOEXEC survive exec with same granted mask | L9072 | Provium |
| `compat_rights_delegable_via_dup` | Compat rights (e.g., WRITE_DAC from legacy open) are delegable via dup | L9973-9987 | Provium |
| `compat_rights_delegable_via_fork` | Compat rights are delegable via fork | L9973-9987 | Provium |
| `compat_rights_delegable_via_scm_rights` | Compat rights are delegable via SCM_RIGHTS to a different-identity process | L9973-9987 | Provium |

## 10. O_PATH Semantics

| Test name | Assertion | Spec ref | Type |
|---|---|---|---|
| `opath_no_granted_mask` | O_PATH fds carry no granted mask (not FACS-managed) | L9699, L9791 | Provium |
| `opath_security_file_open_does_not_fire` | security_file_open does not fire for O_PATH opens | L9791, L10008-10009 | Provium |
| `opath_fstat_allowed_unconditionally` | fstat() on O_PATH fd succeeds unconditionally regardless of SD | L9793-9794, L10014-10016 | Provium |
| `opath_fstatfs_allowed_unconditionally` | fstatfs() on O_PATH fd succeeds unconditionally | L9793-9794 | Provium |
| `opath_fchmod_denied` | fchmod() on O_PATH fd returns EBADF | L9795, L10024-10027 | Provium |
| `opath_fchown_denied` | fchown() on O_PATH fd returns EBADF | L10024-10027 | Provium |
| `opath_fgetxattr_denied` | fgetxattr() on O_PATH fd returns EBADF | L10024-10027 | Provium |
| `opath_ioctl_denied` | ioctl() on O_PATH fd returns EBADF | L10025-10027 | Provium |
| `opath_mmap_denied` | mmap() on O_PATH fd returns EBADF | L10025-10027 | Provium |
| `opath_fchdir_live_accesscheck_traverse` | fchdir() on O_PATH directory fd runs live AccessCheck for FILE_TRAVERSE | L9796-9797, L10020-10023 | Provium |
| `opath_fchdir_denied_if_traverse_denied` | fchdir() on O_PATH fd fails if SD denies FILE_TRAVERSE | L10020-10023 | Provium |
| `opath_execveat_runs_live_accesscheck` | execveat(O_PATH_fd, "", ..., AT_EMPTY_PATH) runs live AccessCheck for FILE_EXECUTE | L9798-9800, L10540-10544 | Provium |
| `opath_used_as_dirfd_for_at_syscalls` | O_PATH fd works as dirfd for *at() syscalls; target resolved with own hooks | L10017-10019 | Provium |
| `opath_bypasses_file_read_attributes` | fstat() on O_PATH bypasses FILE_READ_ATTRIBUTES requirement (accepted platform limitation) | L10041-10054 | Provium |
| `opath_kacs_get_sd_live_check` | kacs_get_sd on O_PATH fd performs live AccessCheck (not granted-mask check) | L9686-9687, L11251-11254 | Provium |
| `opath_kacs_set_sd_live_check` | kacs_set_sd on O_PATH fd performs live AccessCheck | L9773-9774 | Provium |

## 11. DAC Bypass

| Test name | Assertion | Spec ref | Type |
|---|---|---|---|
| `all_processes_have_cap_dac_override` | Every process has CAP_DAC_OVERRIDE in effective/permitted sets | L9131-9133 | Provium |
| `all_processes_have_cap_dac_read_search` | Every process has CAP_DAC_READ_SEARCH | L9135-9136 | Provium |
| `all_processes_have_cap_fowner` | Every process has CAP_FOWNER | L9137-9139 | Provium |
| `all_processes_have_cap_chown` | Every process has CAP_CHOWN | L9140-9142 | Provium |
| `dac_neutralized_lsm_always_fires` | With DAC bypass, LSM hooks always fire (DAC cannot pre-deny) | L9130, L9150-9151 | Provium |
| `capset_cannot_clear_dac_caps` | capset() attempting to clear any of the six implementation caps is denied | L9229-9234 | Provium |
| `prctl_cannot_drop_dac_from_bounding_set` | prctl(PR_CAPBSET_DROP) is denied for DAC bypass caps | L9236-9241 | Provium |
| `prctl_can_drop_non_implementation_caps` | prctl(PR_CAPBSET_DROP) for non-implementation caps (e.g., CAP_NET_RAW) is allowed | L9241-9242 | Provium |
| `prctl_ambient_raise_denied` | PR_CAP_AMBIENT raises are denied | L9237, L9244-9245 | Provium |
| `fork_preserves_dac_caps` | security_prepare_creds ensures DAC caps survive fork | L9176-9186 | Provium |
| `exec_preserves_dac_caps` | DAC caps survive exec (bprm_creds_for_exec reasserts them) | L9219-9227 | Provium |
| `exec_suppresses_file_capabilities` | File capabilities (security.capability xattr) are suppressed at exec | L9193-9196 | Provium |
| `exec_suppresses_setuid` | setuid credential elevation is suppressed at exec | L9197-9198 | Provium |
| `exec_suppresses_setgid` | setgid credential elevation is suppressed at exec | L9200 | Provium |

## 12. Execution Two-Layer Model

| Test name | Assertion | Spec ref | Type |
|---|---|---|---|
| `exec_requires_mode_bit_and_file_execute` | execve requires both at least one +x bit AND FILE_EXECUTE in SD | L10520-10521 | Provium |
| `exec_no_mode_bit_fails_despite_file_execute` | File without +x cannot be executed even if SD grants FILE_EXECUTE | L10521 | Provium |
| `exec_mode_bit_but_no_file_execute_fails` | File with +x but SD denies FILE_EXECUTE: exec fails | L10522-10523 | Provium |
| `mmap_prot_exec_no_mode_bit_required` | mmap(PROT_EXEC) does not require +x mode bit (only FILE_EXECUTE in SD) | L10523-10525 | Provium |
| `exec_mode_bit_live_check` | Execute mode-bit is checked live at exec time, not snapshotted at open | L10494-10497 | Provium |
| `exec_mode_bit_removed_after_open_blocks_exec` | If +x is removed after open, exec on that fd fails despite granted FILE_EXECUTE | L10494-10497 | Provium |

## 13. Append-Only Enforcement (Kernel Patches 1-4)

| Test name | Assertion | Spec ref | Type |
|---|---|---|---|
| `pwrite_denied_on_append_only_fd` | pwrite on fd with FILE_APPEND_DATA but not FILE_WRITE_DATA returns EPERM | L9288, L9953 | Provium |
| `pwritev_denied_on_append_only_fd` | pwritev on append-only fd returns EPERM | L9289, L9954 | Provium |
| `pwritev2_rwf_noappend_denied_on_append_only` | pwritev2 with RWF_NOAPPEND on append-only fd returns EPERM | L9291-9292, L9319-9320 | Provium |
| `pwritev2_rwf_append_allowed` | pwritev2 with RWF_APPEND is always allowed (it only restricts further) | L9321-9322 | Provium |
| `io_uring_positioned_write_denied_on_append_only` | io_uring SQE write with explicit offset on append-only fd fails | L9293-9298, L9955 | Provium |
| `aio_write_denied_on_append_only` | AIO write with offset on append-only fd returns EPERM | L9299-9302, L9956 | Provium |
| `writable_mmap_denied_on_append_only` | mmap PROT_WRITE + MAP_SHARED denied on append-only fd (prevents arbitrary byte writes) | L9278-9283, L10132 | Provium |
| `mprotect_upgrade_denied_on_append_only` | mprotect upgrade to PROT_WRITE denied on append-only fd | L9278-9283 | Provium |
| `fallocate_punch_hole_denied_on_append_only` | fallocate PUNCH_HOLE denied on append-only fd | L9276-9283, L9960 | Provium |
| `fallocate_zero_range_denied_on_append_only` | fallocate ZERO_RANGE denied on append-only fd | L9276-9283, L9960 | Provium |
| `fallocate_collapse_range_denied_on_append_only` | fallocate COLLAPSE_RANGE denied on append-only fd | L9276-9283, L9960 | Provium |
| `fallocate_insert_range_denied_on_append_only` | fallocate INSERT_RANGE denied on append-only fd | L9960 | Provium |
| `sequential_write_allowed_on_append_only` | Sequential write() on O_APPEND fd with FILE_APPEND_DATA succeeds | L9003-9004 | Provium |
| `file_write_data_superset_allows_append` | fd with FILE_WRITE_DATA (without FILE_APPEND_DATA) can do sequential append writes | L10114 | Provium |

## 14. fcntl Enforcement

| Test name | Assertion | Spec ref | Type |
|---|---|---|---|
| `fcntl_clear_append_denied_on_append_only` | F_SETFL clearing O_APPEND denied if fd has FILE_APPEND_DATA but not FILE_WRITE_DATA | L9312-9315, L10326-10327 | Provium |
| `fcntl_set_append_always_allowed` | F_SETFL setting O_APPEND is always allowed (privilege reduction) | L9316-9318, L10328-10331 | Provium |
| `fcntl_o_noatime_requires_write_attributes` | F_SETFL adding O_NOATIME requires FILE_WRITE_ATTRIBUTES in granted mask | L10325, L9424-9426 | Provium |
| `fcntl_f_setown_allowed` | F_SETOWN is allowed | L10332 | Provium |
| `fcntl_f_setsig_allowed` | F_SETSIG is allowed | L10332 | Provium |

## 15. access() / faccessat() Credential Semantics

| Test name | Assertion | Spec ref | Type |
|---|---|---|---|
| `access_uses_effective_token` | access() on Peios uses effective token, not real_cred (intentional POSIX redefinition) | L9324-9338 | Provium |
| `access_at_eaccess_is_noop` | AT_EACCESS is a no-op because effective is already the default | L9337-9338 | Provium |
| `access_impersonating_thread_uses_effective` | An impersonating thread's access() evaluates the impersonated (effective) token | L9333-9335 | Provium |

## 16. open_by_handle_at Enforcement

| Test name | Assertion | Spec ref | Type |
|---|---|---|---|
| `open_by_handle_at_requires_change_notify_privilege` | open_by_handle_at is gated behind SeChangeNotifyPrivilege | L9362-9363, L9958 | Provium |
| `open_by_handle_at_fails_without_privilege` | Process without SeChangeNotifyPrivilege cannot use open_by_handle_at | L9958 | Provium |
| `open_by_handle_at_still_checks_file_sd` | open_by_handle_at still performs normal AccessCheck on the target file | L9377-9379 | Provium |

## 17. SD Storage — xattr Layer

| Test name | Assertion | Spec ref | Type |
|---|---|---|---|
| `sd_stored_in_security_peios_sd_xattr` | SD is stored as self-relative binary blob in security.peios.sd xattr | L9483 | Provium |
| `sd_xattr_format_is_security_descriptor_relative` | The xattr value is raw SECURITY_DESCRIPTOR_RELATIVE, no wrapper/envelope | L9489-9490 | Cargo (parsing) + Provium |
| `sd_xattr_max_size_64kb` | The architectural maximum SD size is 64 KB (AclSize is u16) | L9491-9492 | Cargo |
| `ntfs_uses_system_ntfs_security_xattr` | On NTFS volumes, SD is stored in system.ntfs_security, not security.peios.sd | L9496-9498 | Provium |
| `ntfs_sd_roundtrips_to_windows_format` | SDs on NTFS use identical format (SECURITY_DESCRIPTOR_RELATIVE), no conversion needed | L9498-9502 | Cargo (format identity) |

## 18. SD xattr Protection

| Test name | Assertion | Spec ref | Type |
|---|---|---|---|
| `setxattr_sd_denied_unconditionally` | setxattr(security.peios.sd) is denied unconditionally (-EACCES) | L9545-9551 | Provium |
| `setxattr_ntfs_sd_denied_unconditionally` | setxattr(system.ntfs_security) is denied unconditionally | L9547 | Provium |
| `removexattr_sd_denied_unconditionally` | removexattr(security.peios.sd) is denied unconditionally (-EACCES) | L9556-9558 | Provium |
| `getxattr_sd_denied_unconditionally` | getxattr(security.peios.sd) is denied unconditionally (-EACCES) | L9565-9568 | Provium |
| `setxattr_posix_acl_access_denied` | setxattr(system.posix_acl_access) is denied unconditionally | L9577 | Provium |
| `setxattr_posix_acl_default_denied` | setxattr(system.posix_acl_default) is denied unconditionally | L9577 | Provium |
| `inode_set_acl_denied` | security_inode_set_acl denies POSIX ACL setting unconditionally | L10319-10320 | Provium |
| `no_privilege_overrides_sd_xattr_write` | No privilege, token, or capability can override the raw SD xattr write denial | L9551-9552 | Provium |
| `sd_cannot_be_detached_from_file` | An SD cannot be removed from its file via removexattr | L9558-9563 | Provium |
| `listxattr_unconditionally_allowed` | listxattr/flistxattr/llistxattr are allowed unconditionally (xattr names not sensitive) | L10314-10317 | Provium |

## 19. SD Set-Security Interface

| Test name | Assertion | Spec ref | Type |
|---|---|---|---|
| `set_sd_owner_requires_write_owner` | Setting owner requires WRITE_OWNER on the target | L9619 | Provium |
| `set_sd_group_requires_write_owner` | Setting group requires WRITE_OWNER | L9620 | Provium |
| `set_sd_dacl_requires_write_dac` | Setting DACL requires WRITE_DAC | L9621 | Provium |
| `set_sd_sacl_requires_access_system_security` | Setting SACL requires ACCESS_SYSTEM_SECURITY | L9622 | Provium |
| `set_sd_label_requires_write_owner` | Setting integrity label requires WRITE_OWNER | L9623 | Provium |
| `set_sd_merges_only_indicated_components` | set-security merges only the indicated components; unindicated components preserved | L9607-9609 | Provium |
| `set_sd_dacl_only_preserves_owner` | DACL-only update does not modify owner, group, or SACL | L9608-9609 | Provium |
| `set_sd_validates_blob_structurally` | The kernel validates the SD blob: parseable, well-formed ACEs, valid SIDs, size <= 64 KB | L9604-9605 | Provium |
| `set_sd_rejects_malformed_blob` | A malformed/truncated SD blob is rejected | L9604-9605 | Provium |
| `set_sd_se_restore_bypasses_access_check` | SeRestorePrivilege bypasses the access check entirely on set-security | L9635-9639 | Provium |
| `set_sd_owner_restricted_to_own_sid` | Without SeRestorePrivilege, new owner must be caller's own SID or a group with SE_GROUP_OWNER | L9642-9646 | Provium |
| `set_sd_owner_to_other_sid_denied` | Setting owner to an arbitrary SID without SeRestorePrivilege is denied | L9650-9652 | Provium |
| `set_sd_take_ownership_privilege` | SeTakeOwnershipPrivilege allows setting ownership to caller's own SID regardless of current SD | L9647-9648 | Provium |
| `set_sd_se_restore_allows_any_owner` | SeRestorePrivilege allows setting ownership to any arbitrary SID | L9649-9650 | Provium |
| `set_sd_bypasses_own_xattr_guard` | The set-security syscall writes via internal kernel path, bypassing security_inode_setxattr | L9667-9669 | Provium |
| `set_sd_concurrent_serialized` | Concurrent set-security calls on the same inode are serialized by the inode mutex | L9675-9676 | Provium |

## 20. Missing SDs

| Test name | Assertion | Spec ref | Type |
|---|---|---|---|
| `deny_mode_missing_sd_denies_all_access` | In deny mode, a file with no SD xattr denies all FACS-managed access | L9744-9746 | Provium |
| `deny_mode_missing_sd_no_accesscheck` | In deny mode, no AccessCheck is called for missing SD (immediate denial) | L9745-9746 | Provium |
| `deny_mode_missing_sd_traverse_exception` | In deny mode, SeChangeNotifyPrivilege bypasses traverse checks on directories with missing SDs | L9747-9751 | Provium |
| `deny_mode_opath_allowed_on_missing_sd` | O_PATH opens succeed on files with missing SDs (bypass security_file_open) | L9759-9766 | Provium |
| `deny_mode_repair_path_works` | open(O_PATH) + kacs_set_sd with SeRestorePrivilege can stamp SD onto file with no SD | L9768-9773 | Provium |
| `deny_mode_repair_traversal_through_missing_sd_dirs` | Repair path works even when entire directory tree has missing SDs (SeChangeNotifyPrivilege bypasses) | L9775-9782 | Provium |
| `synthesize_mode_generates_default_sd` | In synthesize mode, missing SD generates a default SD on the fly | L9784-9788 | Provium |
| `synthesize_mode_inherits_from_parent` | Synthesize mode: if parent has SD, inheritance algorithm runs as if creating a new file | L9792-9796 | Provium |
| `synthesize_mode_mount_template_fallback` | Synthesize mode: mount-level template used when no parent SD exists (mount root) | L9798-9800 | Provium |
| `synthesize_mode_persist_true_writes_xattr` | persist_synthesized=true writes the synthesized SD to security.peios.sd immediately | L9817-9820 | Provium |
| `synthesize_mode_persist_false_cache_only` | persist_synthesized=false caches SD in inode blob only, never writes to disk | L9822-9826 | Provium |
| `fat_always_synthesize_mount_template` | FAT/vfat always uses synthesize mode with mount-level template | L9835-9838 | Provium |

## 21. Corrupt SDs

| Test name | Assertion | Spec ref | Type |
|---|---|---|---|
| `corrupt_sd_denies_all_access` | A corrupt SD (truncated, malformed, etc.) denies all access | L9882, L9884 | Provium |
| `corrupt_sd_no_accesscheck` | Corrupt SD: AccessCheck is not called (fail-closed) | L9882-9883 | Provium |
| `corrupt_sd_not_treated_as_empty` | A truncated DACL must not be treated as empty (which would grant GENERIC_ALL) | L9885 | Provium |
| `corrupt_sd_emits_audit_event` | Corrupt SD encounter emits an audit event with file path, xattr size, parse failure reason | L9888-9893 | Provium |
| `corrupt_sd_audit_once_per_inode` | Audit event fires once per inode per cache population, not on every access | L9897 | Provium |
| `corrupt_sd_cached_sentinel` | Corrupt state is cached as a sentinel in i_security to avoid repeated xattr reads | L9897-9898 | Provium |
| `corrupt_sd_recovery_with_se_restore` | SeRestorePrivilege can overwrite a corrupt SD with a valid one | L9902-9907 | Provium |
| `corrupt_sd_parse_error_cases` | Various parse failures trigger corrupt SD: truncated blob, invalid ACE type, malformed SID, size mismatch, ACL size overflow | L9879-9880 | Cargo (parser) + Provium |

## 22. SD Inheritance on File/Directory Creation

| Test name | Assertion | Spec ref | Type |
|---|---|---|---|
| `inheritance_object_inherit_ace_flows_to_files` | An ACE with OBJECT_INHERIT_ACE on a directory is inherited by files created in that directory | L3538-3542 | Cargo (algorithm) + Provium |
| `inheritance_container_inherit_ace_flows_to_subdirs` | An ACE with CONTAINER_INHERIT_ACE is inherited by subdirectories | L3544-3547 | Cargo + Provium |
| `inheritance_object_inherit_on_container_becomes_inherit_only` | OI ACE inherited by a subdirectory becomes inherit-only (does not apply to the subdir itself) unless NP is set | L3541-3542 | Cargo |
| `inheritance_no_propagate_clears_flags` | NO_PROPAGATE_INHERIT_ACE clears OI and CI on the inherited copy (one-level inheritance) | L3549-3552 | Cargo |
| `inheritance_inherit_only_does_not_apply_to_self` | INHERIT_ONLY_ACE does not apply to the object it is attached to | L3554-3555 | Cargo |
| `inheritance_inherited_ace_flag_set` | INHERITED_ACE flag is set on ACEs that came from the parent | L3562-3566, L3647-3648 | Cargo |
| `inheritance_creator_owner_substitution` | CREATOR OWNER SID (S-1-3-0) is replaced with the creating principal's owner SID | L3584-3589 | Cargo + Provium |
| `inheritance_creator_group_substitution` | CREATOR GROUP SID (S-1-3-1) is replaced with the creator's primary group SID | L3591-3592 | Cargo + Provium |
| `inheritance_substitution_at_inheritance_time` | SID substitution happens at inheritance time, not evaluation time | L3594-3595 | Cargo |
| `inheritance_no_creator_sd_parent_inheritable` | No creator SD + parent has inheritable ACEs: new DACL is entirely inherited ACEs from parent | L3625-3628 | Cargo + Provium |
| `inheritance_no_creator_sd_no_parent_inheritable` | No creator SD + parent has no inheritable ACEs: new DACL is token's default DACL | L3630-3631 | Cargo + Provium |
| `inheritance_creator_sd_explicit_aces_preserved` | Creator SD with DACL: explicit ACEs (no INHERITED_ACE) are preserved | L3634-3635 | Cargo |
| `inheritance_creator_sd_unprotected_appends_parent` | Creator SD with unprotected DACL: parent inheritable ACEs appended after explicit ACEs | L3636-3638 | Cargo |
| `inheritance_creator_sd_protected_blocks_parent` | Creator SD with SE_DACL_PROTECTED: parent inheritance blocked | L3639-3640 | Cargo |
| `inheritance_generic_rights_mapped_on_inherited_aces` | Generic rights in inherited ACEs are mapped to object-specific rights via GenericMapping | L3645-3646 | Cargo |
| `inheritance_owner_from_creator_sd_or_token` | Owner: from creator SD if specified, otherwise from token's owner SID | L3616-3617 | Cargo + Provium |
| `inheritance_group_from_creator_sd_or_token` | Group: from creator SD if specified, otherwise from token's primary group SID | L3619-3620 | Cargo + Provium |
| `inheritance_sacl_computed_same_as_dacl` | SACL follows the same inheritance algorithm as DACL | L3650-3653 | Cargo |
| `inheritance_no_default_sacl_means_no_sacl` | No creator SACL + no parent inheritable SACL ACEs = no SACL on new object | L3651-3653 | Cargo |
| `inheritance_eager_at_creation_time` | Inheritance is eager: SD fully computed at creation time, no lazy walk at access time | L3655-3658 | Provium |
| `inheritance_ci_oi_both_inherits_recursively` | CI|OI ACE inherits to everything recursively ("this folder, subfolders, and files") | L3572 | Cargo + Provium |
| `inheritance_ci_only_inherits_containers_only` | CI-only ACE inherits to containers only, not files | L3573 | Cargo |
| `inheritance_oi_only_inherits_noncontainers_only` | OI-only ACE: inherited by containers as inherit-only | L3574 | Cargo |
| `inheritance_init_security_fires_on_create` | security_inode_init_security fires during inode creation and returns SD xattr atomically | L10076-10081 | Provium |
| `inheritance_no_window_without_sd` | On xattr-capable deny-mode filesystems, no window exists where a newly created file has no SD | L10080-10081 | Provium |
| `inheritance_create_checks_parent_rights` | File creation checks FILE_ADD_FILE on parent directory SD; mkdir checks FILE_ADD_SUBDIRECTORY | L10064, L10067 | Provium |
| `inheritance_mknod_checks_file_add_file` | mknod checks FILE_ADD_FILE on parent directory SD | L10070 | Provium |
| `inheritance_symlink_checks_file_add_file` | symlink creation checks FILE_ADD_FILE on parent directory SD | L10073 | Provium |

## 23. O_TMPFILE

| Test name | Assertion | Spec ref | Type |
|---|---|---|---|
| `o_tmpfile_inherits_sd_from_dir` | O_TMPFILE unnamed inode inherits SD from the directory via security_inode_init_security | L10094-10096 | Provium |
| `o_tmpfile_fd_is_facs_managed` | The resulting O_TMPFILE fd is FACS-managed with a normal granted mask | L10096 | Provium |
| `o_tmpfile_linkat_preserves_sd` | When O_TMPFILE is linked via linkat, existing SD travels with the inode (no re-inheritance) | L10098-10099 | Provium |
| `o_tmpfile_linkat_checks_dest_dir` | linkat for O_TMPFILE checks FILE_ADD_FILE on destination directory | L10100-10101 | Provium |
| `o_tmpfile_linkat_checks_source_write_attrs` | linkat for O_TMPFILE checks FILE_WRITE_ATTRIBUTES on the source inode | L10101 | Provium |

## 24. Data Operations — Granted Mask Checks

| Test name | Assertion | Spec ref | Type |
|---|---|---|---|
| `read_requires_file_read_data` | read() requires FILE_READ_DATA in granted mask | L10112 | Provium |
| `write_sequential_requires_write_data` | write() (non-append) requires FILE_WRITE_DATA | L10113 | Provium |
| `write_append_accepts_write_data_or_append_data` | write() on O_APPEND fd accepts FILE_WRITE_DATA or FILE_APPEND_DATA | L10114 | Provium |
| `positioned_write_requires_write_data` | pwrite requires FILE_WRITE_DATA (kernel patches deny on append-only) | L10115 | Provium |
| `readdir_requires_list_directory` | readdir/getdents requires FILE_LIST_DIRECTORY in granted mask | L10116 | Provium |
| `ftruncate_requires_write_data` | ftruncate requires FILE_WRITE_DATA (FILE_APPEND_DATA alone insufficient) | L10122-10124 | Provium |
| `mmap_prot_read_requires_read_data` | mmap(PROT_READ) requires FILE_READ_DATA | L10131 | Provium |
| `mmap_prot_write_shared_requires_write_data` | mmap(PROT_WRITE, MAP_SHARED) requires FILE_WRITE_DATA (not APPEND_DATA) | L10132 | Provium |
| `mmap_prot_exec_requires_file_execute` | mmap(PROT_EXEC) requires FILE_EXECUTE | L10133 | Provium |
| `mprotect_escalation_requires_right` | mprotect upgrade from PROT_READ to PROT_WRITE requires FILE_WRITE_DATA | L10142-10145 | Provium |
| `flock_shared_requires_read_data` | flock(LOCK_SH) requires FILE_READ_DATA | L10151 | Provium |
| `flock_exclusive_requires_write_data_or_append` | flock(LOCK_EX) requires FILE_WRITE_DATA or FILE_APPEND_DATA | L10152 | Provium |

## 25. Metadata Operations — File-Based Hooks

| Test name | Assertion | Spec ref | Type |
|---|---|---|---|
| `fstat_requires_file_read_attributes` | fstat on normal fd checks FILE_READ_ATTRIBUTES in granted mask | L10180-10183, L9961 | Provium |
| `fstat_denied_without_read_attrs` | fstat on fd without FILE_READ_ATTRIBUTES returns EACCES | L9961 | Provium |
| `fstat_after_legacy_open_always_succeeds` | fstat after successful legacy open() always succeeds (FILE_READ_ATTRIBUTES is core) | L10056-10061 | Provium |
| `fgetxattr_sd_denied_unconditionally` | fgetxattr(security.peios.sd) denied unconditionally | L10190 | Provium |
| `fgetxattr_other_requires_read_ea` | fgetxattr on non-SD xattr requires FILE_READ_EA in granted mask | L10191 | Provium |
| `fsetxattr_sd_denied_unconditionally` | fsetxattr(security.peios.sd) denied unconditionally | L10198 | Provium |
| `fsetxattr_posix_acl_denied_unconditionally` | fsetxattr(system.posix_acl_access/default) denied unconditionally | L10199 | Provium |
| `fsetxattr_other_requires_write_ea` | fsetxattr on other xattr requires FILE_WRITE_EA in granted mask | L10200 | Provium |
| `fremovexattr_sd_denied_unconditionally` | fremovexattr on SD xattr denied unconditionally | L10198 | Provium |

## 26. Path-Based Hooks (Dentry-Based)

| Test name | Assertion | Spec ref | Type |
|---|---|---|---|
| `path_chmod_requires_write_dac` | Path-based chmod() requires WRITE_DAC via AccessCheck against SD | L10265 | Provium |
| `path_chown_requires_write_owner` | Path-based chown() requires WRITE_OWNER via AccessCheck | L10266 | Provium |
| `path_truncate_requires_write_data` | Path-based truncate() requires FILE_WRITE_DATA via AccessCheck | L10267 | Provium |
| `path_utimensat_requires_write_attrs` | Path-based utimensat() requires FILE_WRITE_ATTRIBUTES via AccessCheck | L10268 | Provium |
| `path_stat_requires_read_attrs` | Path-based stat()/lstat() requires FILE_READ_ATTRIBUTES via AccessCheck | L10272-10273 | Provium |
| `path_setxattr_sd_denied` | Path-based setxattr on SD xattr names denied unconditionally | L10280-10281 | Provium |
| `path_setxattr_posix_acl_denied` | Path-based setxattr on system.posix_acl_* denied unconditionally | L10282 | Provium |
| `path_setxattr_other_requires_write_ea` | Path-based setxattr on other xattr requires FILE_WRITE_EA via AccessCheck | L10283 | Provium |
| `path_getxattr_sd_denied` | Path-based getxattr on SD xattr denied unconditionally | L10292-10293 | Provium |
| `path_getxattr_other_requires_read_ea` | Path-based getxattr on other xattr requires FILE_READ_EA via AccessCheck | L10294 | Provium |
| `path_removexattr_sd_denied` | Path-based removexattr on SD xattr denied unconditionally | L10310 | Provium |
| `path_removexattr_other_requires_write_ea` | Path-based removexattr on other xattr requires FILE_WRITE_EA via AccessCheck | L10311 | Provium |

## 27. File/Dentry Hook Coordination

| Test name | Assertion | Spec ref | Type |
|---|---|---|---|
| `fd_based_fchmod_dentry_hook_is_noop` | For fd-based fchmod, the file hook decides and the dentry hook is a no-op | L10176-10178, L10270 | Provium |
| `fd_based_fstat_dentry_hook_is_noop` | For fd-based fstat, the file hook decides and the dentry hook is a no-op | L10183, L10274 | Provium |
| `fd_based_fsetxattr_dentry_hook_is_noop` | For fd-based fsetxattr, the file hook decides and the dentry hook is a no-op | L10285 | Provium |
| `coordination_marker_inode_scoped` | The coordination marker is scoped to a specific inode and operation class | L10227-10230 | Provium |
| `coordination_marker_cleared_after_dentry_hook` | The coordination struct is cleared unconditionally at end of each dentry-based hook | L10224-10225 | Provium |

## 28. Link / Unlink / Rename

| Test name | Assertion | Spec ref | Type |
|---|---|---|---|
| `link_requires_add_file_on_dest_dir` | link()/linkat() requires FILE_ADD_FILE on destination directory | L10421-10422 | Provium |
| `link_requires_write_attrs_on_source` | link()/linkat() requires FILE_WRITE_ATTRIBUTES on source inode | L10422 | Provium |
| `unlink_requires_delete_or_delete_child` | unlink()/unlinkat() requires DELETE on file OR FILE_DELETE_CHILD on parent (either sufficient) | L10425-10427 | Provium |
| `rmdir_requires_delete_or_delete_child` | rmdir() requires DELETE on directory OR FILE_DELETE_CHILD on parent | L10429 | Provium |
| `rename_source_requires_delete` | rename source requires DELETE on source OR FILE_DELETE_CHILD on source parent | L10437 | Provium |
| `rename_dest_requires_add_file` | rename destination requires FILE_ADD_FILE on dest dir (or FILE_ADD_SUBDIRECTORY for dirs) | L10437 | Provium |
| `rename_overwrite_requires_delete_on_existing_dest` | Rename overwriting existing dest requires DELETE on existing dest OR FILE_DELETE_CHILD on dest parent | L10438 | Provium |
| `rename_exchange_requires_delete_on_both` | RENAME_EXCHANGE requires DELETE or FILE_DELETE_CHILD on both source and dest | L10439 | Provium |
| `rename_whiteout_requires_add_file_on_source_parent` | RENAME_WHITEOUT additionally requires FILE_ADD_FILE on source parent (for whiteout creation) | L10440 | Provium |
| `rename_same_volume_preserves_sd` | Same-volume rename preserves the SD (same inode, same xattr) | L10442 | Provium |

## 29. Symlink Operations

| Test name | Assertion | Spec ref | Type |
|---|---|---|---|
| `readlink_requires_read_data_on_symlink` | readlink() checks FILE_READ_DATA on the symlink's own SD (not target) | L10452-10453 | Provium |
| `follow_link_unconditionally_allowed` | security_inode_follow_link allows unconditionally (target SD evaluated at open) | L10455-10457 | Provium |

## 30. Directory Traversal

| Test name | Assertion | Spec ref | Type |
|---|---|---|---|
| `traverse_bypassed_by_change_notify_privilege` | SeChangeNotifyPrivilege bypasses per-directory FILE_TRAVERSE checks during path resolution | L10390-10393 | Provium |
| `traverse_enforced_without_change_notify` | Without SeChangeNotifyPrivilege, FILE_TRAVERSE is checked on each intermediate directory | L10393 | Provium |
| `fchdir_requires_traverse_in_granted_mask` | fchdir() on a normal fd requires FILE_TRAVERSE in granted mask regardless of privileges | L10413-10417 | Provium |
| `fchdir_not_affected_by_change_notify` | fchdir() traverse enforcement is NOT bypassed by SeChangeNotifyPrivilege | L10414-10416 | Provium |
| `access_x_ok_on_dir_returns_success_with_privilege` | access(dir, X_OK) returns success when SeChangeNotifyPrivilege is held | L10407-10411 | Provium |

## 31. Ioctl Classification

| Test name | Assertion | Spec ref | Type |
|---|---|---|---|
| `ioctl_regular_file_classified_allowlist` | Known ioctls on regular files are mapped to specific rights | L10337-10344 | Provium |
| `ioctl_fs_ioc_setflags_requires_write_attrs` | FS_IOC_SETFLAGS requires FILE_WRITE_ATTRIBUTES | L10340 | Provium |
| `ioctl_ficlone_requires_write_data` | FICLONE/FICLONERANGE requires FILE_WRITE_DATA on destination | L10341 | Provium |
| `ioctl_fs_ioc_getflags_requires_read_attrs` | FS_IOC_GETFLAGS requires FILE_READ_ATTRIBUTES | L10342 | Provium |
| `ioctl_fiemap_requires_read_data` | FIEMAP requires FILE_READ_DATA | L10343 | Provium |
| `ioctl_fitrim_requires_write_data` | FITRIM requires FILE_WRITE_DATA | L10344 | Provium |
| `ioctl_unknown_on_regular_file_denied` | Unclassified ioctls on regular files are denied | L10346-10348 | Provium |
| `ioctl_device_allowed_with_data_right_or_ioctl_only` | Device ioctls allowed if fd has at least one data right or KACS_FILE_IOCTL_ONLY flag | L10360-10363 | Provium |

## 32. SD Caching

| Test name | Assertion | Spec ref | Type |
|---|---|---|---|
| `sd_cache_populated_lazily` | Cache populated on first access, not eagerly | L9709-9710 | Provium |
| `sd_cache_uses_internal_read_path` | Cache population uses __vfs_getxattr (bypasses security_inode_getxattr) | L9710-9716 | Provium |
| `sd_cache_rcu_no_lock_contention` | AccessCheck readers use rcu_read_lock, no locks or atomics on the hot path | L9697-9700 | Provium |
| `sd_cache_updated_atomically_with_xattr_write` | set-security updates cache in same operation as xattr write (no disagreement window) | L9723-9726 | Provium |
| `sd_cache_freed_on_inode_eviction` | Cached SD freed via inode_free_security_rcu on inode eviction | L9729-9735 | Provium |
| `sd_cache_cmpxchg_race` | If two threads race to populate the same inode's cache, the loser frees its copy | L9717-9718 | Provium |

## 33. Unix Socket Enforcement

| Test name | Assertion | Spec ref | Type |
|---|---|---|---|
| `unix_stream_connect_checks_write_data` | unix_stream_connect checks FILE_WRITE_DATA on listening socket's SD | L10599 | Provium |
| `unix_may_send_checks_write_data` | unix_may_send checks FILE_WRITE_DATA on target socket's SD | L10599 | Provium |
| `pathname_socket_sd_on_inode` | Pathname sockets: SD lives on the socket file's inode (normal FACS object) | L10602-10604 | Provium |
| `abstract_socket_sd_stamped_at_bind` | Abstract sockets: SD stamped on sock->sk_security at bind() time | L10605-10609 | Provium |
| `socketpair_no_sd` | socketpair() fds have no SD; security is by handle possession | L10610-10612 | Provium |

## 34. Capability Side Effects

| Test name | Assertion | Spec ref | Type |
|---|---|---|---|
| `sticky_bit_bypass_replaced_by_sd` | CAP_FOWNER sticky bit bypass replaced by DELETE/FILE_DELETE_CHILD semantics | L9417-9418 | Provium |
| `o_noatime_requires_write_attrs_at_open` | O_NOATIME at open time requires FILE_WRITE_ATTRIBUTES in granted mask | L9423-9424 | Provium |
| `o_noatime_requires_write_attrs_via_fcntl` | O_NOATIME added via fcntl(F_SETFL) requires FILE_WRITE_ATTRIBUTES | L9424-9426 | Provium |
| `cap_linux_immutable_not_granted_universally` | CAP_LINUX_IMMUTABLE is NOT granted universally (dangerous inode flags restricted) | L9432-9433 | Provium |
| `linkat_at_empty_path_checks_link_rights` | linkat(AT_EMPTY_PATH) checks FILE_ADD_FILE on directory and FILE_WRITE_ATTRIBUTES on source | L9435-9437 | Provium |

## 35. LSM Stack Invariant

| Test name | Assertion | Spec ref | Type |
|---|---|---|---|
| `lsm_stack_exactly_commoncap_kacs` | The LSM stack is exactly commoncap, kacs — no other LSMs | L9204-9206 | Provium |
| `kacs_refuses_unexpected_lsm` | KACS verifies the stack at init and refuses to activate if unexpected LSM is present | L9210-9211 | Provium |

## 36. Get-Security Interface (kacs_get_sd)

| Test name | Assertion | Spec ref | Type |
|---|---|---|---|
| `get_sd_owner_requires_read_control` | OWNER_SECURITY_INFORMATION requires READ_CONTROL | L11224 | Provium |
| `get_sd_group_requires_read_control` | GROUP_SECURITY_INFORMATION requires READ_CONTROL | L11225 | Provium |
| `get_sd_dacl_requires_read_control` | DACL_SECURITY_INFORMATION requires READ_CONTROL | L11226 | Provium |
| `get_sd_sacl_requires_access_system_security` | SACL_SECURITY_INFORMATION requires ACCESS_SYSTEM_SECURITY (requires SeSecurityPrivilege) | L11227 | Provium |
| `get_sd_label_requires_read_control` | LABEL_SECURITY_INFORMATION requires READ_CONTROL (not ACCESS_SYSTEM_SECURITY, despite SACL storage) | L11228, L11230-11237 | Provium |
| `get_sd_two_call_pattern` | First call with buf_len=0 returns len_needed in ERANGE; second call with sufficient buffer succeeds | L11239-11240 | Provium |
| `get_sd_normal_fd_uses_granted_mask` | kacs_get_sd with AT_EMPTY_PATH on normal fd uses fd's granted mask for authorization | L11246-11250 | Provium |
| `get_sd_opath_fd_uses_live_check` | kacs_get_sd with AT_EMPTY_PATH on O_PATH fd uses live AccessCheck | L11251-11256 | Provium |

---

**Summary counts:**

- Total tests extracted: **258**
- Cargo tests (pure Rust logic): **~35** (core rights mapping, inheritance algorithm, SD format/parsing, bitmask check function, disposition mapping)
- Provium tests (require running KACS kernel): **~223** (syscall behavior, LSM hook enforcement, handle model, capability management, SD operations, xattr protection, directory operations)

Many assertions listed as "Cargo + Provium" have a Cargo component (testing the mapping/algorithm logic in the kacs-core crate) and a Provium component (testing end-to-end behavior in a running kernel). The Cargo tests validate the computation; the Provium tests validate that the kernel applies it.


---

# Section 14: FACS (Second Half)

## FACS (§14) Second Half — Exhaustive Test Corpus

### Group 1: Kernel Patch Security Properties (Patches 1–11)

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 1 | `pwrite_denied_on_append_only_fd` | `pwrite64()` on an fd opened with only `FILE_APPEND_DATA` (not `FILE_WRITE_DATA`) returns `EPERM` | §14.3 Patch 1 (line 9953) | Provium |
| 2 | `pwrite_allowed_with_write_data` | `pwrite64()` on an fd with `FILE_WRITE_DATA` in granted mask succeeds | §14.3 Patch 1 | Provium |
| 3 | `pwritev2_denied_on_append_only_fd` | `pwritev()` / `pwritev2()` on an append-only fd returns `EPERM` | §14.3 Patch 2 (line 9954) | Provium |
| 4 | `pwritev2_rwf_noappend_denied_on_append_only_fd` | `pwritev2()` with `RWF_NOAPPEND` on an append-only fd returns `EPERM` | §14.3 Patch 2 | Provium |
| 5 | `io_uring_positioned_write_denied_on_append_only_fd` | io_uring SQE write with explicit offset on an append-only fd fails | §14.3 Patch 3 (line 9955) | Provium |
| 6 | `aio_write_denied_on_append_only_fd` | AIO write (`io_submit`) with offset on an append-only fd returns `EPERM` | §14.3 Patch 4 (line 9956) | Provium |
| 7 | `access_uses_effective_token_not_real_cred` | `access()` / `faccessat()` on an impersonating thread evaluates the effective token, not the real credentials (credential swap to `real_cred` is skipped) | §14.3 Patch 5 (line 9957) | Provium |
| 8 | `open_by_handle_requires_change_notify_priv` | `open_by_handle_at()` from a process without `SeChangeNotifyPrivilege` fails | §14.3 Patch 6 (line 9958) | Provium |
| 9 | `open_by_handle_succeeds_with_change_notify_priv` | `open_by_handle_at()` from a process with `SeChangeNotifyPrivilege` succeeds (given other rights are met) | §14.3 Patch 6 | Provium |
| 10 | `fchmod_denied_without_write_dac` | `fchmod()` on an fd without `WRITE_DAC` in granted mask returns `EACCES` | §14.3 Patch 7 (line 9959) | Provium |
| 11 | `fchmod_succeeds_with_write_dac` | `fchmod()` on an fd with `WRITE_DAC` in granted mask succeeds | §14.3 Patch 7 | Provium |
| 12 | `fchown_denied_without_write_owner` | `fchown()` on an fd without `WRITE_OWNER` in granted mask returns `EACCES` | §14.3 Patch 7 (line 9959) | Provium |
| 13 | `fchown_succeeds_with_write_owner` | `fchown()` on an fd with `WRITE_OWNER` in granted mask succeeds | §14.3 Patch 7 | Provium |
| 14 | `futimens_denied_without_write_attributes` | `futimens()` on an fd without `FILE_WRITE_ATTRIBUTES` returns `EACCES` | §14.3 Patch 7 (line 10171) | Provium |
| 15 | `futimens_succeeds_with_write_attributes` | `futimens()` on an fd with `FILE_WRITE_ATTRIBUTES` succeeds | §14.3 Patch 7 | Provium |
| 16 | `fstat_denied_without_read_attributes` | `fstat()` on an fd without `FILE_READ_ATTRIBUTES` in granted mask returns `EACCES` | §14.3 Patch 9 (line 9961) | Provium |
| 17 | `fstat_succeeds_with_read_attributes` | `fstat()` on an fd with `FILE_READ_ATTRIBUTES` in granted mask succeeds | §14.3 Patch 9 | Provium |
| 18 | `statx_at_empty_path_denied_without_read_attributes` | `statx()` with `AT_EMPTY_PATH` on an fd without `FILE_READ_ATTRIBUTES` returns `EACCES` | §14.3 Patch 9 (line 10714) | Provium |
| 19 | `fgetxattr_denied_without_read_ea` | `fgetxattr()` for a non-SD xattr on an fd without `FILE_READ_EA` returns `EACCES` | §14.3 Patch 10 (line 9962) | Provium |
| 20 | `fgetxattr_succeeds_with_read_ea` | `fgetxattr()` for a non-SD xattr on an fd with `FILE_READ_EA` succeeds | §14.3 Patch 10 | Provium |
| 21 | `fgetxattr_sd_xattr_denied_unconditionally` | `fgetxattr()` for `security.peios.sd` is denied regardless of granted mask | §14.3 Patch 10 (line 10190) | Provium |
| 22 | `fgetxattr_ntfs_security_denied_unconditionally` | `fgetxattr()` for `system.ntfs_security` is denied regardless of granted mask | §14.3 Patch 10 (line 10190) | Provium |
| 23 | `fsetxattr_denied_without_write_ea` | `fsetxattr()` for a non-SD xattr on an fd without `FILE_WRITE_EA` returns `EACCES` | §14.3 Patch 11 (line 9963) | Provium |
| 24 | `fsetxattr_succeeds_with_write_ea` | `fsetxattr()` for a non-SD xattr on an fd with `FILE_WRITE_EA` succeeds | §14.3 Patch 11 | Provium |
| 25 | `fsetxattr_sd_xattr_denied_unconditionally` | `fsetxattr()` for `security.peios.sd` is denied regardless of granted mask | §14.3 Patch 11 (line 10198) | Provium |
| 26 | `fsetxattr_posix_acl_denied_unconditionally` | `fsetxattr()` for `system.posix_acl_access` / `system.posix_acl_default` is denied unconditionally | §14.3 Patch 11 (line 10199) | Provium |
| 27 | `fremovexattr_denied_without_write_ea` | `fremovexattr()` for a non-SD xattr on an fd without `FILE_WRITE_EA` returns `EACCES` | §14.3 Patch 11 (line 10200) | Provium |
| 28 | `fremovexattr_sd_xattr_denied_unconditionally` | `fremovexattr()` for `security.peios.sd` / `system.ntfs_security` is denied unconditionally | §14.3 Patch 11 (line 10198) | Provium |
| 29 | `fallocate_punch_hole_denied_on_append_only_fd` | `fallocate(FALLOC_FL_PUNCH_HOLE)` on an append-only fd returns `EPERM` | §14.3 Patch 8 (line 9960) | Provium |
| 30 | `fallocate_zero_range_denied_on_append_only_fd` | `fallocate(FALLOC_FL_ZERO_RANGE)` on an append-only fd returns `EPERM` | §14.3 Patch 8 | Provium |
| 31 | `fallocate_collapse_range_denied_on_append_only_fd` | `fallocate(FALLOC_FL_COLLAPSE_RANGE)` on an append-only fd returns `EPERM` | §14.3 Patch 8 | Provium |
| 32 | `fallocate_insert_range_denied_on_append_only_fd` | `fallocate(FALLOC_FL_INSERT_RANGE)` on an append-only fd returns `EPERM` | §14.3 Patch 8 (line 10696) | Provium |

### Group 2: File Open and Create

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 33 | `open_stamps_granted_mask_on_fd` | A successful `open()` / `openat()` stamps the AccessCheck result (core + compat) as the fd's immutable granted mask | §14.3 (line 9986–9989) | Provium |
| 34 | `open_core_rights_must_be_fully_granted` | Legacy `open()` AccessCheck runs in subset mode: all core rights must be granted or open fails | §14.3 (line 9988) | Provium |
| 35 | `kacs_native_open_strict_mode` | KACS-native open runs AccessCheck in strict mode: all requested rights must be granted or the open fails | §14.3 (line 9993) | Provium |
| 36 | `open_read_data_sets_fmode_read` | `FILE_READ_DATA` in granted mask sets `FMODE_READ` on the file description | §14.3 (line 9996) | Provium |
| 37 | `open_write_data_sets_fmode_write` | `FILE_WRITE_DATA` or `FILE_APPEND_DATA` in granted mask sets `FMODE_WRITE` on the file description | §14.3 (line 9997) | Provium |
| 38 | `open_o_noatime_requires_write_attributes` | `O_NOATIME` flag on `open()` requires `FILE_WRITE_ATTRIBUTES` in the granted mask | §14.3 (line 10001) | Provium |
| 39 | `o_path_fd_not_facs_managed` | `O_PATH` fds carry no granted mask and are not FACS-managed | §14.3 (line 10008–10009) | Provium |
| 40 | `create_requires_file_add_file_on_parent` | Creating a new regular file checks `FILE_ADD_FILE` on the parent directory's SD | §14.3 (line 10064) | Provium |
| 41 | `mkdir_requires_add_subdirectory_on_parent` | Creating a new directory checks `FILE_ADD_SUBDIRECTORY` on the parent directory's SD | §14.3 (line 10067) | Provium |
| 42 | `mknod_requires_file_add_file_on_parent` | Creating a device node / pipe / socket checks `FILE_ADD_FILE` on the parent directory's SD | §14.3 (line 10069) | Provium |
| 43 | `symlink_requires_file_add_file_on_parent` | Creating a symlink checks `FILE_ADD_FILE` on the parent directory's SD | §14.3 (line 10073) | Provium |
| 44 | `new_file_sd_inherited_from_parent_atomically` | New files inherit SDs from parent via `security_inode_init_security` — no window where newly created file has no SD (on xattr-capable deny-mode filesystems) | §14.3 (line 10077–10081) | Provium |
| 45 | `o_tmpfile_inherits_sd_from_directory` | `open(dir, O_TMPFILE)` creates unnamed inode that inherits SD from the directory | §14.3 (line 10093–10096) | Provium |
| 46 | `o_tmpfile_linkat_checks_add_file_and_write_attributes` | `linkat(fd, "", destdir, name, AT_EMPTY_PATH)` for O_TMPFILE checks `FILE_ADD_FILE` on dest dir and `FILE_WRITE_ATTRIBUTES` on source inode | §14.3 (line 10100–10101) | Provium |
| 47 | `o_tmpfile_linkat_preserves_original_sd` | When O_TMPFILE inode is linked via `linkat`, the existing SD travels with the inode; no re-inheritance occurs | §14.3 (line 10098–10099) | Provium |

### Group 3: O_PATH fd Behavior

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 48 | `o_path_fstat_allowed_unconditionally` | `fstat()` on an `O_PATH` fd is allowed unconditionally, regardless of SD | §14.3 (line 10014–10016) | Provium |
| 49 | `o_path_fstatfs_allowed_unconditionally` | `fstatfs()` on an `O_PATH` fd is allowed unconditionally | §14.3 (line 10014–10016) | Provium |
| 50 | `o_path_at_syscalls_allowed` | `*at()` syscalls using an `O_PATH` fd as dirfd are allowed; target is evaluated independently | §14.3 (line 10017–10019) | Provium |
| 51 | `o_path_fchdir_runs_live_accesscheck` | `fchdir()` on an `O_PATH` directory fd runs a live AccessCheck for `FILE_TRAVERSE` against the directory's SD | §14.3 (line 10020–10023) | Provium |
| 52 | `o_path_fchmod_denied_ebadf` | `fchmod()` on `O_PATH` fd returns `EBADF` | §14.3 (line 10024–10027) | Provium |
| 53 | `o_path_fchown_denied_ebadf` | `fchown()` on `O_PATH` fd returns `EBADF` | §14.3 (line 10024–10027) | Provium |
| 54 | `o_path_mmap_denied_ebadf` | `mmap()` on `O_PATH` fd returns `EBADF` | §14.3 (line 10025) | Provium |
| 55 | `o_path_exec_checks_file_execute_live` | `execveat(O_PATH_fd, "", ..., AT_EMPTY_PATH)` falls back to live AccessCheck for `FILE_EXECUTE` on the binary's SD | §14.3 (line 10540–10544) | Provium |
| 56 | `o_path_bypasses_file_read_attributes` | An SD that denies `FILE_READ_ATTRIBUTES` does not prevent attribute reads via `O_PATH` + `fstat()` | §14.3 (line 10041–10048) | Provium |
| 57 | `fstat_after_open_always_succeeds` | `FILE_READ_ATTRIBUTES` is a core right for all legacy open modes, so `fstat()` after a successful `open()` always succeeds | §14.3 (line 10056–10061) | Provium |
| 58 | `sd_denying_read_attributes_causes_open_to_fail` | An SD that denies `FILE_READ_ATTRIBUTES` causes legacy `open()` itself to fail (core right denied) | §14.3 (line 10059–10060) | Provium |

### Group 4: Data Operations (Read/Write/Truncate)

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 59 | `read_requires_file_read_data` | `read()` / `readv()` / `pread64()` / `preadv()` require `FILE_READ_DATA` in granted mask | §14.3 (line 10112) | Provium |
| 60 | `write_requires_file_write_data` | Sequential `write()` on a non-append fd requires `FILE_WRITE_DATA` in granted mask | §14.3 (line 10113) | Provium |
| 61 | `append_write_accepts_append_data_or_write_data` | Sequential write on an `O_APPEND` fd accepts either `FILE_APPEND_DATA` or `FILE_WRITE_DATA` (write_data is superset) | §14.3 (line 10114) | Provium |
| 62 | `positioned_write_requires_write_data_not_append` | `pwrite()` family requires `FILE_WRITE_DATA`; `FILE_APPEND_DATA` alone is insufficient for positioned writes | §14.3 (line 10115) | Provium |
| 63 | `readdir_requires_file_list_directory` | `readdir()` / `getdents()` / `getdents64()` on a directory fd requires `FILE_LIST_DIRECTORY` in granted mask | §14.3 (line 10116) | Provium |
| 64 | `ftruncate_requires_file_write_data` | `ftruncate()` requires `FILE_WRITE_DATA` in granted mask; `FILE_APPEND_DATA` alone is insufficient | §14.3 (line 10122–10124) | Provium |
| 65 | `truncate_path_based_requires_write_data` | Path-based `truncate()` runs live AccessCheck for `FILE_WRITE_DATA` | §14.4 (line 10693) | Provium |
| 66 | `sendfile_checks_both_fds` | `sendfile()` checks `FILE_READ_DATA` on source fd and `FILE_WRITE_DATA` on dest fd | §14.4 (line 10678) | Provium |
| 67 | `copy_file_range_checks_both_fds` | `copy_file_range()` checks `FILE_READ_DATA` on source and `FILE_WRITE_DATA` on dest | §14.4 (line 10679) | Provium |
| 68 | `splice_checks_direction` | `splice()` checks `FILE_READ_DATA` or `FILE_WRITE_DATA` depending on direction | §14.4 (line 10680) | Provium |
| 69 | `fallocate_extend_accepts_write_or_append` | `fallocate()` for extend/preallocate accepts `FILE_WRITE_DATA` or `FILE_APPEND_DATA` | §14.4 (line 10694) | Provium |

### Group 5: Memory Mapping (mmap/mprotect)

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 70 | `mmap_prot_read_requires_read_data` | `mmap(PROT_READ)` requires `FILE_READ_DATA` in granted mask | §14.3 (line 10131) | Provium |
| 71 | `mmap_prot_write_map_shared_requires_write_data` | `mmap(PROT_WRITE, MAP_SHARED)` requires `FILE_WRITE_DATA`; `FILE_APPEND_DATA` is insufficient for shared writable mappings | §14.3 (line 10132) | Provium |
| 72 | `mmap_prot_exec_requires_file_execute` | `mmap(PROT_EXEC)` requires `FILE_EXECUTE` in granted mask | §14.3 (line 10133) | Provium |
| 73 | `mmap_prot_exec_does_not_require_mode_execute_bit` | `mmap(PROT_EXEC)` does not require the mode execute bit (only `execve` does) | §14.3 (line 10512–10524) | Provium |
| 74 | `mmap_prot_write_map_private_requires_read_data` | `mmap(PROT_WRITE, MAP_PRIVATE)` requires only `FILE_READ_DATA` (copy-on-write, no write to file) | §14.4 (line 10705) | Provium |
| 75 | `mmap_audit_bit_25_denies_mmap` | If SACL alarm ACE sets bit 25 in audit mask for the opener's SID, `mmap()` is denied regardless of granted rights | §14.3 (line 10135–10140) | Provium |
| 76 | `mprotect_prevents_escalation` | `mprotect()` upgrading `PROT_READ` mapping to `PROT_WRITE` requires `FILE_WRITE_DATA` in granted mask | §14.3 (line 10143–10145) | Provium |
| 77 | `mprotect_same_checks_as_mmap` | `mprotect()` applies same right checks as `mmap()` for new protection flags | §14.3 (line 10143) | Provium |
| 78 | `mremap_no_lsm_hook` | `mremap()` has no LSM hook; inherits mapping permissions from the original mapping | §14.4 (line 10707) | Provium |

### Group 6: File Locking

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 79 | `flock_shared_requires_read_data` | `flock(LOCK_SH)` requires `FILE_READ_DATA` in granted mask | §14.3 (line 10151) | Provium |
| 80 | `flock_exclusive_requires_write_data_or_append` | `flock(LOCK_EX)` requires `FILE_WRITE_DATA` or `FILE_APPEND_DATA` in granted mask | §14.3 (line 10152) | Provium |
| 81 | `fcntl_rdlck_requires_read_data` | `fcntl(F_RDLCK)` requires `FILE_READ_DATA` in granted mask | §14.3 (line 10151) | Provium |
| 82 | `fcntl_wrlck_requires_write_or_append` | `fcntl(F_WRLCK)` requires `FILE_WRITE_DATA` or `FILE_APPEND_DATA` in granted mask | §14.3 (line 10152) | Provium |

### Group 7: fcntl Operations

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 83 | `fcntl_setfl_o_noatime_requires_write_attributes` | `fcntl(F_SETFL)` adding `O_NOATIME` requires `FILE_WRITE_ATTRIBUTES` in granted mask | §14.3 (line 10325) | Provium |
| 84 | `fcntl_clear_o_append_denied_without_write_data` | `fcntl(F_SETFL)` clearing `O_APPEND` is denied if fd has `FILE_APPEND_DATA` but not `FILE_WRITE_DATA` | §14.3 (line 10326–10327) | Provium |
| 85 | `fcntl_set_o_append_always_allowed` | `fcntl(F_SETFL)` setting `O_APPEND` is always allowed (privilege reduction) | §14.3 (line 10328–10331) | Provium |
| 86 | `fcntl_setown_setsig_allowed` | `fcntl(F_SETOWN)` and `fcntl(F_SETSIG)` are allowed unconditionally | §14.3 (line 10332) | Provium |

### Group 8: ioctl Classification

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 87 | `ioctl_fs_ioc_setflags_requires_write_attributes` | `FS_IOC_SETFLAGS` on a regular file requires `FILE_WRITE_ATTRIBUTES` | §14.3 (line 10340) | Provium |
| 88 | `ioctl_fs_ioc_getflags_requires_read_attributes` | `FS_IOC_GETFLAGS` on a regular file requires `FILE_READ_ATTRIBUTES` | §14.3 (line 10342) | Provium |
| 89 | `ioctl_ficlone_requires_write_data_on_dest` | `FICLONE` / `FICLONERANGE` requires `FILE_WRITE_DATA` on destination fd | §14.3 (line 10341) | Provium |
| 90 | `ioctl_fiemap_requires_read_data` | `FIEMAP` / `FS_IOC_FIEMAP` requires `FILE_READ_DATA` | §14.3 (line 10343) | Provium |
| 91 | `ioctl_fitrim_requires_write_data` | `FITRIM` requires `FILE_WRITE_DATA` | §14.3 (line 10344) | Provium |
| 92 | `ioctl_unclassified_denied_on_regular_files` | Unclassified (unknown) ioctls on regular files and directories are denied | §14.3 (line 10346–10348) | Provium |
| 93 | `ioctl_device_requires_any_data_right` | Device node ioctls are allowed if fd has at least one data right or `KACS_FILE_IOCTL_ONLY` | §14.3 (line 10360–10362) | Provium |
| 94 | `ioctl_direction_bits_not_security_classifier` | `_IOC_DIR` is not used as a security classifier; ioctl direction bits describe buffer flow only | §14.3 (line 10373–10374) | Cargo |

### Group 9: Directory Traversal and SeChangeNotifyPrivilege

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 95 | `traverse_skipped_with_change_notify_privilege` | Path resolution skips per-directory `FILE_TRAVERSE` checks when `SeChangeNotifyPrivilege` is held | §14.3 (line 10391–10393) | Provium |
| 96 | `traverse_checked_without_change_notify_privilege` | Without `SeChangeNotifyPrivilege`, FACS checks `FILE_TRAVERSE` on each intermediate directory's SD during path resolution | §14.3 (line 10393) | Provium |
| 97 | `traverse_default_inert` | In default configuration (all principals have `SeChangeNotifyPrivilege`), directory `FILE_TRAVERSE` ACEs are effectively inert for path resolution | §14.3 (line 10395–10399) | Provium |
| 98 | `access_x_ok_on_dir_checks_file_traverse` | `access(dir, X_OK)` checks `FILE_TRAVERSE` on the directory | §14.4 (line 10751) | Provium |
| 99 | `access_x_ok_succeeds_with_change_notify_privilege` | `access(dir, X_OK)` returns success when `SeChangeNotifyPrivilege` is held (privilege applies to all MAY_EXEC directory checks) | §14.3 (line 10407–10411) | Provium |
| 100 | `fchdir_normal_fd_checks_granted_mask_traverse` | `fchdir()` on a normal fd checks `FILE_TRAVERSE` in the fd's granted mask (handle model, patch 16) | §14.3 (line 10413–10417) | Provium |
| 101 | `fchdir_not_affected_by_change_notify_privilege` | `fchdir()` requires `FILE_TRAVERSE` in the fd's granted mask regardless of `SeChangeNotifyPrivilege` | §14.3 (line 10413–10417) | Provium |
| 102 | `fchdir_denied_without_traverse_in_granted_mask` | `fchdir()` on a normal fd without `FILE_TRAVERSE` in granted mask is denied | §14.3 (line 10400, 10834) | Provium |
| 103 | `inode_permission_defers_non_dir_to_file_open` | `security_inode_permission` on non-directory final component returns 0 (allow) and defers to `security_file_open` | §14.3 (line 10385–10388) | Provium |

### Group 10: Link Operations

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 104 | `link_requires_add_file_on_dest_dir` | `link()` / `linkat()` checks `FILE_ADD_FILE` on destination directory SD | §14.3 (line 10421–10422) | Provium |
| 105 | `link_requires_write_attributes_on_source` | `link()` / `linkat()` checks `FILE_WRITE_ATTRIBUTES` on source inode SD | §14.3 (line 10422) | Provium |
| 106 | `unlink_requires_delete_or_parent_delete_child` | `unlink()` / `unlinkat()` requires either `DELETE` on the file OR `FILE_DELETE_CHILD` on the parent directory (either is sufficient) | §14.3 (line 10425–10427) | Provium |
| 107 | `unlink_succeeds_with_only_delete_on_file` | `unlink()` succeeds if caller has `DELETE` on the file but not `FILE_DELETE_CHILD` on parent | §14.3 (line 10426) | Provium |
| 108 | `unlink_succeeds_with_only_delete_child_on_parent` | `unlink()` succeeds if caller has `FILE_DELETE_CHILD` on parent but not `DELETE` on file | §14.3 (line 10426) | Provium |
| 109 | `rmdir_requires_delete_or_parent_delete_child` | `rmdir()` same as unlink: `DELETE` on directory OR `FILE_DELETE_CHILD` on parent (either sufficient) | §14.3 (line 10429–10430) | Provium |

### Group 11: Rename Operations

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 110 | `rename_plain_requires_delete_on_source` | Plain `rename()` requires `DELETE` on source OR `FILE_DELETE_CHILD` on source parent | §14.3 (line 10437) | Provium |
| 111 | `rename_plain_requires_add_file_on_dest_dir` | Plain `rename()` requires `FILE_ADD_FILE` on destination directory (or `FILE_ADD_SUBDIRECTORY` for dirs) | §14.3 (line 10437) | Provium |
| 112 | `rename_overwrite_requires_delete_on_existing_dest` | Rename overwriting existing dest requires `DELETE` on existing dest OR `FILE_DELETE_CHILD` on dest parent | §14.3 (line 10438) | Provium |
| 113 | `rename_exchange_requires_delete_on_both` | `renameat2(RENAME_EXCHANGE)` requires `DELETE` or `FILE_DELETE_CHILD` on both source and dest sides | §14.3 (line 10439) | Provium |
| 114 | `rename_whiteout_requires_add_file_on_source_parent` | `renameat2(RENAME_WHITEOUT)` requires same as plain rename plus `FILE_ADD_FILE` on source parent for whiteout creation | §14.3 (line 10440) | Provium |
| 115 | `rename_same_volume_preserves_sd` | Same-volume rename preserves the SD (same inode, same xattr) | §14.3 (line 10442) | Provium |

### Group 12: Symlink Operations

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 116 | `readlink_requires_read_data_on_symlink` | `readlink()` / `readlinkat()` checks `FILE_READ_DATA` on the symlink's own SD, not the target's | §14.3 (line 10452–10453) | Provium |
| 117 | `follow_link_allowed_unconditionally` | `security_inode_follow_link` allows unconditionally; the target's SD is evaluated at target open | §14.3 (line 10455–10457) | Provium |

### Group 13: Execution

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 118 | `execve_path_based_requires_file_execute` | `execve()` path-based runs live AccessCheck for `FILE_EXECUTE` on the binary's SD | §14.3 (line 10468–10470) | Provium |
| 119 | `execveat_fd_based_checks_granted_mask` | `execveat(fd, "", ..., AT_EMPTY_PATH)` checks `FILE_EXECUTE` in the fd's granted mask (patch 15) | §14.3 (line 10472–10474) | Provium |
| 120 | `exec_fd_without_file_execute_denied` | An fd without `FILE_EXECUTE` in its granted mask cannot be used for exec, even if the current SD would allow it | §14.3 (line 10488–10490) | Provium |
| 121 | `exec_sd_change_after_open_does_not_affect_granted_mask` | SD changes after open do not affect the granted mask; fd-based exec uses the snapshot | §14.3 (line 10490) | Provium |
| 122 | `exec_requires_mode_execute_bit_live` | Execute mode-bit (`+x`) is checked live against the inode at exec time; removing `+x` after fd open causes exec to fail | §14.3 (line 10492–10497) | Provium |
| 123 | `execve_requires_both_mode_bit_and_file_execute` | For `execve`: both `+x` mode bit AND `FILE_EXECUTE` must be true | §14.3 (line 10520–10521) | Provium |
| 124 | `exec_binfmt_chain_checks_interpreter_sd` | In binfmt chain (shebang → interpreter), subsequent `bprm_check` invocations check the interpreter's SD via live AccessCheck, not the original fd's granted mask | §14.3 (line 10476–10482) | Provium |
| 125 | `bprm_creds_from_file_suppresses_setuid_setgid` | `security_bprm_creds_from_file` suppresses setuid/setgid file capabilities | §14.3 (line 10546–10548) | Provium |
| 126 | `bprm_creds_for_exec_reasserts_dac_bypass_caps` | `security_bprm_creds_for_exec` reasserts four DAC bypass capabilities on new credential set | §14.3 (line 10461–10462) | Provium |

### Group 14: FD Transfer and Lifecycle

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 127 | `scm_rights_transfer_allowed_unconditionally` | `SCM_RIGHTS` fd transfer is allowed unconditionally in `security_file_receive`; fd is a capability token | §14.3 (line 10553–10556) | Provium |
| 128 | `fd_transfer_does_not_reevaluate_mic` | MIC and PIP are not re-evaluated on fd recipients; authority is on the handle, not the holder | §14.3 (line 10566–10572) | Provium |
| 129 | `dup_preserves_granted_mask` | `dup()` / `dup2()` / `dup3()` / `F_DUPFD` produce same file description with same granted mask | §14.4 (line 10816–10818) | Provium |
| 130 | `fork_inherits_fds_same_granted_masks` | `fork()` / `clone()` child inherits fds with same granted masks | §14.4 (line 10826) | Provium |
| 131 | `exec_non_cloexec_fd_survives_same_granted_mask` | Fds without `FD_CLOEXEC` survive exec with same granted mask | §14.4 (line 10827) | Provium |
| 132 | `file_free_frees_granted_mask` | `security_file_free` frees the granted mask on file description cleanup; no security decision | §14.3 (line 10574–10575) | Provium |

### Group 15: Credential Management

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 133 | `prepare_creds_asserts_implementation_caps` | `security_prepare_creds` asserts six implementation capabilities on new credential sets | §14.3 (line 10579–10580) | Provium |
| 134 | `capset_denies_clearing_implementation_caps` | `security_capset` denies clearing the six implementation capabilities | §14.3 (line 10582) | Provium |
| 135 | `prctl_denies_ambient_raise_implementation_caps` | `security_task_prctl` denies ambient capability raises affecting the six implementation capabilities | §14.3 (line 10584–10586) | Provium |
| 136 | `prctl_denies_bounding_set_reduction_implementation_caps` | `security_task_prctl` denies bounding set reductions affecting the six implementation capabilities | §14.3 (line 10585) | Provium |

### Group 16: Dentry-Based Hook Coordination (File + Dentry Dedup)

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 137 | `file_hook_sets_decision_marker` | File-based hook populates `kacs_file_decision` with inode and op_class before returning | §14.3 (line 10218–10220) | Provium |
| 138 | `dentry_hook_noop_when_file_hook_decided` | Dentry-based hook is a no-op when `kacs_file_decision` matches inode and op_class | §14.3 (line 10218–10225) | Provium |
| 139 | `dentry_hook_evaluates_on_mismatch` | Dentry-based hook evaluates normally when `kacs_file_decision` does not match (different inode or op_class) | §14.3 (line 10222–10224) | Provium |
| 140 | `decision_marker_cleared_after_dentry_hook` | `kacs_file_decision` struct is cleared unconditionally at the end of each dentry-based hook | §14.3 (line 10224–10225) | Provium |
| 141 | `decision_marker_scoped_single_syscall` | Decision marker scope is exactly one syscall invocation, one inode, one operation class | §14.3 (line 10229–10230) | Provium |
| 142 | `overlayfs_marker_not_consumed_by_wrong_hook` | In stacked filesystems (overlayfs), marker is not consumed by wrong hook because different inode | §14.3 (line 10236–10242) | Provium |

### Group 17: Path-Based Metadata Operations

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 143 | `path_chmod_requires_write_dac` | Path-based `chmod()` / `fchmodat()` checks `WRITE_DAC` via `security_inode_setattr` | §14.3 (line 10265) | Provium |
| 144 | `path_chown_requires_write_owner` | Path-based `chown()` / `lchown()` / `fchownat()` checks `WRITE_OWNER` via `security_inode_setattr` | §14.3 (line 10266) | Provium |
| 145 | `path_truncate_requires_write_data` | Path-based `truncate()` (`ATTR_SIZE`) checks `FILE_WRITE_DATA` via `security_inode_setattr` | §14.3 (line 10267) | Provium |
| 146 | `path_utimensat_requires_write_attributes` | Path-based `utimensat()` / `utimes()` checks `FILE_WRITE_ATTRIBUTES` via `security_inode_setattr` | §14.3 (line 10268) | Provium |
| 147 | `path_stat_requires_read_attributes` | Path-based `stat()` / `lstat()` checks `FILE_READ_ATTRIBUTES` via `security_inode_getattr` | §14.3 (line 10272–10274) | Provium |
| 148 | `path_setxattr_sd_denied_unconditionally` | Path-based `setxattr()` for `security.peios.sd` / `system.ntfs_security` is denied unconditionally | §14.3 (line 10281) | Provium |
| 149 | `path_setxattr_posix_acl_denied_unconditionally` | Path-based `setxattr()` for `system.posix_acl_access` / `system.posix_acl_default` is denied unconditionally | §14.3 (line 10282) | Provium |
| 150 | `path_setxattr_normal_requires_write_ea` | Path-based `setxattr()` for other xattrs checks `FILE_WRITE_EA` via AccessCheck | §14.3 (line 10283) | Provium |
| 151 | `path_getxattr_sd_denied_unconditionally` | Path-based `getxattr()` for `security.peios.sd` / `system.ntfs_security` returns `-EACCES` unconditionally | §14.3 (line 10292–10293) | Provium |
| 152 | `path_getxattr_normal_requires_read_ea` | Path-based `getxattr()` for non-SD xattrs checks `FILE_READ_EA` via AccessCheck | §14.3 (line 10294) | Provium |
| 153 | `path_removexattr_sd_denied_unconditionally` | Path-based `removexattr()` for SD xattrs is denied unconditionally | §14.3 (line 10309–10311) | Provium |
| 154 | `path_removexattr_normal_requires_write_ea` | Path-based `removexattr()` for other xattrs checks `FILE_WRITE_EA` via AccessCheck | §14.3 (line 10311) | Provium |
| 155 | `listxattr_allowed_unconditionally` | `listxattr()` / `flistxattr()` / `llistxattr()` is allowed unconditionally; xattr names are not sensitive | §14.3 (line 10314–10317) | Provium |
| 156 | `posix_acl_set_denied_unconditionally` | `security_inode_set_acl` denies POSIX ACL setting unconditionally | §14.3 (line 10319–10320) | Provium |

### Group 18: access() / faccessat() Behavior

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 157 | `access_f_ok_no_accesscheck` | `access(path, F_OK)` is an existence check only; no AccessCheck runs | §14.4 (line 10748) | Provium |
| 158 | `access_r_ok_file_checks_read_data` | `access(path, R_OK)` on a file checks `FILE_READ_DATA` | §14.4 (line 10749) | Provium |
| 159 | `access_r_ok_dir_checks_list_directory` | `access(dir, R_OK)` checks `FILE_LIST_DIRECTORY` | §14.4 (line 10749) | Provium |
| 160 | `access_w_ok_file_checks_write_data` | `access(path, W_OK)` on a file checks `FILE_WRITE_DATA` | §14.4 (line 10750) | Provium |
| 161 | `access_w_ok_dir_checks_add_file` | `access(dir, W_OK)` checks `FILE_ADD_FILE` (approximation) | §14.4 (line 10750) | Provium |
| 162 | `access_x_ok_file_checks_file_execute` | `access(path, X_OK)` on a file checks `FILE_EXECUTE` | §14.4 (line 10751) | Provium |
| 163 | `access_is_advisory_only` | `access()` answers "does the SD broadly permit this?" not "will the next syscall succeed" | §14.4 (line 10753–10754) | Provium |
| 164 | `access_at_eaccess_is_noop` | `AT_EACCESS` flag is a no-op because FACS always uses effective token (patch 5) | §14.4 (line 10742) | Provium |

### Group 19: Corrupt SD Handling

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 165 | `corrupt_sd_denies_all_access` | A corrupt `security.peios.sd` xattr (truncated, invalid ACE, malformed SID) denies all access; AccessCheck is not called | §14.2 (line 10882–10883) | Provium |
| 166 | `corrupt_sd_truncated_dacl_not_treated_as_empty` | A truncated DACL must not be treated as empty (which would grant `GENERIC_ALL` to everyone) | §14.2 (line 10885) | Cargo |
| 167 | `corrupt_sd_garbled_ace_not_skipped` | A garbled ACE must not be skipped (could remove a critical deny entry) | §14.2 (line 10886) | Cargo |
| 168 | `corrupt_sd_emits_audit_event` | Every corrupt SD encounter emits an audit event with file path/inode, xattr size, parse failure reason, mount path | §14.2 (line 10888–10894) | Provium |
| 169 | `corrupt_sd_audit_once_per_inode_per_cache` | Audit event fires once per inode per cache population, not on every access attempt | §14.2 (line 10897) | Provium |
| 170 | `corrupt_sd_state_cached_sentinel` | Corrupt state is cached as a sentinel value in `i_security` to avoid repeated xattr reads | §14.2 (line 10897–10898) | Provium |
| 171 | `corrupt_sd_recovery_requires_restore_privilege` | Online recovery from corrupt SD requires a process with `SeRestorePrivilege` to call set-security syscall | §14.2 (line 10902–10906) | Provium |
| 172 | `corrupt_sd_no_unprivileged_recovery` | No unprivileged recovery path exists for corrupt SDs (corrupt SD denies `WRITE_DAC` and `WRITE_OWNER`) | §14.2 (line 10906–10907) | Provium |

### Group 20: SD Validation (Cargo — pure parse/format logic)

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 173 | `sd_parse_detects_truncated_blob` | SD parser detects and rejects a truncated binary blob | §14.2 (line 10879–10880) | Cargo |
| 174 | `sd_parse_detects_invalid_ace_type` | SD parser detects and rejects an invalid ACE type value | §14.2 (line 10879) | Cargo |
| 175 | `sd_parse_detects_malformed_sid` | SD parser detects and rejects a malformed SID (e.g., sub-authority count exceeds remaining buffer) | §14.2 (line 10879, 10892–10893) | Cargo |
| 176 | `sd_parse_detects_size_mismatch` | SD parser detects and rejects size mismatch in SD/ACL headers | §14.2 (line 10879) | Cargo |
| 177 | `sd_parse_detects_acl_size_exceeding_buffer` | SD parser detects ACL size field exceeding the actual buffer size | §14.2 (line 10880) | Cargo |
| 178 | `sd_parse_any_error_is_corrupt` | Any parse error in the xattr blob produces a corrupt-SD result, not a partial parse | §14.2 (line 10880) | Cargo |

### Group 21: Handle Model Core Logic

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 179 | `granted_mask_subset_check` | Fd-based operation check is `(fd->granted & required) == required`; pass if all required bits present | §14.3 (line 9928–9929) | Cargo |
| 180 | `granted_mask_immutable_after_open` | Granted mask set at open time is immutable for the lifetime of the fd | §14.3 (line 9989, 10490) | Provium |
| 181 | `granted_mask_no_accesscheck_no_sd_read` | Fd-based checks do not call AccessCheck and do not read the SD | §14.3 (line 9929) | Cargo |

### Group 22: Special Filesystem Handling

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 182 | `fat_always_synthesize_mode` | FAT (vfat) uses synthesize mode with mount-level template; every access synthesizes ephemerally | §14.2 (line 9835–9838) | Provium |
| 183 | `ntfs_uses_system_ntfs_security_xattr` | NTFS (ntfs3) reads/writes SD from `system.ntfs_security` xattr; SDs round-trip to Windows | §14.2 (line 9840–9841) | Provium |
| 184 | `tmpfs_supports_xattrs_facs_normal` | tmpfs supports xattrs; FACS works normally with mount root SD set by init | §14.2 (line 9846–9848) | Provium |
| 185 | `devtmpfs_sd_applied_by_udev_helper` | devtmpfs device node SDs are applied by udev `RUN+=` helper after device creation | §14.2 (line 9850–9852) | Provium |
| 186 | `procfs_not_facs_managed_pip_protected` | `/proc` is not FACS-managed; protected by PIP (not SD-based access control) | §14.2 (line 9854) | Provium |
| 187 | `sysfs_writes_require_admin_or_system` | `/sys` uses hardcoded rule: writes require Administrators or SYSTEM | §14.2 (line 9855–9856) | Provium |
| 188 | `nfs_synthesize_mode_with_template` | NFS client mounts use synthesize mode with mount-level template | §14.2 (line 9858–9859) | Provium |
| 189 | `nfs_not_sole_authority` | NFS client mounts: FACS is not sole authority; server enforces independently | §14.2 (line 9862–9864) | Cargo |
| 190 | `nfs_no_post_open_success_guarantee` | NFS client mounts: locally authorized `open()` may produce fd whose `read()` fails server-side | §14.2 (line 9865–9868) | Cargo |

### Group 23: SD Synthesis and Persistence

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 191 | `persist_synthesized_true_writes_xattr` | With `persist_synthesized = true`, synthesized SD is immediately written to `security.peios.sd`; subsequent accesses use persisted SD | §14.2 (line 9817–9820) | Provium |
| 192 | `persist_synthesized_false_caches_only` | With `persist_synthesized = false`, synthesized SD is cached in inode blob only; never written to disk | §14.2 (line 9822–9826) | Provium |
| 193 | `persist_false_staleness_on_parent_change` | With `persist_synthesized = false`, cached synthesized SDs are not recomputed when parent SD or mount template changes | §14.2 (line 9828–9831) | Provium |
| 194 | `hardlink_ambiguity_first_access_wins` | File with multiple hard links under different parents: whichever path is accessed first determines the synthesized SD for all paths (per-inode cache) | §14.2 (line 9802–9812) | Provium |

### Group 24: Unix Socket SD Enforcement

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 195 | `unix_stream_connect_requires_write_data_on_socket` | `connect()` on Unix stream socket checks `FILE_WRITE_DATA` on the listening socket's SD | §14.3 (line 10599) | Provium |
| 196 | `unix_dgram_send_requires_write_data_on_socket` | `sendto()` / `sendmsg()` on Unix dgram checks `FILE_WRITE_DATA` on the socket file's SD | §14.3 (line 10599) | Provium |
| 197 | `abstract_socket_sd_set_at_bind_from_token` | Abstract socket's SD is set at `bind()` time from the binding thread's effective token using default SD template | §14.3 (line 10605–10609) | Provium |
| 198 | `socketpair_no_sd_handle_possession` | `socketpair()` creates sockets with no SD; security is by handle possession | §14.3 (line 10610–10612) | Provium |

### Group 25: Not-FACS-Managed Objects

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 199 | `pipe_not_facs_managed` | `pipe()` / `pipe2()` creates anonymous pipes; no FACS enforcement | §14.4 (line 10849) | Provium |
| 200 | `eventfd_not_facs_managed` | `eventfd()` / `timerfd_create()` / `signalfd()` are anonymous fds; not FACS-managed | §14.4 (line 10850) | Provium |
| 201 | `epoll_inotify_fanotify_not_facs_managed` | `epoll_create()` / `inotify_init()` / `fanotify_init()` are anonymous fds; not FACS-managed | §14.4 (line 10851) | Provium |
| 202 | `socket_not_facs_managed_at_create` | `socket()` creates network sockets; not a filesystem object; Unix sockets gated at connect/send | §14.4 (line 10852) | Provium |
| 203 | `memfd_create_not_facs_managed` | `memfd_create()` creates anonymous memory fd; not FACS-managed | §14.4 (line 10853) | Provium |

### Group 26: Inode Cache Management

| # | Test Name | Assertion | Spec Ref | Type |
|---|-----------|-----------|----------|------|
| 204 | `inode_getsecurity_returns_sd_from_cache_or_xattr` | `security_inode_getsecurity` returns SD data from cache or xattr for kernel-internal reads | §14.3 (line 10590–10591) | Provium |
| 205 | `inode_free_security_rcu_frees_cached_sd` | `inode_free_security_rcu` frees cached SD after RCU grace period | §14.3 (line 10593–10594) | Provium |

---

## Summary

**Total tests: 205**

- **Cargo tests (pure Rust logic, no kernel): 11** — tests 94, 166, 167, 173, 174, 175, 176, 177, 178, 179, 181, 189, 190
- **Provium tests (requires booted KACS kernel): 194** — all remaining tests

The Cargo tests cluster around SD parsing/validation (detecting corrupt SDs in pure data structures) and the granted-mask subset-check logic (pure bitwise operation). Nearly everything else requires a running KACS kernel because the behaviors are enforced by LSM hooks, kernel patches, and syscall-level interactions that cannot be tested outside the kernel.


---

# Section 15: Kernel Interface + Section 16: Derooting + Section 17: Audit Pipeline

## Test Corpus: KACS §15 Kernel Interface, §16 Derooting, §17 Audit Pipeline

---

### §15.1 Syscalls — Token Lifecycle

#### kacs_open_self_token

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 1 | `open_self_token_returns_fd` | `kacs_open_self_token(0, TOKEN_QUERY)` returns a valid token fd | §15.1 | Provium |
| 2 | `open_self_token_no_privilege_required` | An unprivileged thread can open its own token; no privilege gate applies | §15.1 | Provium |
| 3 | `open_self_token_effective_token_default` | With `flags=0`, returns the impersonated token if the thread is impersonating, or the primary token otherwise | §15.1 | Provium |
| 4 | `open_self_token_real_token_flag` | With `KACS_REAL_TOKEN` flag, returns the primary token even when thread is impersonating | §15.1 | Provium |
| 5 | `open_self_token_access_mask_gates_ioctls` | The returned fd's access mask controls which ioctls succeed; requesting TOKEN_QUERY allows QUERY but not ADJUST_PRIVS | §15.1 | Provium |
| 6 | `open_self_token_sd_access_check` | The access mask is checked against the token's own SD (tokens are self-securing objects) | §15.1 | Provium |
| 7 | `open_self_token_returns_neg_errno_on_failure` | Returns `-errno` on failure (e.g., invalid access mask bits that fail the token's SD check) | §15.1 | Provium |

#### kacs_open_process_token

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 8 | `open_process_token_returns_fd` | `kacs_open_process_token(pidfd, TOKEN_QUERY)` returns a valid token fd for another process | §15.1 | Provium |
| 9 | `open_process_token_process_gate` | AccessCheck for `PROCESS_QUERY_INFORMATION` runs against the target process's SD using the caller's effective token | §15.1, §7.9 | Provium |
| 10 | `open_process_token_token_gate` | AccessCheck for the requested access_mask runs against the token's own SD | §15.1, §7.9 | Provium |
| 11 | `open_process_token_denied_without_process_query` | Fails with `-EACCES` if the caller cannot satisfy `PROCESS_QUERY_INFORMATION` on the target process SD | §15.1 | Provium |
| 12 | `open_process_token_denied_without_token_access` | Fails with `-EACCES` if the caller can reach the process but the token SD denies the requested access_mask | §15.1 | Provium |
| 13 | `open_process_token_live_reference` | The returned handle is a live reference (refcounted Arc); privilege adjustments via another handle are visible through this one | §15.1 | Provium |
| 14 | `open_process_token_identity_immutable` | User SID and groups queried through the returned handle are immutable and never change | §15.1 | Provium |
| 15 | `open_process_token_pip_protection` | PIP provides additional protection for high-trust processes; a low-trust caller cannot open a PIP-protected process's token | §15.1 | Provium |

#### kacs_create_token

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 16 | `create_token_returns_fd` | `kacs_create_token` with valid spec returns a token fd | §15.1 | Provium |
| 17 | `create_token_requires_se_create_token_privilege` | Fails with `-EPERM` if the caller's real (primary) token lacks `SeCreateTokenPrivilege` | §15.1 | Provium |
| 18 | `create_token_checks_real_token` | The privilege check is on the real (primary) token, not the impersonated token | §15.1 | Provium |
| 19 | `create_token_wire_format_primary` | A wire-format spec with `token_type=Primary` produces a Primary token | §15.1 | Cargo |
| 20 | `create_token_wire_format_impersonation` | A wire-format spec with `token_type=Impersonation` and an impersonation level produces an Impersonation token | §15.1 | Cargo |
| 21 | `create_token_wire_format_all_fields` | Wire format correctly encodes user SID, group SIDs with attributes, privilege bitmask, owner SID, primary group SID, default DACL, token source, logon session ID, elevation type, mandatory policy | §15.1 | Cargo |
| 22 | `create_token_wire_format_optional_fields` | Wire format accepts optional fields: device groups, AppContainer SID, capabilities | §15.1 | Cargo |
| 23 | `create_token_rejects_malformed_spec` | Returns `-EINVAL` for a malformed/truncated wire-format specification | §15.1 | Provium |

#### kacs_open_peer_token

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 24 | `open_peer_token_returns_fd` | `kacs_open_peer_token(sock_fd)` returns a valid token fd from a connected Unix socket | §15.1 | Provium |
| 25 | `open_peer_token_snapshot_at_connect` | The returned token is a snapshot of the peer's identity at `connect()` time; subsequent changes to the peer's token are not reflected | §15.1 | Provium |
| 26 | `open_peer_token_no_privilege_required` | No privilege required; any thread can call it on a connected socket it owns | §15.1 | Provium |
| 27 | `open_peer_token_impersonation_level_from_socket` | The impersonation level on the returned token matches the level stored on the socket (set by client via `kacs_set_impersonation_level`) | §15.1 | Provium |
| 28 | `open_peer_token_identification_level_inspect_only` | An Identification-level peer token can be inspected (QUERY) but not impersonated | §15.1 | Provium |
| 29 | `open_peer_token_fails_not_connected` | Returns `-errno` on an unconnected or non-Unix socket | §15.1 | Provium |

---

### §15.1 Syscalls — Impersonation

#### kacs_impersonate_peer

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 30 | `impersonate_peer_success` | `kacs_impersonate_peer(sock_fd)` returns 0 and the calling thread is now impersonating the peer | §15.1 | Provium |
| 31 | `impersonate_peer_with_privilege` | If the caller has `SeImpersonatePrivilege`, impersonation proceeds at the level stored on the socket | §15.1, §12.2 | Provium |
| 32 | `impersonate_peer_same_user_fallback` | If the caller lacks `SeImpersonatePrivilege` but the peer token is the same user, impersonation proceeds | §15.1, §12.2 | Provium |
| 33 | `impersonate_peer_same_restriction_fallback` | If the caller lacks `SeImpersonatePrivilege` but the peer token is more restricted, impersonation proceeds | §15.1, §12.2 | Provium |
| 34 | `impersonate_peer_capped_to_identification` | If neither gate passes, the token is capped to Identification level (not rejected) | §15.1, §12.2 | Provium |
| 35 | `impersonate_peer_identification_denies_resource_access` | At Identification level, AccessCheck step 0 denies all resource access | §15.1, §12.2 | Provium |
| 36 | `impersonate_peer_all_four_levels_installable` | All four impersonation levels (Anonymous, Identification, Impersonation, Delegation) are valid installable states | §15.1 | Provium |
| 37 | `impersonate_peer_overwrites_existing` | Calling `kacs_impersonate_peer` while already impersonating does an implicit revert-then-impersonate | §15.1 | Provium |
| 38 | `impersonate_peer_combines_open_impersonate_close` | Functionally equivalent to `kacs_open_peer_token` + `KACS_IOC_IMPERSONATE` + close in one syscall | §15.1 | Provium |

#### kacs_revert

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 39 | `revert_success` | `kacs_revert()` returns 0 and the thread returns to its primary token | §15.1 | Provium |
| 40 | `revert_noop_when_not_impersonating` | Returns 0 (success) when the thread is not impersonating (no-op) | §15.1 | Provium |
| 41 | `revert_no_privilege_required` | No privilege required; any thread can revert to its own primary token | §15.1 | Provium |

#### kacs_set_impersonation_level

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 42 | `set_impersonation_level_success` | `kacs_set_impersonation_level(sock_fd, IMPERSONATION)` returns 0 on an unconnected socket | §15.1 | Provium |
| 43 | `set_impersonation_level_default_impersonation` | Default level is IMPERSONATION (matching Windows) when not explicitly set | §15.1 | Provium |
| 44 | `set_impersonation_level_anonymous` | Level ANONYMOUS (0) is accepted and stored | §15.1 | Provium |
| 45 | `set_impersonation_level_identification` | Level IDENTIFICATION (1) is accepted and stored | §15.1 | Provium |
| 46 | `set_impersonation_level_delegation` | Level DELEGATION (3) is accepted and stored | §15.1 | Provium |
| 47 | `set_impersonation_level_captured_at_connect` | The level is captured into the connection at `connect()` time; changes after connect have no effect | §15.1 | Provium |
| 48 | `set_impersonation_level_fails_after_connect` | Returns `-errno` when called on an already-connected socket | §15.1 | Provium |
| 49 | `set_impersonation_level_delegation_forwards_identity` | Delegation level allows the server to forward the client's identity to other services (impersonated token stored in socket blob) | §15.1 | Provium |
| 50 | `set_impersonation_level_invalid_value` | Returns `-EINVAL` for values outside 0-3 | §15.1 | Provium |

---

### §15.1 Syscalls — Session Management

#### kacs_create_session

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 51 | `create_session_returns_id` | `kacs_create_session` returns a session ID >= 0 | §15.1 | Provium |
| 52 | `create_session_requires_se_tcb_privilege` | Fails with `-EPERM` if caller lacks `SeTcbPrivilege` | §15.1 | Provium |
| 53 | `create_session_auto_logon_sid` | The session receives an auto-generated logon SID `S-1-5-5-{high32}-{low32}` | §15.1 | Provium |
| 54 | `create_session_logon_sid_injected_into_tokens` | The logon SID is injected into the groups of any token associated with the session | §15.1 | Provium |
| 55 | `create_session_zero_is_system` | Session 0 is the SYSTEM session, created at boot by KACS initialization | §15.1 | Provium |
| 56 | `create_session_linked_token_attachment` | Sessions are the attachment point for linked token pairs via `KACS_IOC_LINK_TOKENS` | §15.1 | Provium |

---

### §15.1 Syscalls — File Operations

#### kacs_open

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 57 | `kacs_open_returns_fd` | `kacs_open` with valid params returns a file fd | §15.1 | Provium |
| 58 | `kacs_open_access_check_strict` | Every bit in `desired_access` must be granted by the file's SD or the open fails | §15.1 | Provium |
| 59 | `kacs_open_granted_mask_stamped_on_fd` | The granted mask is stamped on the fd's LSM blob | §15.1 | Provium |
| 60 | `kacs_open_fmode_read_mapping` | `FILE_READ_DATA` maps to `FMODE_READ` | §15.1 | Provium |
| 61 | `kacs_open_fmode_write_mapping` | `FILE_WRITE_DATA` / `FILE_APPEND_DATA` maps to `FMODE_WRITE` | §15.1 | Provium |
| 62 | `kacs_open_fmode_exec_mapping` | `FILE_EXECUTE` (alone) maps to `FMODE_EXEC` | §15.1 | Provium |
| 63 | `kacs_open_disposition_open` | `FILE_OPEN` (1): opens existing file, fails if file doesn't exist | §15.1 | Provium |
| 64 | `kacs_open_disposition_create` | `FILE_CREATE` (2): creates new file, fails if file exists | §15.1 | Provium |
| 65 | `kacs_open_disposition_open_if` | `FILE_OPEN_IF` (3): opens existing file or creates new file | §15.1 | Provium |
| 66 | `kacs_open_disposition_overwrite` | `FILE_OVERWRITE` (4): truncates existing file to zero, fails if file doesn't exist; requires `FILE_WRITE_DATA` | §15.1 | Provium |
| 67 | `kacs_open_disposition_overwrite_if` | `FILE_OVERWRITE_IF` (5): truncates existing or creates new | §15.1 | Provium |
| 68 | `kacs_open_disposition_supersede_new_inode` | `FILE_SUPERSEDE` (0): deletes existing file and creates new one with new inode | §15.1 | Provium |
| 69 | `kacs_open_supersede_requires_delete` | Supersede requires `DELETE` on the existing file (or `FILE_DELETE_CHILD` on the parent) AND `FILE_ADD_FILE` on the parent | §15.1 | Provium |
| 70 | `kacs_open_supersede_breaks_hardlinks` | Supersede creates a new inode; old hardlinks to the old inode are broken | §15.1 | Provium |
| 71 | `kacs_open_supersede_old_fds_see_old_inode` | Already-open fds reference the old (now unlinked) inode with their old granted masks | §15.1 | Provium |
| 72 | `kacs_open_supersede_atomic` | Supersede holds parent directory inode_lock across unlink + create, making it atomic from userspace | §15.1 | Provium |
| 73 | `kacs_open_supersede_failure_rollback` | If any step fails after creation in supersede, the new inode is cleaned up and the old file is untouched | §15.1 | Provium |
| 74 | `kacs_open_sd_from_caller` | If `sd` is non-NULL, the provided SD is used (merged with inheritable ACEs from parent per §9.5) | §15.1 | Provium |
| 75 | `kacs_open_sd_inherited_from_parent` | If `sd` is NULL, the SD is inherited from the parent directory entirely | §15.1 | Provium |
| 76 | `kacs_open_status_out_created` | `status_out` reports `KACS_STATUS_CREATED` when a new file was created | §15.1 | Provium |
| 77 | `kacs_open_status_out_opened` | `status_out` reports `KACS_STATUS_OPENED` when an existing file was opened | §15.1 | Provium |
| 78 | `kacs_open_status_out_overwritten` | `status_out` reports `KACS_STATUS_OVERWRITTEN` when an existing file was truncated | §15.1 | Provium |
| 79 | `kacs_open_status_out_superseded` | `status_out` reports `KACS_STATUS_SUPERSEDED` when an existing file was superseded | §15.1 | Provium |
| 80 | `kacs_open_status_out_null_ok` | If `status_out` is NULL, no status is reported and no error occurs | §15.1 | Provium |
| 81 | `kacs_open_overwrite_preserves_inode` | `FILE_OVERWRITE` / `FILE_OVERWRITE_IF` preserves the same inode, same SD, and hardlinks | §15.1 | Provium |
| 82 | `kacs_open_overwrite_visible_to_existing_fds` | Already-open fds see the truncated file after overwrite | §15.1 | Provium |
| 83 | `kacs_open_at_fdcwd` | `dirfd=AT_FDCWD` resolves path relative to the current working directory | §15.1 | Provium |
| 84 | `kacs_open_directory_file` | `FILE_DIRECTORY_FILE` in create_options constrains the open to directories | §15.1 | Provium |
| 85 | `kacs_open_delete_on_close` | `FILE_DELETE_ON_CLOSE` causes the file to be deleted when the last handle closes | §15.1 | Provium |

#### kacs_get_sd

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 86 | `get_sd_returns_self_relative` | `kacs_get_sd` returns a self-relative SD in the output buffer | §15.1 | Provium |
| 87 | `get_sd_owner_requires_read_control` | `OWNER_SECURITY_INFORMATION` (0x01) requires `READ_CONTROL` | §15.1 | Provium |
| 88 | `get_sd_group_requires_read_control` | `GROUP_SECURITY_INFORMATION` (0x02) requires `READ_CONTROL` | §15.1 | Provium |
| 89 | `get_sd_dacl_requires_read_control` | `DACL_SECURITY_INFORMATION` (0x04) requires `READ_CONTROL` | §15.1 | Provium |
| 90 | `get_sd_sacl_requires_access_system_security` | `SACL_SECURITY_INFORMATION` (0x08) requires `ACCESS_SYSTEM_SECURITY` (which requires `SeSecurityPrivilege`) | §15.1 | Provium |
| 91 | `get_sd_label_requires_read_control_only` | `LABEL_SECURITY_INFORMATION` (0x10) requires only `READ_CONTROL`, not `ACCESS_SYSTEM_SECURITY`, despite labels being stored in the SACL | §15.1 | Provium |
| 92 | `get_sd_two_call_pattern` | First call with `buf_len=0` returns `-ERANGE` and populates `len_needed`; second call with sufficient buffer succeeds | §15.1 | Provium |
| 93 | `get_sd_erange_on_small_buffer` | Returns `-ERANGE` if buffer is too small, with `len_needed` set to the actual size | §15.1 | Provium |
| 94 | `get_sd_at_empty_path_file_fd` | With `AT_EMPTY_PATH` on a normal file fd, operates on the file's SD using the fd's granted mask | §15.1 | Provium |
| 95 | `get_sd_at_empty_path_opath_fd` | With `AT_EMPTY_PATH` on an `O_PATH` fd, operates on the file's SD via a live AccessCheck (not snapshot) | §15.1 | Provium |
| 96 | `get_sd_at_empty_path_socket_fd` | With `AT_EMPTY_PATH` on a socket fd, operates on the socket's SD | §15.1 | Provium |
| 97 | `get_sd_at_empty_path_pidfd` | With `AT_EMPTY_PATH` on a pidfd, operates on the process's SD (§8.4); authorized via `PROCESS_QUERY_INFORMATION` | §15.1 | Provium |
| 98 | `get_sd_at_empty_path_token_fd` | With `AT_EMPTY_PATH` on a token fd, operates on the token's SD; authorized via the token handle's access mask | §15.1 | Provium |
| 99 | `get_sd_file_fd_uses_granted_mask` | For normal file fd with `AT_EMPTY_PATH`, `READ_CONTROL` must be in the fd's granted mask | §15.1 | Provium |
| 100 | `get_sd_opath_no_snapshot_authorization` | O_PATH provides race-free object identity but live authorization (not snapshot) | §15.1 | Provium |

#### kacs_set_sd

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 101 | `set_sd_owner_requires_write_owner` | `OWNER_SECURITY_INFORMATION` requires `WRITE_OWNER` | §15.1 | Provium |
| 102 | `set_sd_group_requires_write_owner` | `GROUP_SECURITY_INFORMATION` requires `WRITE_OWNER` | §15.1 | Provium |
| 103 | `set_sd_dacl_requires_write_dac` | `DACL_SECURITY_INFORMATION` requires `WRITE_DAC` | §15.1 | Provium |
| 104 | `set_sd_sacl_requires_access_system_security` | `SACL_SECURITY_INFORMATION` requires `ACCESS_SYSTEM_SECURITY` (requires `SeSecurityPrivilege`) | §15.1 | Provium |
| 105 | `set_sd_label_requires_write_owner_plus_integrity` | `LABEL_SECURITY_INFORMATION` requires `WRITE_OWNER` plus integrity constraints (§10.3) | §15.1 | Provium |
| 106 | `set_sd_owner_other_sid_requires_se_restore` | Setting owner to a SID other than the caller's own SID or a group with `SE_GROUP_OWNER` requires `SeRestorePrivilege` | §15.1 | Provium |
| 107 | `set_sd_missing_sd_repair` | In deny mode, `kacs_set_sd` with `SeRestorePrivilege` bypasses the missing-SD hard-deny, allowing stamping an SD onto a file with none | §15.1 | Provium |
| 108 | `set_sd_validates_format` | Malformed SDs, invalid SID structures, or ACLs exceeding 64 KB are rejected with `-EINVAL` | §15.1 | Provium |
| 109 | `set_sd_malformed_sid_rejected` | An SD with a structurally invalid SID is rejected with `-EINVAL` | §15.1 | Cargo |
| 110 | `set_sd_acl_exceeding_64kb_rejected` | An ACL exceeding 64 KB is rejected with `-EINVAL` | §15.1 | Cargo |
| 111 | `set_sd_at_empty_path_dispatch` | With `AT_EMPTY_PATH`, the same object-type dispatch as `kacs_get_sd` applies: file fd, O_PATH fd, pidfd, token fd | §15.1 | Provium |

---

### §15.1 Syscalls — AccessCheck

#### kacs_access_check

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 112 | `access_check_returns_zero_on_grant` | Returns 0 when all requested rights are granted | §15.1 | Provium |
| 113 | `access_check_returns_eacces_on_deny` | Returns `-EACCES` when any requested right is denied | §15.1 | Provium |
| 114 | `access_check_granted_out_always_populated` | `granted_out` is populated even on failure, showing which rights were granted | §15.1 | Provium |
| 115 | `access_check_requires_token_query` | The token fd must have `TOKEN_QUERY` access or the call fails | §15.1 | Provium |
| 116 | `access_check_generic_mapping_required` | GenericMapping must be provided; generic bits in ACEs are expanded using the mapping | §15.1 | Cargo |
| 117 | `access_check_generic_read_expansion` | `GENERIC_READ` in an ACE is expanded to the `generic_read` mapping | §15.1 | Cargo |
| 118 | `access_check_generic_write_expansion` | `GENERIC_WRITE` in an ACE is expanded to the `generic_write` mapping | §15.1 | Cargo |
| 119 | `access_check_generic_execute_expansion` | `GENERIC_EXECUTE` in an ACE is expanded to the `generic_execute` mapping | §15.1 | Cargo |
| 120 | `access_check_generic_all_expansion` | `GENERIC_ALL` in an ACE is expanded to the `generic_all` mapping | §15.1 | Cargo |
| 121 | `access_check_self_sid_substitution` | When `self_sid_ptr` is non-null, `PRINCIPAL_SELF` in ACEs is substituted with the provided SID | §15.1 | Cargo |
| 122 | `access_check_privilege_intent_backup` | `KACS_BACKUP_INTENT` in `privilege_intent` enables backup-privilege-granted access | §15.1 | Cargo |
| 123 | `access_check_privilege_intent_restore` | `KACS_RESTORE_INTENT` in `privilege_intent` enables restore-privilege-granted access | §15.1 | Cargo |
| 124 | `access_check_no_privilege_intent_default` | `privilege_intent=0` disables backup/restore privilege grants | §15.1 | Cargo |
| 125 | `access_check_optional_fields_zero` | `self_sid_ptr=0`, `object_tree_ptr=0`, `local_claims_ptr=0` all work (optional fields) | §15.1 | Cargo |
| 126 | `access_check_extensibility_smaller_size` | Older callers with smaller `size` field have missing trailing fields default to zero | §15.1 | Provium |
| 127 | `access_check_extensibility_larger_size` | The kernel accepts a struct with a `size` larger than it knows (future fields), ignoring unknown trailing fields | §15.1 | Provium |
| 128 | `access_check_same_pipeline_as_facs` | Uses the same DACL walk, privilege evaluation, and MIC check as FACS | §15.1 | Cargo |
| 129 | `access_check_object_tree_support` | `object_tree_ptr` with a valid `OBJECT_TYPE_LIST` array enables per-property access decisions | §15.1 | Cargo |
| 130 | `access_check_local_claims_support` | `local_claims_ptr` with claim attributes enables conditional ACE evaluation using `@Local.` references | §15.1 | Cargo |

---

### §15.2 Ioctls on Token Fds

#### Token Access Rights

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 131 | `token_query_right_value` | `TOKEN_QUERY` has value 0x0008 | §15.2 | Cargo |
| 132 | `token_adjust_privileges_right_value` | `TOKEN_ADJUST_PRIVILEGES` has value 0x0020 | §15.2 | Cargo |
| 133 | `token_adjust_groups_right_value` | `TOKEN_ADJUST_GROUPS` has value 0x0040 | §15.2 | Cargo |
| 134 | `token_duplicate_right_value` | `TOKEN_DUPLICATE` has value 0x0002 | §15.2 | Cargo |
| 135 | `token_impersonate_right_value` | `TOKEN_IMPERSONATE` has value 0x0004 | §15.2 | Cargo |
| 136 | `token_assign_primary_right_value` | `TOKEN_ASSIGN_PRIMARY` has value 0x0001 | §15.2 | Cargo |
| 137 | `token_query_source_folded_into_query` | `TOKEN_QUERY_SOURCE` (0x0010) is reserved; TokenSource is queryable with `TOKEN_QUERY`; bit must not be reused | §15.2 | Cargo |

#### KACS_IOC_IMPERSONATE

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 138 | `ioc_impersonate_requires_token_impersonate` | Requires `TOKEN_IMPERSONATE` on the handle; fails without it | §15.2 | Provium |
| 139 | `ioc_impersonate_must_be_impersonation_token` | The token must be an Impersonation token (any level) | §15.2 | Provium |
| 140 | `ioc_impersonate_anonymous_level` | Anonymous-level impersonation token can be installed | §15.2 | Provium |
| 141 | `ioc_impersonate_delegation_level` | Delegation-level impersonation token can be installed | §15.2 | Provium |
| 142 | `ioc_impersonate_two_gate_model` | If caller lacks `SeImpersonatePrivilege` and same-user/same-restriction fallback does not apply, effective level is capped to Identification (not rejected) | §15.2, §12.2 | Provium |
| 143 | `ioc_impersonate_overwrites_existing` | Overwrites any existing impersonation on the calling thread | §15.2 | Provium |

#### KACS_IOC_INSTALL

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 144 | `ioc_install_requires_token_assign_primary` | Requires `TOKEN_ASSIGN_PRIMARY` on the handle | §15.2 | Provium |
| 145 | `ioc_install_requires_se_assign_primary_token` | Requires `SeAssignPrimaryTokenPrivilege` on the caller's real token | §15.2 | Provium |
| 146 | `ioc_install_must_be_primary_token` | The token must be a Primary token | §15.2 | Provium |
| 147 | `ioc_install_commits_creds` | Commits the token as the calling process's primary token via `commit_creds()` | §15.2 | Provium |
| 148 | `ioc_install_process_sd_regen_on_user_change` | When the new token's user SID differs from current, KACS auto-regenerates the process SD using the new token's identity | §15.2, §8.4 | Provium |
| 149 | `ioc_install_process_sd_template` | The default template: new user SID gets `GENERIC_ALL`, Administrators and SYSTEM get `GENERIC_ALL`, Everyone gets `PROCESS_QUERY_LIMITED` | §15.2 | Provium |
| 150 | `ioc_install_process_sd_same_user_no_regen` | When new token's user SID is the same as current, the process SD is NOT regenerated | §15.2 | Provium |

#### KACS_IOC_QUERY

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 151 | `ioc_query_requires_token_query` | Requires `TOKEN_QUERY` on the handle | §15.2 | Provium |
| 152 | `ioc_query_two_call_pattern` | Call with `buf_len=0` gets needed size, second call with buffer gets data | §15.2 | Provium |
| 153 | `ioc_query_token_user` | `TokenUser` class returns the user SID | §15.2 | Provium |
| 154 | `ioc_query_token_groups` | `TokenGroups` class returns array of (SID, attributes) pairs | §15.2 | Provium |
| 155 | `ioc_query_token_privileges` | `TokenPrivileges` class returns privilege bitmask (present, enabled, default, used) | §15.2 | Provium |
| 156 | `ioc_query_token_owner` | `TokenOwner` class returns default owner SID for new objects | §15.2 | Provium |
| 157 | `ioc_query_token_primary_group` | `TokenPrimaryGroup` class returns default primary group SID | §15.2 | Provium |
| 158 | `ioc_query_token_default_dacl` | `TokenDefaultDacl` class returns default DACL for new objects | §15.2 | Provium |
| 159 | `ioc_query_token_source` | `TokenSource` class returns 8-byte name + 64-bit source ID (queryable with `TOKEN_QUERY`, not `TOKEN_QUERY_SOURCE`) | §15.2 | Provium |
| 160 | `ioc_query_token_type` | `TokenType` class returns Primary (1) or Impersonation (2) | §15.2 | Provium |
| 161 | `ioc_query_token_impersonation_level` | `TokenImpersonationLevel` class returns Anonymous/Identification/Impersonation/Delegation | §15.2 | Provium |
| 162 | `ioc_query_token_statistics` | `TokenStatistics` class returns token ID, logon session ID, modified ID, token type, expiration | §15.2 | Provium |
| 163 | `ioc_query_token_restricted_sids` | `TokenRestrictedSids` class returns restricting SID array | §15.2 | Provium |
| 164 | `ioc_query_token_session_id` | `TokenSessionId` class returns logon session ID | §15.2 | Provium |
| 165 | `ioc_query_token_origin` | `TokenOrigin` class returns originating logon session ID | §15.2 | Provium |
| 166 | `ioc_query_token_elevation_type` | `TokenElevationType` class returns Default (1) / Full (2) / Limited (3) | §15.2 | Provium |
| 167 | `ioc_query_token_integrity_level` | `TokenIntegrityLevel` class returns mandatory integrity SID | §15.2 | Provium |
| 168 | `ioc_query_token_mandatory_policy` | `TokenMandatoryPolicy` class returns `NO_WRITE_UP`, `NEW_PROCESS_MIN` flags | §15.2 | Provium |
| 169 | `ioc_query_token_logon_type` | `TokenLogonType` class returns Interactive/Service/Network/etc. | §15.2 | Provium |
| 170 | `ioc_query_token_logon_sid` | `TokenLogonSid` class returns the session's logon SID (`S-1-5-5-x-y`) | §15.2 | Provium |
| 171 | `ioc_query_token_device_groups` | `TokenDeviceGroups` class returns device group SIDs (for claims-based access) | §15.2 | Provium |

#### KACS_IOC_DUPLICATE

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 172 | `ioc_duplicate_requires_token_duplicate` | Requires `TOKEN_DUPLICATE` on the source handle | §15.2 | Provium |
| 173 | `ioc_duplicate_deep_clone` | Deep-clones the token into a new token fd | §15.2 | Provium |
| 174 | `ioc_duplicate_target_type_primary` | Can target Primary token type | §15.2 | Provium |
| 175 | `ioc_duplicate_target_type_impersonation` | Can target Impersonation token type with specified level | §15.2 | Provium |
| 176 | `ioc_duplicate_target_access_mask` | The new handle's access mask is set from the `desired_access` parameter | §15.2 | Provium |
| 177 | `ioc_duplicate_impersonation_to_primary_requires_tcb` | Converting Impersonation to Primary requires `SeTcbPrivilege` | §15.2 | Provium |
| 178 | `ioc_duplicate_impersonation_to_primary_without_tcb_fails` | Converting Impersonation to Primary without `SeTcbPrivilege` fails | §15.2 | Provium |

#### KACS_IOC_ADJUST_PRIVS

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 179 | `ioc_adjust_privs_requires_token_adjust_privileges` | Requires `TOKEN_ADJUST_PRIVILEGES` on the handle | §15.2 | Provium |
| 180 | `ioc_adjust_privs_enable` | Can enable a present-but-disabled privilege | §15.2 | Provium |
| 181 | `ioc_adjust_privs_disable` | Can disable an enabled privilege | §15.2 | Provium |
| 182 | `ioc_adjust_privs_remove_irreversible` | Removal is irreversible; a removed privilege cannot be re-enabled | §15.2 | Provium |
| 183 | `ioc_adjust_privs_cannot_enable_removed` | Cannot enable a privilege that has been removed | §15.2 | Provium |
| 184 | `ioc_adjust_privs_bumps_modified_id` | Bumps the token's `modified_id` | §15.2 | Provium |
| 185 | `ioc_adjust_privs_atomic` | Multiple (privilege_index, action) pairs are applied atomically | §15.2 | Provium |

#### KACS_IOC_ADJUST_GROUPS

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 186 | `ioc_adjust_groups_requires_token_adjust_groups` | Requires `TOKEN_ADJUST_GROUPS` on the handle | §15.2 | Provium |
| 187 | `ioc_adjust_groups_enable` | Can enable a disabled group | §15.2 | Provium |
| 188 | `ioc_adjust_groups_disable` | Can disable a non-mandatory group | §15.2 | Provium |
| 189 | `ioc_adjust_groups_mandatory_cannot_disable` | Mandatory groups (`SE_GROUP_MANDATORY`) cannot be disabled | §15.2 | Provium |
| 190 | `ioc_adjust_groups_bumps_modified_id` | Bumps `modified_id` | §15.2 | Provium |

#### KACS_IOC_RESTRICT

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 191 | `ioc_restrict_requires_token_duplicate` | Requires `TOKEN_DUPLICATE` on the handle | §15.2 | Provium |
| 192 | `ioc_restrict_returns_new_fd` | Returns a new token fd (not the same fd) | §15.2 | Provium |
| 193 | `ioc_restrict_deep_clone` | The restricted token is a deep clone with reduced authority | §15.2 | Provium |
| 194 | `ioc_restrict_deny_only_sids` | SIDs to mark deny-only are correctly applied | §15.2 | Provium |
| 195 | `ioc_restrict_remove_privileges` | Privileges to remove are removed from the restricted token | §15.2 | Provium |
| 196 | `ioc_restrict_restricting_sids` | Restricting SIDs are added, enabling the two-pass AccessCheck (§11) | §15.2 | Provium |
| 197 | `ioc_restrict_two_pass_access_check` | A restricted token triggers the two-pass DACL walk: normal pass intersected with restricting-SID pass | §15.2, §11 | Cargo |

#### KACS_IOC_LINK_TOKENS

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 198 | `ioc_link_tokens_requires_se_tcb_privilege` | Requires `SeTcbPrivilege` | §15.2 | Provium |
| 199 | `ioc_link_tokens_same_session` | Both tokens must belong to the same logon session | §15.2 | Provium |
| 200 | `ioc_link_tokens_different_session_fails` | Fails if the two tokens belong to different logon sessions | §15.2 | Provium |
| 201 | `ioc_link_tokens_stores_arc_clones` | Stores Arc clones on the LogonSession object | §15.2 | Provium |

#### KACS_IOC_GET_LINKED_TOKEN

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 202 | `ioc_get_linked_token_returns_deep_clone` | Returns a deep clone of the partner token | §15.2 | Provium |
| 203 | `ioc_get_linked_token_identification_level` | The returned token is at Identification level | §15.2 | Provium |
| 204 | `ioc_get_linked_token_query_access_only` | The returned handle has `TOKEN_QUERY` access only | §15.2 | Provium |
| 205 | `ioc_get_linked_token_no_impersonate` | The caller can inspect the partner but not impersonate it (Identification level + TOKEN_QUERY only) | §15.2 | Provium |
| 206 | `ioc_get_linked_token_requires_token_query` | No privilege required beyond `TOKEN_QUERY` on the source handle | §15.2 | Provium |

---

### §15.3 LSM Blob Layout

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 207 | `cred_blob_token_refcounted` | The cred blob contains an Arc-managed token pointer; multiple creds can share the same token after fork() | §15.3 | Provium |
| 208 | `cred_blob_prepare_copies_token` | `security_prepare_creds` copies the token pointer and increments refcount | §15.3 | Provium |
| 209 | `cred_blob_free_decrements_refcount` | `security_cred_free` decrements the token's refcount | §15.3 | Provium |
| 210 | `file_blob_granted_immutable` | The file blob's `granted` field is set once at open time and never modified | §15.3 | Provium |
| 211 | `file_blob_continuous_audit` | The file blob's `continuous_audit` field holds alarm ACE bits including bit 25 (no-mmap) | §15.3 | Provium |
| 212 | `inode_blob_sd_rcu_protected` | The inode blob's parsed SD is RCU-protected; updates via `kacs_set_sd` use RCU replacement | §15.3 | Provium |
| 213 | `inode_blob_sd_from_xattr` | The parsed SD is populated on first access from `security.peios.sd` xattr | §15.3 | Provium |
| 214 | `task_blob_proc_sd` | The task blob contains a pointer to the process SD (§8.4) | §15.3 | Provium |
| 215 | `socket_blob_peer_token_captured_at_connect` | Socket blob's `peer_token` is captured in `security_unix_stream_connect` from the connecting thread's effective cred | §15.3 | Provium |
| 216 | `socket_blob_default_impersonation_level` | Socket blob's `max_impersonation_level` defaults to IMPERSONATION | §15.3 | Provium |
| 217 | `socket_blob_socket_sd_at_bind` | Socket blob's `socket_sd` is stamped at `bind()` time for abstract sockets (NULL for pathname/socketpair) | §15.3 | Provium |
| 218 | `file_blob_continuous_audit_no_mmap` | Bit 25 in `continuous_audit` (from alarm ACE) causes mmap to be denied regardless of granted rights | §15.3, §14 | Provium |

---

### §15.4 Inspection Interfaces

#### procfs

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 219 | `procfs_pid_token_shows_primary` | `/proc/<pid>/token` displays the primary token (user SID, groups, privileges, integrity level, token type, logon session ID) | §15.4 | Provium |
| 220 | `procfs_tid_token_shows_effective` | `/proc/<pid>/task/<tid>/token` displays the effective (impersonated) token if the thread is impersonating | §15.4 | Provium |
| 221 | `procfs_token_access_gated` | Access to `/proc/<pid>/token` is gated by AccessCheck for `PROCESS_QUERY_INFORMATION` against the target process SD, plus PIP trust level comparison | §15.4 | Provium |
| 222 | `procfs_self_token_always_readable` | `/proc/self/token` is always readable (own token) | §15.4 | Provium |
| 223 | `procfs_token_not_weaker_than_syscall` | procfs token inspection does not provide a weaker authorization path than the `kacs_open_process_token` syscall | §15.4 | Provium |

#### securityfs

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 224 | `securityfs_self_readable` | `/sys/kernel/security/kacs/self` shows the calling thread's effective token | §15.4 | Provium |
| 225 | `securityfs_self_always_readable` | Reading own token via securityfs is always allowed | §15.4 | Provium |
| 226 | `securityfs_sessions_lists_sessions` | `/sys/kernel/security/kacs/sessions` lists active logon sessions with session ID, user SID, logon type, logon time | §15.4 | Provium |
| 227 | `securityfs_sessions_requires_admin_or_system` | Reading sessions requires Administrators or SYSTEM | §15.4 | Provium |

---

### §15.5 Build Configuration

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 228 | `config_kacs_enabled` | `CONFIG_SECURITY_KACS=y` enables the KACS LSM | §15.5 | Provium |
| 229 | `config_rust_required` | `CONFIG_RUST=y` is required for the AccessCheck engine | §15.5 | Provium |
| 230 | `config_no_selinux` | `CONFIG_SECURITY_SELINUX=n` is required | §15.5 | Provium |
| 231 | `config_no_apparmor` | `CONFIG_SECURITY_APPARMOR=n` is required | §15.5 | Provium |
| 232 | `config_no_bpf_lsm` | `CONFIG_BPF_LSM=n` is required | §15.5 | Provium |
| 233 | `config_lsm_stack` | `CONFIG_LSM="commoncap,kacs"` is the exact LSM stack | §15.5 | Provium |
| 234 | `config_rejects_unexpected_lsm` | KACS verifies the LSM stack at initialization and refuses to activate if any unexpected LSM is present | §15.5 | Provium |

---

### §15.6 Kernel Patches

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 235 | `patch12_do_dentry_open_desired_access` | `do_dentry_open` accepts KACS `desired_access` and sets `f_mode` from granted mask instead of open flags | §15.6 | Provium |
| 236 | `patch13_pidfd_getfd_mode` | `pidfd_getfd()` uses `PTRACE_MODE_GETFD` flag to distinguish fd extraction from ptrace attach | §15.6 | Provium |
| 237 | `patch14_current_fsuid_projected` | `current_fsuid()` returns projected UID from KACS token instead of `cred->fsuid` | §15.6, §16.2 | Provium |
| 238 | `patch15_execveat_file_execute` | `execveat` / `do_open_execat` with `AT_EMPTY_PATH` checks `FILE_EXECUTE` on the original fd's granted mask | §15.6 | Provium |
| 239 | `patch16_fchdir_file_traverse` | `fchdir()` / `vfs_fchdir()` has a new `security_file_fchdir` hook that checks `FILE_TRAVERSE` in granted mask | §15.6 | Provium |

---

### §15.7 Boot Sequence

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 240 | `boot_lsm_registration_second_after_commoncap` | KACS registers as the second LSM after commoncap | §15.7 | Provium |
| 241 | `boot_lsm_stack_verification` | KACS verifies the LSM stack; if an unexpected LSM is present, KACS logs error and does not activate | §15.7 | Provium |
| 242 | `boot_system_session_zero` | Session 0 is created with `logon_type=SERVICE`, `user_sid=S-1-5-18`, `auth_package="Negotiate"` | §15.7 | Provium |
| 243 | `boot_system_session_logon_sid` | Session 0's logon SID is `S-1-5-5-0-0` | §15.7 | Provium |
| 244 | `boot_system_token_user` | The SYSTEM token has `user=S-1-5-18` (Local System) | §15.7 | Provium |
| 245 | `boot_system_token_all_privileges` | The SYSTEM token has all 35 privileges enabled | §15.7 | Provium |
| 246 | `boot_system_token_integrity` | The SYSTEM token has `integrity=S-1-16-16384` (System) | §15.7 | Provium |
| 247 | `boot_system_token_primary` | The SYSTEM token has `token_type=Primary` | §15.7 | Provium |
| 248 | `boot_system_token_session_id` | The SYSTEM token has `logon_session_id=0` | §15.7 | Provium |
| 249 | `boot_system_token_groups` | The SYSTEM token includes groups: `S-1-5-32-544` (Administrators), `S-1-1-0` (Everyone), `S-1-5-11` (Authenticated Users) | §15.7 | Provium |
| 250 | `boot_init_attachment` | The SYSTEM token is attached to the init process's cred via `commit_creds()` | §15.7 | Provium |
| 251 | `boot_init_children_inherit` | All processes forked from init inherit the SYSTEM token | §15.7 | Provium |
| 252 | `boot_implementation_caps_asserted` | Six implementation capabilities are asserted on the SYSTEM cred: `CAP_DAC_OVERRIDE`, `CAP_DAC_READ_SEARCH`, `CAP_FOWNER`, `CAP_CHOWN`, `CAP_SETUID`, `CAP_SETGID` | §15.7 | Provium |
| 253 | `boot_everything_system_phase` | Between init attachment and authd startup, all file access succeeds (SYSTEM has all rights) | §15.7 | Provium |

---

### §16.1 The Projected UID

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 254 | `projected_uid_on_token` | Every KACS token carries a projected UID derived from the token's user SID via authd's projection system | §16.1 | Provium |
| 255 | `projected_uid_not_authorization` | The projected UID is not an authorization primitive; KACS tokens are the sole authorization mechanism | §16.1 | Provium |
| 256 | `projected_uid_stored_on_token_object` | The projected UID is stored on the token object and available through the KACS credential blob | §16.1 | Provium |

---

### §16.2 The current_fsuid() Patch

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 257 | `current_fsuid_returns_projected_uid` | When KACS is active, `current_fsuid()` returns the projected UID from the KACS token, not `cred->fsuid` | §16.2 | Provium |
| 258 | `current_fsuid_static_branch` | The check uses `static_branch_unlikely` for near-zero-cost; when KACS is not configured, compiled out entirely | §16.2 | Provium |
| 259 | `current_fsuid_inode_init_owner` | Files created by a process are owned by the projected UID, not `cred->fsuid` | §16.2 | Provium |
| 260 | `current_fsuid_disk_quotas` | Disk quotas (ext4, XFS) track usage against the projected UID | §16.2 | Provium |
| 261 | `current_fsuid_kernel_keyring` | Per-user keyrings (`_uid.<uid>`) are keyed by the projected UID | §16.2 | Provium |
| 262 | `current_fsuid_nfs_client` | NFS RPC credentials use the projected UID, not UID 0 | §16.2 | Provium |
| 263 | `current_fsuid_capable_wrt_inode` | `capable_wrt_inode_uidgid` ("Are you the owner?") matches against the projected UID | §16.2 | Provium |
| 264 | `current_fsuid_uid0_interaction` | After `uid0` sets `cred->fsuid` to 0, `current_fsuid()` still returns the projected UID; files are owned by the real user | §16.2 | Provium |
| 265 | `current_fsuid_ignores_setfsuid` | `setfsuid()` changes `cred->fsuid` but `current_fsuid()` ignores it and returns the projected UID | §16.2, §16.6 | Provium |

---

### §16.3 The uid0 Utility

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 266 | `uid0_getuid_returns_zero` | A program run under `uid0` sees `getuid() == 0` | §16.3 | Provium |
| 267 | `uid0_token_unaffected` | The KACS token is unaffected by `uid0`; the program runs with its real identity for access control | §16.3 | Provium |
| 268 | `uid0_no_kacs_privilege_required` | `uid0` requires no special KACS privilege because UIDs carry no authorization meaning | §16.3 | Provium |
| 269 | `uid0_uses_cap_setuid` | `uid0` uses `setuid(0)` under the hood, which requires `CAP_SETUID` (granted universally by KACS) | §16.3 | Provium |
| 270 | `uid0_file_ownership_projected` | Files created by a uid0 process are owned by the projected UID, not UID 0 | §16.3 | Provium |

---

### §16.4 Subsystem-by-Subsystem Analysis

#### Disk Quotas

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 271 | `quotas_track_projected_uid` | ext4/XFS quotas track disk usage against the projected UID (via `inode->i_uid` set by the `current_fsuid()` patch) | §16.4 | Provium |
| 272 | `quotas_no_subsystem_changes` | No changes to the quota subsystem itself are needed | §16.4 | Provium |

#### Kernel Keyring

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 273 | `keyring_per_user_projected_uid` | Per-user keyrings (`@u`, `@us`) are keyed by the projected UID | §16.4 | Provium |
| 274 | `keyring_session_process_unaffected` | Session and process keyrings (`@s`, `@p`, `@t`) are not UID-based and are unaffected by derooting | §16.4 | Provium |

#### File Ownership

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 275 | `file_ownership_ls_shows_projected_uid` | `ls -l` shows the projected UID (resolved to username via `/etc/passwd` or NSS) | §16.4 | Provium |
| 276 | `file_ownership_chown_via_write_owner` | `chown` semantics are handled by FACS (`WRITE_OWNER` on the SD), not by UID comparison | §16.4 | Provium |

#### SysV IPC

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 277 | `sysv_ipc_sd_at_creation` | Each SysV IPC object receives a default SD at creation (creator full control, Administrators/SYSTEM full control) | §16.4 | Provium |
| 278 | `sysv_ipc_access_check` | Every SysV IPC operation is checked via AccessCheck against the object's SD (via `security_ipc_permission` LSM hook) | §16.4 | Provium |

#### nftables UID Matching

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 279 | `nftables_uid_sees_cosmetic_uid` | nftables `meta skuid` matches against `cred->uid` (cosmetic UID), not the projected UID | §16.4 | Provium |
| 280 | `nftables_uid0_matches_zero` | uid0 processes match as UID 0 in nftables UID matching | §16.4 | Provium |

#### Programs Calling setuid()

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 281 | `setuid_cosmetic_only` | A daemon calling `setuid(service_uid)` changes `cred->uid`/`cred->euid`/`cred->fsuid` but the KACS token is unchanged | §16.4 | Provium |
| 282 | `setuid_getuid_returns_new_uid` | After `setuid()`, `getuid()` returns the new UID; the program is satisfied | §16.4 | Provium |
| 283 | `setuid_fsuid_returns_projected` | After `setuid()`, `current_fsuid()` still returns the projected UID from the token (not affected by setuid) | §16.4 | Provium |
| 284 | `setuid_files_owned_by_projected_uid` | Files created after `setuid()` are owned by the projected UID, not the new UID | §16.4 | Provium |
| 285 | `setuid_dac_bypass_irremovable` | DAC bypass capabilities are irremovable even after `setuid()` | §16.4 | Provium |

---

### §16.5 Kernel Patch Summary

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 286 | `patch14_ci_test` | File created by a uid0 process is owned by the projected UID, not UID 0 (CI test assertion) | §16.5 | Provium |

---

### §16.6 What Does Not Work

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 287 | `quota_split_on_token_change` | If a process changes its KACS token via `KACS_IOC_INSTALL`, the projected UID changes; files before and after are owned by different UIDs | §16.6 | Provium |
| 288 | `setfsuid_noop_for_filesystem` | `setfsuid()` becomes a no-op for filesystem purposes; `current_fsuid()` returns the projected UID regardless | §16.6 | Provium |
| 289 | `nftables_uid0_matches_zero_known_limitation` | Legacy nftables UID rules match the cosmetic UID; uid0 processes match as UID 0 (known limitation) | §16.6 | Provium |

---

### §17.1 Architecture

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 290 | `audit_three_layers` | Audit pipeline has three layers: emitters, ring buffer, eventd | §17.1 | Provium |
| 291 | `audit_ring_buffer_kernel_stamps_identity` | The kernel stamps every event with trusted metadata (identity, timestamp, sequence) | §17.1 | Provium |
| 292 | `audit_emitter_identity_unforgeable` | The emitter's identity is unforgeable in the ring buffer | §17.1 | Provium |
| 293 | `audit_timestamp_authoritative` | The timestamp in the event header is authoritative (kernel-stamped) | §17.1 | Provium |
| 294 | `audit_sequence_monotonic` | The sequence number is monotonic | §17.1 | Provium |
| 295 | `audit_event_subsystem_independent` | The event infrastructure is a separate PKM subsystem, not part of KACS itself | §17.1 | Provium |

---

### §17.2 Event Format

#### Kernel Header

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 296 | `event_header_sequence_monotonic_never_reused` | `sequence` is monotonic and never reused; a gap indicates lost events | §17.2 | Provium |
| 297 | `event_header_timestamp_clock_monotonic` | `timestamp_ns` uses `CLOCK_MONOTONIC` nanoseconds | §17.2 | Provium |
| 298 | `event_header_emitter_pid_kernel_verified` | `emitter_pid` is kernel-verified from `current` | §17.2 | Provium |
| 299 | `event_header_emitter_tid_kernel_verified` | `emitter_tid` is kernel-verified from `current` | §17.2 | Provium |
| 300 | `event_header_emitter_uid_projected` | `emitter_uid` is the projected UID from the token (kernel-verified) | §17.2 | Provium |
| 301 | `event_header_size_32_bytes` | Header struct is 28 bytes padded to 32 | §17.2 | Cargo |
| 302 | `event_header_source_kernel_or_userspace` | `source` field is `PEIOS_EVENT_SOURCE_KERNEL` or `_USERSPACE` | §17.2 | Cargo |
| 303 | `event_header_forged_identity_impossible` | A compromised service calling `event_emit` gets its real token identity stamped, not whatever identity it claims in the payload | §17.2 | Provium |

#### Event Body

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 304 | `event_body_opaque_to_kernel` | The kernel treats the body as opaque except for the event ID prefix check | §17.2 | Provium |
| 305 | `event_body_event_id_prefix_check` | The kernel reads the event ID from a fixed position at the start of the body (msgpack string, first element) to enforce reserved namespace restrictions | §17.2 | Provium |
| 306 | `event_body_reserved_namespace_kacs` | `kacs.*` event IDs are reserved for kernel-originated events | §17.2 | Provium |
| 307 | `event_body_reserved_namespace_kernel` | `kernel.*` event IDs are reserved for kernel-originated events | §17.2 | Provium |
| 308 | `event_body_userspace_namespace` | Userspace services use their own namespace (`authd.*`, `registryd.*`, `lpsd.*`, etc.) | §17.2 | Provium |
| 309 | `event_body_msgpack_serialized` | The body is serialized using msgpack | §17.2 | Cargo |
| 310 | `event_body_contains_event_id` | The body contains an event ID string (e.g., `"kacs.access_check.denied"`) | §17.2 | Cargo |
| 311 | `event_body_contains_categories` | The body contains an arbitrary list of category strings | §17.2 | Cargo |
| 312 | `event_body_contains_fields` | The body contains arbitrary key-value pairs for event data | §17.2 | Cargo |

---

### §17.3 The event_emit Syscall

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 313 | `event_emit_returns_zero_on_success` | `event_emit` returns 0 on success | §17.3 | Provium |
| 314 | `event_emit_max_body_8kb` | Returns `-EINVAL` if `body_len` exceeds 8 KB | §17.3 | Provium |
| 315 | `event_emit_enospc_on_overflow` | Returns `-ENOSPC` if ring buffer is full and overflow policy dropped the event | §17.3 | Provium |
| 316 | `event_emit_eperm_reserved_namespace` | Returns `-EPERM` if the event ID uses a reserved namespace (`kacs.*` or `kernel.*`) from userspace | §17.3 | Provium |
| 317 | `event_emit_validates_body_len` | Step 1: validates `body_len <= 8 KB` | §17.3 | Provium |
| 318 | `event_emit_checks_namespace` | Step 2: reads event ID prefix to check namespace reservation | §17.3 | Provium |
| 319 | `event_emit_allocates_header_plus_body` | Step 3: allocates `sizeof(header) + body_len` in the ring buffer | §17.3 | Provium |
| 320 | `event_emit_stamps_header` | Step 4: stamps header with sequence number, `ktime_get_ns()` timestamp, PID/TID, projected UID | §17.3 | Provium |
| 321 | `event_emit_copies_body` | Step 5: copies body via `copy_from_user()` | §17.3 | Provium |
| 322 | `event_emit_advances_write_ptr` | Step 6: advances the write pointer | §17.3 | Provium |
| 323 | `event_emit_notifies_eventd` | Step 7: notifies eventd via eventfd if blocked on poll | §17.3 | Provium |
| 324 | `event_emit_kernel_internal_skips_namespace` | Kernel-originated events via `peios_event_emit_kernel()` skip the syscall overhead and namespace check | §17.3 | Provium |
| 325 | `event_emit_kernel_internal_same_buffer` | Kernel internal events go to the same ring buffer with same header format | §17.3 | Provium |

---

### §17.4 Ring Buffer Mechanism

#### Structure

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 326 | `ring_buffer_default_4mb` | Default ring buffer size is 4 MB (configurable via boot parameter or securityfs) | §17.4 | Provium |
| 327 | `ring_buffer_status_page_read_only` | Status page (`write_ptr`, `overflow_count`, `buffer_size`) is mapped read-only for eventd | §17.4 | Provium |
| 328 | `ring_buffer_consumer_page_read_write` | Consumer page (`read_ptr`) is mapped read-write for eventd | §17.4 | Provium |
| 329 | `ring_buffer_event_data_read_only` | Event data region is mapped read-only for eventd | §17.4 | Provium |
| 330 | `ring_buffer_separate_page_mappings` | Status page and consumer page are separate mappings with different permissions | §17.4 | Provium |
| 331 | `ring_buffer_read_ptr_only_forward` | The kernel validates that `read_ptr` only moves forward and does not exceed `write_ptr` | §17.4 | Provium |
| 332 | `ring_buffer_compromised_eventd_cannot_falsify_write_ptr` | A compromised eventd can advance `read_ptr` (skip events) but cannot falsify `write_ptr`, `overflow_count`, or `buffer_size` | §17.4 | Provium |
| 333 | `ring_buffer_atomic_pointers` | Both pointers are atomic u64s; no locks needed for single-producer/single-consumer | §17.4 | Provium |
| 334 | `ring_buffer_mapped_via_securityfs` | The buffer is mapped into eventd via `/sys/kernel/security/peios/events` | §17.4 | Provium |

#### Notification

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 335 | `ring_buffer_eventfd_notification` | When the kernel writes an event, it increments an eventfd counter | §17.4 | Provium |
| 336 | `ring_buffer_eventd_epoll` | eventd blocks on `epoll_wait()` on the eventfd | §17.4 | Provium |
| 337 | `ring_buffer_batch_wakeup` | One wakeup per batch, not per event; eventd drains all available events from `read_ptr` to `write_ptr` | §17.4 | Provium |

#### Overflow Policy — best_effort

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 338 | `overflow_best_effort_default` | `best_effort` is the default overflow policy | §17.4 | Provium |
| 339 | `overflow_best_effort_advances_read_ptr` | When buffer is full, kernel advances `read_ptr` past oldest events to make room | §17.4 | Provium |
| 340 | `overflow_best_effort_increments_count` | `overflow_count` is incremented when events are discarded | §17.4 | Provium |
| 341 | `overflow_best_effort_sequence_gap` | eventd detects the gap via sequence numbers and logs a warning | §17.4 | Provium |
| 342 | `overflow_best_effort_system_continues` | The system continues operating after overflow in best_effort mode | §17.4 | Provium |

#### Overflow Policy — audit_required

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 343 | `overflow_audit_required_uses_overflow_space` | When buffer is full, kernel uses pre-allocated overflow space (default 512 KB) | §17.4 | Provium |
| 344 | `overflow_audit_required_overflow_allocated_at_boot` | The overflow region is allocated at boot alongside the main buffer | §17.4 | Provium |
| 345 | `overflow_audit_required_no_remap` | The overflow region is part of the original mmap'd allocation; eventd's mapping remains valid | §17.4 | Provium |
| 346 | `overflow_audit_required_buffer_size_updated` | The `buffer_size` field in the shared header is updated atomically to reflect expanded logical size | §17.4 | Provium |
| 347 | `overflow_audit_required_policy_switches_to_best_effort` | After using overflow space, the policy switches to `best_effort` for the remainder of the boot | §17.4 | Provium |
| 348 | `overflow_audit_required_signals_peinit_shutdown` | The kernel signals peinit to initiate a normal shutdown sequence | §17.4 | Provium |
| 349 | `overflow_audit_required_shutdown_events_captured` | Shutdown events are captured in the expanded buffer during peinit shutdown | §17.4 | Provium |
| 350 | `overflow_audit_required_crash_file` | After peinit completes shutdown, the kernel flushes ring buffer to `/var/log/peios/audit-crash` with a SYSTEM-only SD | §17.4 | Provium |
| 351 | `overflow_audit_required_safe_mode_on_reboot` | On next boot, peinit detects the `audit-crash` file and boots into safe mode (minimal services, admin-only access) | §17.4 | Provium |
| 352 | `overflow_audit_required_crash_file_ingested` | eventd ingests the crash file into its normal SQLite storage on the next boot | §17.4 | Provium |
| 353 | `overflow_audit_required_crash_file_deleted_after_drain` | Once the crash file is fully drained, peinit deletes it and transitions to normal mode | §17.4 | Provium |
| 354 | `overflow_policy_configurable` | Overflow policy is configurable via `/sys/kernel/security/peios/events/overflow_policy` | §17.4 | Provium |

---

### §17.5 eventd Drain Contract

#### Liveness

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 355 | `eventd_heartbeat_interval` | eventd writes a monotonic heartbeat timestamp at a fixed interval (default 1 second) regardless of whether events exist | §17.5 | Provium |
| 356 | `eventd_peinit_monitors_heartbeat_and_backlog` | peinit monitors both the heartbeat and the backlog (`write_ptr - read_ptr`) | §17.5 | Provium |
| 357 | `eventd_restart_both_conditions` | peinit kills and restarts eventd (SIGKILL) only if BOTH conditions are true: heartbeat stale (default 10s) AND unread events exist | §17.5 | Provium |
| 358 | `eventd_long_fsync_no_restart` | A long fsync or SQLite checkpoint does not trigger restart as long as heartbeat continues | §17.5 | Provium |
| 359 | `eventd_idle_no_restart` | On an idle system with no events, no liveness action is taken; a healthy idle eventd is not restarted | §17.5 | Provium |

#### Crash Recovery

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 360 | `eventd_ring_buffer_survives_crash` | The ring buffer is kernel memory; it survives eventd restarts | §17.5 | Provium |
| 361 | `eventd_new_instance_continues_draining` | A new eventd instance maps the same buffer and continues draining | §17.5 | Provium |

#### Durability Protocol

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 362 | `eventd_read_ptr_after_commit` | eventd advances `read_ptr` only AFTER the corresponding SQLite transaction has committed | §17.5 | Provium |
| 363 | `eventd_durability_ordering` | Ordering: read batch, INSERT into SQLite in transaction, COMMIT (fsync via WAL), then advance `read_ptr` | §17.5 | Provium |
| 364 | `eventd_crash_recovery_dedup` | If eventd crashes between commit and read_ptr advance, new eventd re-reads events; `INSERT OR IGNORE` on sequence number deduplicates | §17.5 | Provium |
| 365 | `eventd_crash_recovery_last_committed_sequence` | New eventd reads `last_committed_sequence` from SQLite and advances `read_ptr` to the event after that sequence | §17.5 | Provium |
| 366 | `eventd_batching` | eventd writes in batches (configurable, default 100-1000 events per transaction) | §17.5 | Provium |

#### Storage

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 367 | `eventd_sqlite_path` | Events stored in SQLite at `/var/log/peios/events.db` | §17.5 | Provium |
| 368 | `eventd_header_fields_indexed` | Kernel header fields (sequence, timestamp, emitter PID/TID/UID) are mapped to indexed columns | §17.5 | Provium |
| 369 | `eventd_body_deserialized` | Event body is deserialized from msgpack and stored as structured columns (event_id, categories, fields) | §17.5 | Provium |

---

### §17.6 Kernel-Originated Events

#### KACS Events (kacs.*)

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 370 | `kacs_event_access_check_allowed` | `kacs.access_check.allowed` emitted when SACL audit ACE matches and access is granted; contains object, desired, granted, token user | §17.6 | Provium |
| 371 | `kacs_event_access_check_denied` | `kacs.access_check.denied` emitted when access is denied; contains object, desired, token user, deny reason | §17.6 | Provium |
| 372 | `kacs_event_privilege_used` | `kacs.privilege.used` emitted when a privilege contributes to the access decision; contains privilege name, object, granted bits | §17.6 | Provium |
| 373 | `kacs_event_privilege_adjusted` | `kacs.privilege.adjusted` emitted when a privilege is enabled/disabled/removed; contains token, privilege, action | §17.6 | Provium |
| 374 | `kacs_event_token_created` | `kacs.token.created` emitted when a new token is minted; contains token ID, user SID, source | §17.6 | Provium |
| 375 | `kacs_event_token_installed` | `kacs.token.installed` emitted when a primary token is replaced; contains process, old token, new token | §17.6 | Provium |
| 376 | `kacs_event_token_impersonated` | `kacs.token.impersonated` emitted when a thread begins impersonation; contains thread, impersonated SID, level | §17.6 | Provium |
| 377 | `kacs_event_token_reverted` | `kacs.token.reverted` emitted when a thread ends impersonation; contains thread | §17.6 | Provium |
| 378 | `kacs_event_session_created` | `kacs.session.created` emitted when a new logon session is created; contains session ID, user SID, logon type | §17.6 | Provium |
| 379 | `kacs_event_sd_modified` | `kacs.sd.modified` emitted when an SD is changed; contains object, security_info, modifier SID | §17.6 | Provium |
| 380 | `kacs_event_process_access` | `kacs.process.access` emitted on a process SD access check; contains source PID, target PID, right, result | §17.6 | Provium |

#### Kernel Events (kernel.*)

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 381 | `kernel_event_module_load` | `kernel.module.load` emitted when a kernel module is loaded; contains module name, loader PID | §17.6 | Provium |
| 382 | `kernel_event_audit_overflow` | `kernel.audit.overflow` emitted on ring buffer overflow; contains events_dropped, policy | §17.6 | Provium |
| 383 | `kernel_event_audit_shutdown` | `kernel.audit.shutdown` emitted when audit_required shutdown is initiated; contains events_in_buffer | §17.6 | Provium |

---

### §17.7 Userspace Event Emission

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 384 | `userspace_event_emit_via_syscall` | Userspace services emit events via the `event_emit` syscall | §17.7 | Provium |
| 385 | `userspace_event_kernel_stamps_not_in_body` | Kernel-stamped fields (sequence, timestamp, emitter identity) are not included in the emitter's body; they are added by the kernel | §17.7 | Provium |
| 386 | `userspace_event_cannot_override_stamps` | An emitter cannot override or forge kernel-stamped fields | §17.7 | Provium |

---

### §17.8 Tamper Resistance

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 387 | `tamper_emitter_identity_unforgeable` | The kernel stamps every event with the calling thread's real token identity; a compromised service cannot claim to be different | §17.8 | Provium |
| 388 | `tamper_event_data_immutable` | Event data region and status page are mapped read-only from userspace | §17.8 | Provium |
| 389 | `tamper_eventd_write_only_read_ptr` | eventd has write access only to `read_ptr` on the consumer page; cannot modify events or kernel metadata | §17.8 | Provium |
| 390 | `tamper_skipped_events_visible` | Skipped events produce sequence number gaps visible in the database | §17.8 | Provium |
| 391 | `tamper_sqlite_append_only` | eventd inserts events but does not delete or modify them during normal operation | §17.8 | Provium |
| 392 | `tamper_ring_buffer_survives_crash` | Buffer is kernel memory; eventd crashing does not lose events | §17.8 | Provium |
| 393 | `tamper_sequence_numbers_detect_gaps` | If events are lost (overflow in best_effort mode), the gap is visible in sequence numbers; eventd logs a warning | §17.8 | Provium |
| 394 | `tamper_audit_required_guarantees_completeness` | In audit_required mode, the system shuts down rather than operate without audit; ring buffer is flushed to crash file before reboot | §17.8 | Provium |

---

### §11.10 / §17 Cross-Reference — SACL Evaluation (Audit ACE Matching)

These tests cover the SACL evaluation rules referenced from §17 but specified in §11.10 and §9.3. Included here because the task explicitly asks for audit ACE matching, SACL evaluation rules, mandatory label ACEs, resource attribute ACEs, and alarm ACEs.

#### Access Auditing (SACL Audit ACEs)

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 395 | `sacl_audit_sid_matching_deny_polarity` | Audit ACE SID is matched using deny polarity (broadest identity view: deny-only and disabled-but-deny-only groups are visible) | §11.10 | Cargo |
| 396 | `sacl_audit_mask_overlap_success` | For success auditing: the audit ACE's mask overlaps with the granted bits (access result) | §11.10 | Cargo |
| 397 | `sacl_audit_mask_overlap_failure` | For failure auditing: the audit ACE's mask overlaps with the denied bits | §11.10 | Cargo |
| 398 | `sacl_audit_success_flag` | `SUCCESSFUL_ACCESS_ACE_FLAG` (0x40) audits granted access | §11.10 | Cargo |
| 399 | `sacl_audit_failure_flag` | `FAILED_ACCESS_ACE_FLAG` (0x80) audits denied access | §11.10 | Cargo |
| 400 | `sacl_audit_both_flags` | An ACE with both 0x40 and 0x80 audits every matching access attempt | §11.10 | Cargo |
| 401 | `sacl_audit_failure_only_detects_unauthorized` | An ACE with only the failure flag audits denied attempts (unauthorized access detection) | §11.10 | Cargo |
| 402 | `sacl_audit_purely_observational` | Auditing does not affect the access decision; audit ACEs do not grant or deny rights | §11.10 | Cargo |
| 403 | `sacl_audit_after_access_decision` | Audit ACEs are evaluated after the access decision is final | §11.10 | Cargo |
| 404 | `sacl_audit_ace_basic_type` | SYSTEM_AUDIT (0x02) basic audit ACE is recognized | §11.10, §9.3 | Cargo |
| 405 | `sacl_audit_ace_object_type` | SYSTEM_AUDIT_OBJECT (0x07) object-scoped audit ACE targets specific properties via GUIDs | §11.10, §9.3 | Cargo |
| 406 | `sacl_audit_ace_conditional_type` | SYSTEM_AUDIT_CALLBACK (0x0D) conditional audit ACE carries an expression | §11.10, §9.3 | Cargo |
| 407 | `sacl_audit_ace_conditional_object_type` | SYSTEM_AUDIT_CALLBACK_OBJECT (0x0F) conditional object-scoped audit ACE | §11.10, §9.3 | Cargo |
| 408 | `sacl_conditional_audit_unknown_emits` | For conditional audit ACEs, expression evaluating to UNKNOWN results in the event being emitted (when in doubt, audit) | §11.10, §11.12 | Cargo |
| 409 | `sacl_conditional_audit_false_skips` | For conditional audit ACEs, expression evaluating to FALSE skips the event | §11.10, §11.12 | Cargo |

#### Continuous Auditing (Alarm ACEs)

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 410 | `alarm_ace_continuous_audit_mask` | When an alarm ACE's SID matches the caller, the ACE's access mask is recorded as a continuous audit mask on the open handle | §11.10 | Provium |
| 411 | `alarm_ace_per_operation_check` | On each subsequent operation (read, write, execute), the enforcement point checks the handle's continuous audit mask | §11.10 | Provium |
| 412 | `alarm_ace_emit_on_match` | If the operation matches the continuous audit mask, an audit event is emitted | §11.10 | Provium |
| 413 | `alarm_ace_no_mask_zero_cost` | Objects without alarm ACEs have a zero continuous audit mask; no per-operation cost | §11.10 | Provium |
| 414 | `alarm_ace_basic_type` | SYSTEM_ALARM (0x03) basic continuous audit ACE | §9.3 | Cargo |
| 415 | `alarm_ace_object_type` | SYSTEM_ALARM_OBJECT (0x08) object-scoped continuous audit ACE | §9.3 | Cargo |
| 416 | `alarm_ace_conditional_type` | SYSTEM_ALARM_CALLBACK (0x0E) conditional continuous audit ACE | §9.3 | Cargo |
| 417 | `alarm_ace_conditional_object_type` | SYSTEM_ALARM_CALLBACK_OBJECT (0x10) conditional continuous audit ACE, scoped to GUID | §9.3 | Cargo |
| 418 | `alarm_ace_bit25_no_mmap` | Bit 25 in alarm ACE mask (`MAXIMUM_ALLOWED` repurposed as no-mmap flag) causes mmap to be denied on matching handles | §14, §15.3 | Provium |
| 419 | `alarm_ace_intentional_divergence` | Alarm ACEs are intentionally diverged from Windows (which reserves them); SDs from external sources will not contain them | §9.3 | Cargo |

#### Privilege-Use Auditing

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 420 | `privilege_use_audit_fires` | When a privilege is exercised to grant access that the DACL would not have granted, a privilege-use audit event is emitted | §11.10 | Provium |
| 421 | `privilege_use_audit_identifies_privilege` | The audit records "access was granted because [specific privilege] was used" | §11.10 | Provium |
| 422 | `privilege_use_audit_after_pipeline` | Privilege-use auditing fires after the complete evaluation pipeline (integrity, confinement, CAP) | §11.10 | Cargo |
| 423 | `privilege_use_audit_only_when_necessary` | Only fires when the privilege was actually necessary for the final result; if a later stage revoked privilege-granted bits, no audit | §11.10 | Cargo |

#### Mandatory Label ACEs in SACL

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 424 | `mandatory_label_ace_type` | SYSTEM_MANDATORY_LABEL_ACE (0x11) sets the object's integrity level | §9.3 | Cargo |
| 425 | `mandatory_label_ace_at_most_one` | At most one mandatory label ACE per SACL | §9.3 | Cargo |
| 426 | `mandatory_label_ace_sid_encodes_level` | The SID encodes the integrity level (e.g., S-1-16-8192 = Medium, S-1-16-12288 = High) | §9.3 | Cargo |
| 427 | `mandatory_label_ace_mask_encodes_policy` | The access mask encodes MIC policy: which operations are blocked when caller's integrity is below the object's | §9.3 | Cargo |
| 428 | `mandatory_label_readable_with_read_control` | Labels readable via `LABEL_SECURITY_INFORMATION` with only `READ_CONTROL`, not `ACCESS_SYSTEM_SECURITY` | §15.1 | Provium |
| 429 | `mandatory_label_write_requires_write_owner_plus_integrity` | Writing labels via `kacs_set_sd` with `LABEL_SECURITY_INFORMATION` requires `WRITE_OWNER` plus integrity constraints | §15.1 | Provium |

#### Resource Attribute ACEs in SACL

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 430 | `resource_attribute_ace_type` | SYSTEM_RESOURCE_ATTRIBUTE_ACE (0x12) defines a resource attribute on the object | §9.3 | Cargo |
| 431 | `resource_attribute_ace_sid_everyone` | The ACE's SID is always the well-known Everyone SID (S-1-1-0) | §9.3 | Cargo |
| 432 | `resource_attribute_ace_format` | Attribute data follows the `CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1` format from MS-DTYP §2.4.10.1 | §9.3 | Cargo |
| 433 | `resource_attribute_ace_name_value` | Each resource attribute ACE encodes a single named, typed, multi-valued attribute | §11.11 | Cargo |
| 434 | `resource_attribute_ace_value_types` | Values can be integers, strings, booleans, SIDs, or byte arrays | §11.11 | Cargo |
| 435 | `resource_attribute_ace_multiple` | Multiple resource attribute ACEs can appear in the same SACL, each carrying a different attribute | §11.11 | Cargo |
| 436 | `resource_attribute_ace_first_wins` | If two ACEs carry the same attribute name, the first one wins (duplicates silently ignored) | §11.11 | Cargo |
| 437 | `resource_attribute_extracted_before_dacl` | Resource attributes are extracted from the SACL before the DACL walk begins | §11.11 | Cargo |
| 438 | `resource_attribute_available_in_conditional` | Extracted attributes are available for conditional expression evaluation via `@Resource.` prefix | §11.11 | Cargo |

#### Audit Event Contents

| # | Test name | Assertion | Spec ref | Type |
|---|-----------|-----------|----------|------|
| 439 | `audit_event_subject` | Each audit event contains the calling token's identity (user SID, group SIDs, integrity level, PIP identity) | §11.10 | Cargo |
| 440 | `audit_event_object` | Each audit event contains caller-provided context identifying the object | §11.10 | Cargo |
| 441 | `audit_event_access` | Each audit event contains what was requested, what was granted, whether succeeded or failed | §11.10 | Cargo |
| 442 | `audit_event_trigger` | Each audit event contains which audit ACE matched or which privilege was exercised | §11.10 | Cargo |
| 443 | `audit_event_process` | Each audit event contains the calling process's PID, name, and executable path (from kernel task context) | §11.10 | Provium |

---

## Summary

**Total tests extracted: 443**

| Category | Cargo | Provium |
|----------|-------|---------|
| §15.1 Syscalls — Token lifecycle | 7 | 29 |
| §15.1 Syscalls — Impersonation | 0 | 21 |
| §15.1 Syscalls — Session management | 0 | 6 |
| §15.1 Syscalls — File operations (kacs_open) | 0 | 29 |
| §15.1 Syscalls — kacs_get_sd / kacs_set_sd | 3 | 23 |
| §15.1 Syscalls — kacs_access_check | 14 | 5 |
| §15.2 Ioctls | 1 | 69 |
| §15.3 LSM blob layout | 0 | 12 |
| §15.4 Inspection interfaces | 0 | 9 |
| §15.5 Build configuration | 0 | 7 |
| §15.6 Kernel patches | 0 | 5 |
| §15.7 Boot sequence | 0 | 14 |
| §16 Derooting | 0 | 35 |
| §17 Audit pipeline | 5 | 71 |
| §11.10/§9.3 SACL evaluation (cross-ref) | 35 | 15 |
| **Total** | **65** | **378** |

The heavy Provium skew is expected: §15-17 are predominantly about kernel interfaces (syscalls, ioctls, procfs, boot, ring buffers) that cannot be tested without a running KACS kernel. The Cargo tests cluster around format parsing/validation, AccessCheck evaluation logic, ACE type recognition, and audit event structure -- pure data-structure and algorithm tests that the kacs-core crate can exercise in userspace.


---

# Section 18: Testing Strategy

## Exhaustive Test Corpus from KACS §18 "Testing Strategy"

---

### CARGO TESTS (§18.1 — Rust unit tests, `cargo test`)

#### Module: `test_sd_parse`
Spec ref: §18.1, line 12439

| # | Test name | Assertion |
|---|-----------|-----------|
| 1 | `sd_parse_valid_minimal` | A minimal valid binary SD parses successfully with correct owner, group, DACL, SACL fields |
| 2 | `sd_parse_valid_full` | A fully populated SD (owner, group, DACL, SACL all present) parses correctly |
| 3 | `sd_parse_malformed_header` | An SD with invalid revision or control bits returns a parse error |
| 4 | `sd_parse_truncated_mid_header` | An SD truncated within the header region returns a parse error |
| 5 | `sd_parse_truncated_mid_acl` | An SD truncated within an ACL structure returns a parse error |
| 6 | `sd_parse_truncated_mid_ace` | An SD truncated within an ACE structure returns a parse error |
| 7 | `sd_parse_oversized_acl` | An SD with ACL size exceeding MAX_SD_SIZE is rejected |
| 8 | `sd_parse_oversized_sd` | An SD exceeding the maximum permitted total size is rejected |
| 9 | `sd_parse_corrupt_dacl_offset` | An SD with a DACL offset pointing out of bounds returns a parse error |
| 10 | `sd_parse_corrupt_sacl_offset` | An SD with a SACL offset pointing out of bounds returns a parse error |
| 11 | `sd_parse_corrupt_ace_size` | An SD with an ACE whose size field is inconsistent with its type returns a parse error |
| 12 | `sd_parse_corrupt_acl_ace_count` | An SD where the ACL's AceCount disagrees with the actual ACE data returns a parse error |

#### Module: `test_dacl_walk`
Spec ref: §18.1, line 12440

| # | Test name | Assertion |
|---|-----------|-----------|
| 13 | `dacl_walk_deny_before_allow` | A deny ACE matching the caller's SID is evaluated before a subsequent allow ACE for the same SID, resulting in denial |
| 14 | `dacl_walk_allow_after_deny_different_sid` | A deny ACE for SID A does not block an allow ACE for SID B when caller has SID B |
| 15 | `dacl_walk_ace_ordering_canonical` | ACEs in canonical order (explicit deny, explicit allow, inherited deny, inherited allow) are evaluated correctly |
| 16 | `dacl_walk_sid_matching_primary` | An ACE matching the token's user SID grants/denies the specified mask bits |
| 17 | `dacl_walk_sid_matching_group` | An ACE matching one of the token's group SIDs grants/denies the specified mask bits |
| 18 | `dacl_walk_sid_no_match` | An ACE whose SID matches none of the token's SIDs has no effect |
| 19 | `dacl_walk_mask_accumulation` | Multiple allow ACEs accumulate their masks via bitwise OR |
| 20 | `dacl_walk_deny_clears_accumulated` | A deny ACE removes bits from the remaining-desired set, preventing later allows from granting them |
| 21 | `dacl_walk_empty_dacl` | An empty DACL (present but no ACEs) denies all access |
| 22 | `dacl_walk_null_dacl` | A NULL DACL (not present) grants all access |

#### Module: `test_generic_mapping`
Spec ref: §18.1, line 12441

| # | Test name | Assertion |
|---|-----------|-----------|
| 23 | `generic_mapping_file_read` | GENERIC_READ maps to the correct specific bits for file objects |
| 24 | `generic_mapping_file_write` | GENERIC_WRITE maps to the correct specific bits for file objects |
| 25 | `generic_mapping_file_execute` | GENERIC_EXECUTE maps to the correct specific bits for file objects |
| 26 | `generic_mapping_file_all` | GENERIC_ALL maps to the correct specific bits for file objects |
| 27 | `generic_mapping_process` | Generic rights map to the correct specific bits for process objects |
| 28 | `generic_mapping_registry` | Generic rights map to the correct specific bits for registry objects |
| 29 | `generic_mapping_clears_generic_bits` | After mapping, no GENERIC_* bits remain in the output mask |

#### Module: `test_privilege_grants`
Spec ref: §18.1, line 12442

| # | Test name | Assertion |
|---|-----------|-----------|
| 30 | `privilege_backup_grants_read` | SeBackupPrivilege grants read access bypassing DACL |
| 31 | `privilege_restore_grants_write` | SeRestorePrivilege grants write access bypassing DACL |
| 32 | `privilege_security_grants_sacl` | SeSecurityPrivilege grants ACCESS_SYSTEM_SECURITY for SACL access |
| 33 | `privilege_take_ownership_grants_write_owner` | SeTakeOwnershipPrivilege grants WRITE_OWNER |
| 34 | `privilege_not_enabled_no_grant` | A privilege present but not enabled does not grant access |
| 35 | `privilege_not_held_no_grant` | A token lacking a privilege entirely does not get privilege-based grants |

#### Module: `test_owner_rights`
Spec ref: §18.1, line 12443

| # | Test name | Assertion |
|---|-----------|-----------|
| 36 | `owner_implicit_read_control` | The object owner is implicitly granted READ_CONTROL without an explicit ACE |
| 37 | `owner_implicit_write_dac` | The object owner is implicitly granted WRITE_DAC without an explicit ACE |
| 38 | `owner_rights_ace_overrides_implicit` | An OWNER RIGHTS ACE replaces the implicit READ_CONTROL + WRITE_DAC with the mask in the ACE |
| 39 | `owner_rights_ace_deny` | An OWNER RIGHTS deny ACE removes the owner's implicit grants |
| 40 | `owner_rights_ace_restricts_to_subset` | An OWNER RIGHTS allow ACE granting only READ_CONTROL suppresses the implicit WRITE_DAC |

#### Module: `test_mic`
Spec ref: §18.1, line 12444

| # | Test name | Assertion |
|---|-----------|-----------|
| 41 | `mic_no_write_up` | A low-integrity token cannot write to a high-integrity object (no-write-up policy) |
| 42 | `mic_no_read_up` | When no-read-up is set, a low-integrity token cannot read a high-integrity object |
| 43 | `mic_no_execute_up` | When no-execute-up is set, a low-integrity token cannot execute a high-integrity object |
| 44 | `mic_equal_integrity_allowed` | A token with integrity equal to the object's integrity level passes MIC |
| 45 | `mic_higher_integrity_allowed` | A token with integrity higher than the object's passes MIC unconditionally |
| 46 | `mic_new_process_min` | NEW_PROCESS_MIN policy ensures a child process gets at least the object's integrity level |
| 47 | `mic_no_label_defaults` | An object without an explicit integrity label defaults to Medium integrity |

#### Module: `test_conditional_ace`
Spec ref: §18.1, line 12445

| # | Test name | Assertion |
|---|-----------|-----------|
| 48 | `conditional_ace_resource_claim_match` | A conditional ACE referencing @Resource.attr evaluates correctly when the resource claim matches |
| 49 | `conditional_ace_resource_claim_no_match` | A conditional ACE referencing @Resource.attr evaluates to false when the resource claim does not match |
| 50 | `conditional_ace_user_claim_match` | A conditional ACE referencing @User.attr evaluates correctly against user claims on the token |
| 51 | `conditional_ace_device_claim_match` | A conditional ACE referencing @Device.attr evaluates correctly against device claims |
| 52 | `conditional_ace_local_claim_match` | A conditional ACE referencing @Local.attr evaluates correctly against local claims |
| 53 | `conditional_ace_expression_string_equals` | String equality comparisons in conditional expressions evaluate correctly |
| 54 | `conditional_ace_expression_int_comparison` | Integer comparison operators in conditional expressions evaluate correctly |
| 55 | `conditional_ace_expression_contains` | The Contains operator in conditional expressions evaluates correctly |
| 56 | `conditional_ace_expression_any_of` | The Any_of operator in conditional expressions evaluates correctly |
| 57 | `conditional_ace_expression_logical_and_or` | Logical AND/OR combinations in conditional expressions evaluate correctly |
| 58 | `conditional_ace_expression_not` | The NOT operator in conditional expressions evaluates correctly |
| 59 | `conditional_ace_malformed_expression` | A conditional ACE with a malformed expression is skipped (not crash, not grant) |

#### Module: `test_restricted_token`
Spec ref: §18.1, line 12446

| # | Test name | Assertion |
|---|-----------|-----------|
| 60 | `restricted_token_two_pass_both_pass` | Access is granted only when both the normal SID pass and the restricting SID pass succeed |
| 61 | `restricted_token_two_pass_normal_fail` | Access is denied when the normal SID pass fails, even if the restricting SID pass would succeed |
| 62 | `restricted_token_two_pass_restricted_fail` | Access is denied when the restricting SID pass fails, even if the normal SID pass succeeds |
| 63 | `restricted_token_restricting_sids` | Only the restricting SIDs (not normal groups) are used for the second pass |
| 64 | `restricted_token_deny_only_groups` | Groups marked deny-only participate in deny ACE matching but not allow ACE matching |

#### Module: `test_object_ace`
Spec ref: §18.1, line 12447

| # | Test name | Assertion |
|---|-----------|-----------|
| 65 | `object_ace_guid_match` | An object ACE with a matching object type GUID applies its mask |
| 66 | `object_ace_guid_no_match` | An object ACE with a non-matching object type GUID is skipped |
| 67 | `object_ace_inherited_guid_match` | An object ACE with a matching inherited object type GUID applies during inheritance |
| 68 | `object_ace_ds_rights` | Object ACEs correctly gate DS-specific rights (e.g., ADS_RIGHT_DS_READ_PROP) |
| 69 | `object_ace_object_type_tree` | Object type tree traversal correctly determines GUID inheritance |
| 70 | `object_ace_principal_self_substitution` | The PRINCIPAL_SELF SID in an object ACE is substituted with the object's actual principal SID |

#### Module: `test_maximum_allowed`
Spec ref: §18.1, line 12448

| # | Test name | Assertion |
|---|-----------|-----------|
| 71 | `maximum_allowed_full_dacl_walk` | MAXIMUM_ALLOWED triggers a full DACL walk without short-circuiting at first grant |
| 72 | `maximum_allowed_returns_all_granted` | The returned mask contains all rights the DACL would grant |
| 73 | `maximum_allowed_includes_privilege_grants` | Privilege-based grants (backup, restore, etc.) are included in the MAXIMUM_ALLOWED result |
| 74 | `maximum_allowed_includes_owner_implicit` | Owner implicit rights are included in MAXIMUM_ALLOWED |
| 75 | `maximum_allowed_respects_deny` | Deny ACEs reduce the MAXIMUM_ALLOWED result |

#### Module: `test_cap`
Spec ref: §18.1, line 12449

| # | Test name | Assertion |
|---|-----------|-----------|
| 76 | `cap_central_access_policy_grants` | A central access policy rule grants access when the token matches its conditions |
| 77 | `cap_central_access_policy_denies` | A central access policy rule denies access when the token does not match |
| 78 | `cap_recovery_policy_grants` | The recovery policy grants access when the main policy denies it, for admin override scenarios |
| 79 | `cap_recovery_policy_audit` | Access via recovery policy is flagged for audit even when granted |

#### Module: `test_pip`
Spec ref: §18.1, line 12450

| # | Test name | Assertion |
|---|-----------|-----------|
| 80 | `pip_trust_label_match` | A trust label on the object matching the token's trust claim passes PIP |
| 81 | `pip_trust_label_no_match` | A trust label on the object not matching the token's trust claim fails PIP |
| 82 | `pip_tier_comparison_higher` | A higher PIP tier on the token passes against a lower required tier |
| 83 | `pip_tier_comparison_equal` | An equal PIP tier passes |
| 84 | `pip_tier_comparison_lower` | A lower PIP tier on the token fails against a higher required tier |

---

### CARGO TESTS — Windows Cross-Testing Corpus (§18.1, lines 12475–12486)

Each bullet in the spec is a family of cross-test vectors. Every test here is **Cargo** (pure evaluation, comparing against recorded Windows outputs).

| # | Test name | Assertion | Spec ref |
|---|-----------|-----------|----------|
| 85 | `cross_dacl_owner_only` | Owner-only DACL pattern produces same granted mask as Windows AccessCheck | §18.1 line 12476 |
| 86 | `cross_dacl_group_read` | Group-read DACL pattern produces same result as Windows | §18.1 line 12476 |
| 87 | `cross_dacl_everyone_deny` | Everyone-deny DACL pattern produces same result as Windows | §18.1 line 12476 |
| 88 | `cross_ace_interleaved_allow_deny` | Interleaved allow/deny ACE ordering produces same result as Windows | §18.1 line 12477 |
| 89 | `cross_inheritance_ci` | Container inherit (CI) flag produces same inherited ACEs as Windows | §18.1 line 12478 |
| 90 | `cross_inheritance_oi` | Object inherit (OI) flag produces same result as Windows | §18.1 line 12478 |
| 91 | `cross_inheritance_io` | Inherit-only (IO) flag produces same result as Windows | §18.1 line 12478 |
| 92 | `cross_inheritance_np` | No-propagate (NP) flag produces same result as Windows | §18.1 line 12478 |
| 93 | `cross_inheritance_ci_oi_combined` | CI+OI combined flags produce same result as Windows | §18.1 line 12478 |
| 94 | `cross_inheritance_ci_oi_np` | CI+OI+NP combined flags produce same result as Windows | §18.1 line 12478 |
| 95 | `cross_inheritance_ci_oi_io` | CI+OI+IO combined flags produce same result as Windows | §18.1 line 12478 |
| 96 | `cross_conditional_ace_string` | Conditional ACE with string expression produces same result as Windows | §18.1 line 12479 |
| 97 | `cross_conditional_ace_int` | Conditional ACE with integer expression produces same result as Windows | §18.1 line 12479 |
| 98 | `cross_conditional_ace_sid` | Conditional ACE with SID member-of expression produces same result as Windows | §18.1 line 12479 |
| 99 | `cross_restricted_token` | Restricted token two-pass evaluation produces same result as Windows | §18.1 line 12480 |
| 100 | `cross_object_ace_guid` | Object ACE with GUID matching produces same result as Windows | §18.1 line 12481 |
| 101 | `cross_privilege_backup` | SeBackupPrivilege-granted access produces same result as Windows | §18.1 line 12482 |
| 102 | `cross_privilege_restore` | SeRestorePrivilege-granted access produces same result as Windows | §18.1 line 12482 |
| 103 | `cross_privilege_security` | SeSecurityPrivilege-granted access produces same result as Windows | §18.1 line 12482 |
| 104 | `cross_maximum_allowed` | MAXIMUM_ALLOWED evaluation produces same mask as Windows | §18.1 line 12483 |
| 105 | `cross_null_dacl` | NULL DACL grants all access, same as Windows | §18.1 line 12484 |
| 106 | `cross_empty_dacl` | Empty DACL denies all access, same as Windows | §18.1 line 12484 |
| 107 | `cross_owner_implicit_no_override` | Owner implicit grants without OWNER RIGHTS ACE match Windows | §18.1 line 12485 |
| 108 | `cross_owner_rights_ace_override` | OWNER RIGHTS ACE override behavior matches Windows | §18.1 line 12485 |

---

### PROVIUM TESTS — VM Integration Tests (§18.1, lines 12495–12509)

All tests below are **Provium** (require booted KACS kernel).

#### Token lifecycle (line 12497: "create -> install -> query -> adjust -> restrict -> impersonate -> revert")

| # | Test name | Assertion | Spec ref |
|---|-----------|-----------|----------|
| 109 | `token_lifecycle_create` | kacs_create_token syscall succeeds with valid parameters, returning a token handle | §18.1 line 12497 |
| 110 | `token_lifecycle_install` | KACS_IOC_INSTALL ioctl installs a created token as the process's primary token | §18.1 line 12497 |
| 111 | `token_lifecycle_query` | kacs_query_token syscall returns correct token attributes (user SID, groups, privileges, integrity) | §18.1 line 12497 |
| 112 | `token_lifecycle_adjust` | kacs_adjust_token syscall can enable/disable privileges on a token | §18.1 line 12497 |
| 113 | `token_lifecycle_restrict` | kacs_restrict_token syscall creates a restricted token with restricting SIDs and deny-only groups | §18.1 line 12497 |
| 114 | `token_lifecycle_impersonate` | kacs_impersonate syscall sets the thread's effective token to the impersonation token | §18.1 line 12497 |
| 115 | `token_lifecycle_revert` | kacs_revert_to_self syscall restores the thread's effective token to the process primary token | §18.1 line 12497 |

#### FACS open (line 12498)

| # | Test name | Assertion | Spec ref |
|---|-----------|-----------|----------|
| 116 | `facs_open_read_only` | kacs_open with FILE_READ_DATA desired_access succeeds on a file whose SD allows it | §18.1 line 12498 |
| 117 | `facs_open_write_data` | kacs_open with FILE_WRITE_DATA desired_access succeeds when SD allows write | §18.1 line 12498 |
| 118 | `facs_open_denied` | kacs_open with a desired_access not granted by the SD fails with EACCES | §18.1 line 12498 |
| 119 | `facs_open_multiple_rights` | kacs_open requesting multiple rights succeeds only if all are granted by SD | §18.1 line 12498 |
| 120 | `facs_open_sd_inheritance_new_file` | A newly created file inherits SD from parent directory per §9.5 | §18.1 line 12498 |
| 121 | `facs_open_disposition_create_new` | kacs_open with create-new disposition creates a file and stamps inherited SD | §18.1 line 12498 |
| 122 | `facs_open_disposition_open_existing` | kacs_open with open-existing disposition opens an existing file | §18.1 line 12498 |

#### Legacy open compat (line 12499)

| # | Test name | Assertion | Spec ref |
|---|-----------|-----------|----------|
| 123 | `legacy_open_rdonly_compat_set` | open(O_RDONLY) maps to core rights (FILE_READ_DATA, FILE_READ_ATTRIBUTES) + compat set | §18.1 line 12499 |
| 124 | `legacy_open_wronly_compat_set` | open(O_WRONLY) maps to correct core + compat rights | §18.1 line 12499 |
| 125 | `legacy_open_rdwr_compat_set` | open(O_RDWR) maps to correct core + compat rights | §18.1 line 12499 |
| 126 | `legacy_open_core_compat_split` | Core rights must be fully granted; compat rights are best-effort | §18.1 line 12499 |
| 127 | `legacy_open_fstat_on_result` | fstat on an fd from legacy open() succeeds (FILE_READ_ATTRIBUTES is a core right) | §18.1 line 12499 |
| 128 | `legacy_open_fchmod_on_result` | fchmod on an fd from legacy open() succeeds only if WRITE_DAC was granted | §18.1 line 12499 |

#### Handle model (line 12500)

| # | Test name | Assertion | Spec ref |
|---|-----------|-----------|----------|
| 129 | `handle_open_with_rights` | Opening a file with specific rights stamps those rights as the fd's granted mask | §18.1 line 12500 |
| 130 | `handle_use_time_check` | A use-time operation (read/write) checks the fd's granted mask, not the current SD | §18.1 line 12500 |
| 131 | `handle_sd_change_no_affect_open` | Changing the file's SD after open does not affect operations on the already-opened fd | §18.1 line 12500 |
| 132 | `handle_sd_change_affects_new_open` | A new open after SD change is evaluated against the new SD | §18.1 line 12500 |

#### Process SDs (line 12501)

| # | Test name | Assertion | Spec ref |
|---|-----------|-----------|----------|
| 133 | `process_sd_default_on_fork` | A forked process has a default SD with the creator as owner | §18.1 line 12501 |
| 134 | `process_query_information_gated` | Querying process information is gated behind PROCESS_QUERY_INFORMATION in the process SD | §18.1 line 12501 |
| 135 | `process_dup_handle_via_pidfd_getfd` | pidfd_getfd requires PROCESS_DUP_HANDLE in the target process's SD | §18.1 line 12501 |
| 136 | `process_dup_handle_denied` | pidfd_getfd without PROCESS_DUP_HANDLE returns EACCES | §18.1 line 12501 |

#### Impersonation (line 12502)

| # | Test name | Assertion | Spec ref |
|---|-----------|-----------|----------|
| 137 | `impersonation_socket_identity_capture` | A process connecting over a Unix socket captures the server's identity for impersonation | §18.1 line 12502 |
| 138 | `impersonation_level_anonymous` | Impersonation at Anonymous level prevents SID queries | §18.1 line 12502 |
| 139 | `impersonation_level_identification` | Impersonation at Identification level allows SID queries but not access checks | §18.1 line 12502 |
| 140 | `impersonation_level_impersonation` | Impersonation at Impersonation level allows full access checks on behalf of the client | §18.1 line 12502 |
| 141 | `impersonation_level_delegation` | Impersonation at Delegation level allows the server to use the client identity across machines | §18.1 line 12502 |
| 142 | `impersonation_two_gate_model` | Two-gate impersonation: both client consent and server privilege are required | §18.1 line 12502 |
| 143 | `impersonation_cap_to_identification` | A CAP_-bearing process lacking SeImpersonatePrivilege is capped at Identification level | §18.1 line 12502 |

#### Privilege gating (line 12503)

| # | Test name | Assertion | Spec ref |
|---|-----------|-----------|----------|
| 144 | `privilege_gate_create_token` | kacs_create_token requires SeCreateTokenPrivilege on the caller's token | §18.1 line 12503 |
| 145 | `privilege_gate_create_token_denied` | kacs_create_token without SeCreateTokenPrivilege fails | §18.1 line 12503 |
| 146 | `privilege_gate_assign_primary` | Installing a primary token on another process requires SeAssignPrimaryTokenPrivilege | §18.1 line 12503 |
| 147 | `privilege_gate_assign_primary_denied` | Token install without SeAssignPrimaryTokenPrivilege fails | §18.1 line 12503 |
| 148 | `privilege_gate_restore` | SeRestorePrivilege grants write access bypassing DACL in the kernel path | §18.1 line 12503 |
| 149 | `privilege_gate_restore_denied` | Write without SeRestorePrivilege on a deny-all SD fails | §18.1 line 12503 |

#### Logon sessions (line 12504)

| # | Test name | Assertion | Spec ref |
|---|-----------|-----------|----------|
| 150 | `logon_session_create` | kacs_create_session creates a new logon session with a unique logon SID | §18.1 line 12504 |
| 151 | `logon_session_logon_sid_injection` | The logon SID is injected into tokens created within the session | §18.1 line 12504 |
| 152 | `logon_session_linked_token` | A logon session with UAC-like split tokens can retrieve the linked (elevated) token | §18.1 line 12504 |

#### SysV IPC SDs (line 12505)

| # | Test name | Assertion | Spec ref |
|---|-----------|-----------|----------|
| 153 | `sysv_ipc_default_sd_shmget` | shmget creates a shared memory segment with a default SD (creator as owner) | §18.1 line 12505 |
| 154 | `sysv_ipc_accesscheck_shmat` | shmat runs AccessCheck against the segment's SD before attaching | §18.1 line 12505 |
| 155 | `sysv_ipc_shmat_denied` | shmat to a segment whose SD denies access to the caller returns EACCES | §18.1 line 12505 |

#### Event pipeline (line 12506)

| # | Test name | Assertion | Spec ref |
|---|-----------|-----------|----------|
| 156 | `event_emit_success` | event_emit syscall writes an event to the ring buffer | §18.1 line 12506 |
| 157 | `event_ring_buffer_drain` | Events written to the ring buffer can be drained by an eventd consumer | §18.1 line 12506 |
| 158 | `event_crash_recovery` | After a simulated crash, events in the ring buffer are recoverable | §18.1 line 12506 |
| 159 | `event_overflow_policy` | When the ring buffer is full, the overflow policy (drop oldest or fail new) is enforced | §18.1 line 12506 |

---

### PROVIUM TESTS — Kernel Patch Regression Tests (§18.1, lines 12523–12531, plus §14.3 lines 9951–9963)

All tests below are **Provium**. The spec explicitly names 6 examples in §18.1 and defines CI tests for all 16 patches in §14.3.

| # | Test name | Assertion | Spec ref |
|---|-----------|-----------|----------|
| 160 | `patch01_pwrite_append_only_eperm` | pwrite on an append-only fd returns EPERM | §18.1 line 12526, §14.3 patch 1 |
| 161 | `patch02_pwritev2_noappend_eperm` | pwritev2 with RWF_NOAPPEND on an append-only fd returns EPERM | §14.3 patch 2 |
| 162 | `patch02_pwritev_append_only_eperm` | pwritev on an append-only fd returns EPERM | §14.3 patch 2 |
| 163 | `patch03_io_uring_positioned_write_fail` | io_uring SQE write with explicit offset on an append-only fd fails | §14.3 patch 3 |
| 164 | `patch04_aio_write_offset_eperm` | AIO write with offset on an append-only fd returns EPERM | §14.3 patch 4 |
| 165 | `patch05_faccessat_effective_token` | access()/faccessat() during impersonation evaluates the effective (impersonation) token, not real_cred | §14.3 patch 5 |
| 166 | `patch06_open_by_handle_no_privilege` | open_by_handle_at without SeChangeNotifyPrivilege fails | §14.3 patch 6 |
| 167 | `patch07_fchmod_no_write_dac_eacces` | fchmod on an fd without WRITE_DAC in granted mask returns EACCES | §18.1 line 12527, §14.3 patch 7 |
| 168 | `patch07_fchown_no_write_dac_eacces` | fchown on an fd without WRITE_DAC (or WRITE_OWNER) returns EACCES | §14.3 patch 7 |
| 169 | `patch07_futimens_no_write_dac_eacces` | futimens on an fd without WRITE_DAC returns EACCES | §14.3 patch 7 |
| 170 | `patch08_fallocate_punch_hole_append_only_eperm` | fallocate with PUNCH_HOLE on an append-only fd returns EPERM | §14.3 patch 8 |
| 171 | `patch08_fallocate_zero_range_append_only_eperm` | fallocate with ZERO_RANGE on an append-only fd returns EPERM | §14.3 patch 8 |
| 172 | `patch08_fallocate_collapse_range_append_only_eperm` | fallocate with COLLAPSE_RANGE on an append-only fd returns EPERM | §14.3 patch 8 |
| 173 | `patch08_fallocate_insert_range_append_only_eperm` | fallocate with INSERT_RANGE on an append-only fd returns EPERM | §14.3 patch 8 |
| 174 | `patch09_fstat_no_read_attributes_eacces` | fstat on an fd without FILE_READ_ATTRIBUTES in granted mask returns EACCES | §14.3 patch 9 |
| 175 | `patch09_statx_empty_path_no_read_attributes_eacces` | statx(AT_EMPTY_PATH) on an fd without FILE_READ_ATTRIBUTES returns EACCES | §14.3 patch 9 |
| 176 | `patch10_fgetxattr_no_read_ea_eacces` | fgetxattr on an fd without FILE_READ_EA in granted mask returns EACCES | §14.3 patch 10 |
| 177 | `patch11_fsetxattr_no_write_ea_eacces` | fsetxattr on an fd without FILE_WRITE_EA in granted mask returns EACCES | §14.3 patch 11 |
| 178 | `patch11_fremovexattr_no_write_ea_eacces` | fremovexattr on an fd without FILE_WRITE_EA in granted mask returns EACCES | §14.3 patch 11 |
| 179 | `patch12_do_dentry_open_kacs_desired_access` | do_dentry_open accepts KACS desired_access and sets f_mode from granted mask | §15.6 patch 12 |
| 180 | `patch13_pidfd_getfd_no_dup_handle_eacces` | pidfd_getfd without PROCESS_DUP_HANDLE returns EACCES | §18.1 line 12528, §14.3/§15.6 patch 13 |
| 181 | `patch14_current_fsuid_projected_uid` | File created by a uid0 process is owned by the token's projected UID, not 0 | §18.1 line 12529, §15.6 patch 14 |
| 182 | `patch15_execveat_no_file_execute_eacces` | execveat on an fd without FILE_EXECUTE in granted mask returns EACCES | §18.1 line 12530, §15.6 patch 15 |
| 183 | `patch16_fchdir_no_file_traverse_eacces` | fchdir on an fd without FILE_TRAVERSE in granted mask returns EACCES | §18.1 line 12531, §15.6 patch 16 |

---

## Summary counts

| Category | Count |
|----------|-------|
| Cargo: SD parse tests | 12 |
| Cargo: DACL walk tests | 10 |
| Cargo: Generic mapping tests | 7 |
| Cargo: Privilege grant tests | 6 |
| Cargo: Owner rights tests | 5 |
| Cargo: MIC tests | 7 |
| Cargo: Conditional ACE tests | 12 |
| Cargo: Restricted token tests | 5 |
| Cargo: Object ACE tests | 6 |
| Cargo: MAXIMUM_ALLOWED tests | 5 |
| Cargo: CAP tests | 4 |
| Cargo: PIP tests | 5 |
| Cargo: Windows cross-tests | 24 |
| **Cargo subtotal** | **108** |
| Provium: Token lifecycle | 7 |
| Provium: FACS open | 7 |
| Provium: Legacy open compat | 6 |
| Provium: Handle model | 4 |
| Provium: Process SDs | 4 |
| Provium: Impersonation | 7 |
| Provium: Privilege gating | 6 |
| Provium: Logon sessions | 3 |
| Provium: SysV IPC SDs | 3 |
| Provium: Event pipeline | 4 |
| Provium: Kernel patch regressions (16 patches, expanded) | 24 |
| **Provium subtotal** | **75** |
| **Total** | **183** |

Source file: `/home/jack/projects/peios/z_proposals/KACS.md`, lines 12413-12564 (primary), with patch details from lines 9919-9963 (§14.3) and 11653-11668 (§15.6).


---

# Appendix A: Audit-Finding Gap Tests

Tests proposed to cover the specific bugs found during the KACS implementation audit.
**None of the 24 P0-P2 audit findings had existing tests that would catch them.**

| Finding | Existing Test Coverage | Gap? | Proposed Test |
|---|---|---|---|
| **P0-1: Code tree desync** (kernel copy behind canonical crate) | No test in the corpus checks whether the kernel build copy and the canonical crate are in sync. The corpus is entirely behavioral. | **YES** | `kernel_copy_matches_canonical_crate` (Cargo/CI): Run a checksum or diff between `pkm/crates/kacs-core/src/` and `pkm/kacs/kacs_core/`. Assert they are identical (or that a single-source mechanism exists). Type: CI build step, not a cargo test. |
| **P0-2: CI\|IO inheritance bug** (ACEs never apply to child containers) | Test #110 `ci_oi_io_inherits_contents_only` covers CI\|OI\|IO ("inherits to everything but does not apply to the object itself") and test #95 `cross_inheritance_ci_oi_io` cross-checks with Windows. However, these tests describe the *expected behavior* at a high level. Neither test specifically verifies that the IO flag is **cleared** on the inherited copy for child containers. The audit notes "No CI\|IO test" -- importantly, CI\|IO *without* OI is the untested combination. The existing tests describe intent but would not catch the one-line code bug where `} else if !io` should be `} else`. | **YES** | `inherit_ci_io_clears_io_on_child_container` (Cargo): Parent ACE with CI\|IO (no OI). Inherit to child container. Assert the child's inherited ACE does NOT have INHERIT_ONLY_ACE set. Also: `inherit_ci_oi_io_clears_io_on_child_container`: same for CI\|OI\|IO combination. Both assert the inherited ACE applies to the child container (is not perpetually inherit-only). |
| **P0-3: SE_GROUP_LOGON_ID wrong value** (0x40 vs 0xC0000000) | No test asserts the numeric value of SE_GROUP_LOGON_ID. Tests reference logon SIDs (`adjust_groups_logon_sid_cannot_disable`, `create_session_auto_logon_sid`, etc.) but none check the constant's bit pattern. The `is_logon_id()` function is also untested per the audit. | **YES** | `se_group_logon_id_value_is_0xC0000000` (Cargo): Assert `SE_GROUP_LOGON_ID == 0xC000_0000`. Also: `se_group_integrity_value_is_0x20` and `se_group_integrity_enabled_value_is_0x40` to assert the missing constants. |
| **P0-4: SE_RELABEL/SE_UNDOCK bit positions swapped** | Tests #194-196 test SeRelabelPrivilege behavior (MIC bypass for WRITE_OWNER), and #255 confirms SeUndockPrivilege is reserved. However, no test asserts the actual LUID/bit position of these privileges. The behavioral tests pass because they use the constant by name, not by numeric bit. | **YES** | `se_relabel_privilege_bit_is_32` (Cargo): Assert the bit index for SeRelabelPrivilege equals 32 (LUID 33, index 32). `se_undock_privilege_bit_is_25` (Cargo): Assert the bit index for SeUndockPrivilege equals 25. Also: `privilege_bit_positions_match_windows_luids` (Cargo): Exhaustive assertion of all 36 privilege bit assignments against MS-DTYP LUID values. |
| **P0-5: Object tree not handled in restricted/confinement passes** | Tests #17 `restricted_tree_fresh_copy`, #18 `restricted_tree_normal_intersection`, #37 `confinement_tree_deep_copy`, #38 `confinement_tree_intersection` all exist and *describe the required behavior* (deep copy + per-node intersection). However, the audit says the implementation passes `None` for the tree. If these tests are corpus entries (spec requirements) not yet implemented as running tests, they would not catch the bug. If they ARE implemented, they should catch it -- the question is whether the existing 389 passing tests include these. The audit explicitly says "restricted token pass passes None for the object tree" is undetected, meaning these test corpus entries are not yet in the running test suite. | **YES** | `restricted_pass_with_object_tree_evaluates_per_node` (Cargo): Build an SD with object ACEs targeting specific GUIDs, create a restricted token, provide an object_tree. Assert restricted pass evaluates tree nodes with restricted SIDs (not None). `confinement_pass_with_object_tree_evaluates_per_node` (Cargo): Same pattern for confinement. Both must verify that individual tree nodes reflect the restricted/confinement SID evaluation, not just the scalar result. |
| **P0-6: Missing virtual group support in kernel build** | Tests #42 `sd_owner_rights_ace_overrides_implicit`, #129 `ownership_owner_rights_suppress_implicit`, #136 `principal_self_matches_caller_who_is_object_principal`, and many others test OWNER_RIGHTS and PRINCIPAL_SELF behavior. These pass against the canonical crate which has EnrichedToken. The kernel copy lacks EnrichedToken entirely. No test runs against the kernel copy. This is a direct consequence of P0-1. | **YES** | Same fix as P0-1 (sync code trees). Additionally: `kernel_build_owner_rights_ace_matches` (Provium): Create an SD with S-1-3-4 ACE, run AccessCheck in the actual kernel. Assert owner rights override works. `kernel_build_principal_self_matches` (Provium): Same for S-1-5-10. |
| **P1-1: Audit SID matching uses bare token** (OWNER_RIGHTS/PRINCIPAL_SELF audit ACEs never fire) | Test #153 `audit_sid_matches_with_deny_polarity` and #393 `audit_sid_uses_deny_polarity` verify audit SID matching uses deny polarity. Test #183 `sacl_same_sid_matching_as_dacl` says audit uses same SID matching as DACL. However, no test specifically creates an audit ACE targeting S-1-3-4 or S-1-5-10 and verifies it fires. The audit report confirms this gap. | **YES** | `audit_ace_owner_rights_sid_fires` (Cargo): SACL audit ACE targeting S-1-3-4, SD owner matches token user. Assert audit event is generated. `audit_ace_principal_self_fires` (Cargo): SACL audit ACE targeting S-1-5-10 with self_sid matching token. Assert audit event fires. Both require EnrichedToken in audit evaluation. |
| **P1-2: Token identity immutability not enforced** (all fields pub) | Test #22 `token_identity_immutable` exists and asserts "Token identity (SIDs, type, level) is immutable after creation." Tests `token_user_sid_immutable`, `token_type_immutable`, `integrity_level_immutable`, etc., exist in the corpus. However, these are behavioral/spec assertions. If the fields are all `pub`, nothing prevents `token.user_sid = other_sid` in Rust code. No test attempts mutation and asserts compile failure or runtime rejection. | **YES** | `token_user_sid_mutation_rejected` (Cargo): Attempt to assign `token.user_sid` directly after creation. Assert this either doesn't compile (if fields are made private) or panics/errors at runtime. Same for `integrity_level`, `token_type`, `impersonation_level`. This is fundamentally a type-system enforcement, best done via private fields + getters rather than runtime tests. |
| **P1-3: &mut aliasing UB in token adjust functions** | No test for concurrent adjust operations. Tests #23 `token_privileges_atomically_adjustable` and `adjustments_mutate_in_place_atomic` describe the expected atomicity. No test exercises two threads calling adjust concurrently on the same token. The audit explicitly notes "No concurrent access tests for Privileges." | **YES** | `concurrent_token_adjust_privileges_no_ub` (Provium): Two threads hold fds to the same token. Both call KACS_IOC_ADJUST_PRIVS concurrently in a tight loop. Assert no data corruption (modified_id is consistent, privilege state is valid). Run under Miri for UB detection in the Cargo version if possible. |
| **P1-4: inode_init_security RCU use-after-free** | Tests `inheritance_init_security_fires_on_create` and `sd_cache_rcu_no_lock_contention` exist but they test correctness, not the race window. No test creates a file while concurrently replacing the parent's SD to trigger the RCU use-after-free. | **YES** | `inode_init_security_concurrent_sd_replace` (Provium): Thread A continuously replaces the parent directory's SD. Thread B continuously creates files in that directory. Run under KASAN. Assert no use-after-free. This is a kernel stress test, not a Cargo test. |
| **P1-5: Session table refcount underflow** | Tests `last_token_freed_destroys_session` and `logon_session_cleanup_on_last_ref_drop` verify normal refcount behavior. No test calls release() on an already-released session. The audit notes "No release underflow" in session coverage. | **YES** | `session_release_at_zero_refcount_does_not_underflow` (Cargo): Create a session, drop all references, call release() again. Assert the refcount does not wrap to u32::MAX (either panics, errors, or is a no-op). |
| **P1-6: Deadlock hazard (lock ordering inversion)** | No test for lock ordering. No concurrent token link/release tests exist. The audit notes "No concurrent access tests." | **YES** | `concurrent_session_link_and_release_no_deadlock` (Provium): Thread A calls kacs_session_link_tokens. Thread B concurrently releases a session. Run in a tight loop with timeout detection. Assert no deadlock within timeout. Also a code review item: document and enforce canonical lock order. |
| **P2-1: SE_DACL_PROTECTED not carried to output SD** | Test #128 `dacl_protected_blocks_parent_inheritance` verifies that SE_DACL_PROTECTED blocks inheritance at creation time. Test #225 `break_inheritance_preserves_existing_aces_as_explicit` covers the break-inheritance behavior. However, no test checks that the **output SD's control word** retains the SE_DACL_PROTECTED flag after creation. The tests verify inheritance blocking behavior, not flag propagation to the output. | **YES** | `inherit_dacl_protected_carried_to_output_sd` (Cargo): Creator SD has SE_DACL_PROTECTED set. Create inherited SD. Assert the output SD's control word includes SE_DACL_PROTECTED. |
| **P2-2: Missing SE_SELF_RELATIVE validation on SD parsing** | Test #4 `sd_self_relative_format_only` says "KACS only produces/accepts self-relative format" and #40 `sd_only_self_relative_format` confirms this. Test #151 `control_flag_sr_bit_15` checks the bit value. But no test creates an SD buffer *without* SE_SELF_RELATIVE set and verifies the parser rejects it. | **YES** | `sd_parse_rejects_absolute_format` (Cargo): Create an SD binary buffer with SE_SELF_RELATIVE clear in control word. Pass to `SecurityDescriptor::from_bytes()`. Assert parse error (not silent acceptance with garbage offsets). |
| **P2-3: CAP recovery policy more permissive than spec** | Tests #320-322 and #57-61 explicitly test recovery policy: `cap_recovery_grants_owner_admin_system` asserts it grants GENERIC_ALL to owner/admin/SYSTEM. `cap_recovery_no_worse_than_no_cap` asserts the intersection is no worse. These tests describe the spec-correct behavior (synthetic SD for owner/admin/SYSTEM). If the implementation uses `continue` instead, these tests *should catch it* because the `continue` behavior would grant broader access than the recovery SD. However, the tests may be corpus entries not yet implemented. | **PARTIAL** | `cap_unknown_policy_does_not_grant_arbitrary_access` (Cargo): Scoped policy ACE with unknown SID. Non-admin, non-owner, non-SYSTEM token. Assert access is DENIED (recovery policy restricts to owner/admin/SYSTEM). The `continue` bug would grant access to this non-privileged token. |
| **P2-4: Object type list validation missing** | Tests #46 `duplicate_guids_in_tree_rejected`, #47 `level_gap_in_tree_rejected`, #142-147 `tree_empty_rejected` through `tree_duplicate_guids_rejected`, and #421-426 all specify validation behavior. These tests specify the correct behavior but if the implementation is missing validation, they would catch it if they are in the running test suite. The audit says `parent_idx.unwrap()` could panic, suggesting these validation tests may not actually be implemented. | **PARTIAL** | `object_tree_duplicate_guid_panics_or_errors` (Cargo): Construct a tree with duplicate GUIDs. Pass to AccessCheck. Assert ERROR_INVALID_PARAMETER (not a panic). `object_tree_level_gap_returns_error` (Cargo): Construct tree with level 0 then level 2. Assert error. `object_tree_root_not_level_zero_returns_error` (Cargo): Root node at level 1. Assert error. |
| **P2-5: Integer truncation in ACE/ACL serialization** | No test in the corpus covers serialization overflow or u16 truncation. The closest are tests about SD max size (64KB) which is an architectural maximum. No test constructs a very large ACE or ACL near u16::MAX boundary. | **YES** | `ace_serialization_rejects_body_exceeding_u16` (Cargo): Construct an ACE with body > 65531 bytes. Assert serialization returns an error (not silently truncated). `acl_serialization_rejects_size_exceeding_u16` (Cargo): Construct an ACL that would exceed u16::MAX total size. Assert error. |
| **P2-6: Missing FilterToken/DuplicateToken/AdjustGroups** | Tests for FilterToken (#1216-1232), DuplicateToken (#1197-1211), and AdjustGroups (#1261-1277) are extensively specified in the corpus. Behavioral tests for their invariants exist. However, the audit says these operations are "not implemented" in kacs-core. The corpus entries are spec requirements, not passing tests. The existing 389 tests likely do not include these since the functions don't exist. | **YES** | Implementation required first. Once implemented: `filter_token_cannot_unrestrict` (Cargo): FilterToken result has restricted_sids. Attempt to create new unrestricted token from it. Assert failure. `duplicate_token_cannot_escalate_impersonation` (Cargo): Duplicate an Identification-level token. Request Impersonation level. Assert capped to Identification. `adjust_groups_cannot_disable_mandatory` (Cargo): Attempt to disable SE_GROUP_MANDATORY group. Assert failure. |
| **P2-7: Conditional ACE resolve_claim hardcodes Origin::UserAttr** | Tests #99-102 (`cond_local_attr_reference`, `cond_user_attr_reference`, `cond_resource_attr_reference`, `cond_device_attr_reference`) verify correct origin for each namespace. Tests #219-229 cover resolve_claim in detail including #229 `resolve_claim_flags_carried`. However, no test checks the origin of *inner Composite elements*. The tests check the outer Value's origin, not elements within a multi-valued claim. | **YES** | `resolve_claim_composite_elements_retain_correct_origin` (Cargo): Create a @Device. claim with multiple values. Resolve it. Assert each element in the COMPOSITE Value has Origin::DeviceAttr (not Origin::UserAttr). Same for @Local. and @Resource. namespaces. |
| **P2-8: Object-scoped audit/alarm ACE types silently ignored** | Tests #405 `sacl_audit_ace_object_type` and #407 `sacl_audit_ace_conditional_object_type` exist for SYSTEM_AUDIT_OBJECT (0x07) and SYSTEM_AUDIT_CALLBACK_OBJECT (0x0F). Tests #398 `audit_object_type_per_node` and #406 `continuous_audit_object_per_node` specify per-property audit behavior. These describe the expected behavior but if the implementation silently skips these ACE types, the tests would catch it IF they're in the running suite. The audit says they're "silently ignored," meaning these tests are likely not yet implemented. | **YES** | `audit_object_ace_0x07_not_silently_skipped` (Cargo): SACL with SYSTEM_AUDIT_OBJECT_ACE (0x07) targeting a GUID. Matching tree node with access. Assert audit event is generated for that node. `audit_callback_object_ace_0x0f_fires` (Cargo): Same for type 0x0F with a conditional expression. |
| **P2-9: Missing SE_GROUP_INTEGRITY flags** | No test asserts the existence or values of SE_GROUP_INTEGRITY (0x20) or SE_GROUP_INTEGRITY_ENABLED (0x40). The integrity level tests use integrity SIDs, not group flags. | **YES** | `se_group_integrity_value_is_0x20` (Cargo): Assert the constant exists and equals 0x20. `se_group_integrity_enabled_value_is_0x40` (Cargo): Assert equals 0x40. `integrity_sid_group_entry_has_integrity_flags` (Cargo): Create a token with an integrity level SID in groups. Assert the group entry has SE_GROUP_INTEGRITY \| SE_GROUP_INTEGRITY_ENABLED set. |
| **P2-10: No constructor for initially-disabled privileges** | Test #180 `privilege_most_start_disabled` and #147 `privileges_start_disabled` describe the expected behavior. No test verifies a constructor exists for creating a privilege set with specific privileges disabled from birth. | **YES** | `privilege_set_backup_starts_disabled` (Cargo): Create a privilege set containing SeBackupPrivilege. Assert it is present but NOT enabled by default. `privilege_set_restore_starts_disabled` (Cargo): Same for SeRestorePrivilege. `new_with_disabled` constructor test: Create privilege set via a constructor that takes (present, enabled) separately. Assert present contains backup/restore, enabled does not. |
| **P2-11: SpinLock protects sleeping paths** | No test in the corpus. This is a kernel-level correctness issue that would manifest as "scheduling while atomic" BUG under kernel debug options. | **YES** | `session_table_lock_does_not_schedule_while_atomic` (Provium): Enable `CONFIG_DEBUG_ATOMIC_SLEEP`. Perform session operations that trigger token drop under lock. Assert no "BUG: scheduling while atomic" in dmesg. |
| **P2-12: Session remove() corrupts data on OOM** | No test. The audit notes "No OOM corruption" test for sessions. | **YES** | `session_remove_under_oom_does_not_corrupt_sids` (Cargo): Create a session with multiple user SIDs. Simulate allocation failure during remove(). Assert no SID is replaced with a null-authority SID (S-0-0). If fallible allocation is used, assert the error is propagated rather than silently corrupting. |

---

**Summary of coverage:**

- **0 of 24 findings** have existing tests that would definitively catch the specific bug.
- **2 findings** (P2-3 CAP recovery, P2-4 object type validation) have partial coverage -- the test corpus specifies the correct behavior, but either the tests are not yet in the running suite or test the behavior at a level that might not catch the specific implementation shortcut.
- **22 findings** have clear test gaps. No existing test would catch the bug.
- The most impactful missing test categories: inheritance flag combination tests (would have prevented P0-2), constant value assertion tests (would have prevented P0-3 and P0-4), code tree sync checks (would have prevented P0-1 and P0-6), and concurrent access/stress tests (would have caught P1-3 through P1-6).

Key files referenced:
- `/home/jack/projects/peios/kacs-audit-report.md` (audit findings)
- `/home/jack/projects/peios/kacs-test-corpus.md` (test corpus, ~3,127 specified tests)


---

# Appendix B: Compound Interaction Tests

Cross-subsystem tests that exercise multiple KACS features simultaneously.
These scenarios test the composition of MIC, PIP, restricted tokens, confinement,
CAP, privileges, impersonation, and inheritance in adversarial combinations.

### Category 1: MIC + PIP Combined

**Test 1**
- **Name:** `mic_and_pip_both_present_dominant_on_both`
- **Assertion:** When the caller dominates both the MIC label and the PIP trust label, neither mechanism restricts access; the DACL alone determines the result.
- **Subsystems:** MIC (11.13), PIP (11.15), DACL walk (11.3)
- **Target:** Cargo
- **Spec refs:** 11.13 (dominant callers bypass MIC), 11.15 (dominant callers bypass PIP), 11.17 steps 4-5

**Test 2**
- **Name:** `mic_blocks_write_pip_allows_all_nondominated`
- **Assertion:** Object has Medium MIC label (NO_WRITE_UP) and a PIP trust label with mask allowing all rights. A Low-integrity caller who dominates PIP but not MIC is blocked from GENERIC_WRITE by MIC, even though PIP imposes no restriction.
- **Subsystems:** MIC (11.13), PIP (11.15)
- **Target:** Cargo
- **Spec refs:** 11.13 (no-write-up), 11.15 (allowed mask), 11.17 PreSACLWalk ordering

**Test 3**
- **Name:** `pip_revokes_bits_mic_would_allow`
- **Assertion:** Object has Low MIC label and a PIP trust label with mask 0 (total lockout). A Medium-integrity caller dominates MIC (no restriction) but does not dominate PIP. PIP denies everything. Result: zero granted.
- **Subsystems:** MIC (11.13), PIP (11.15)
- **Target:** Cargo
- **Spec refs:** 11.15 (mask of 0 = total lockout), 11.17 EnforcePIP

**Test 4**
- **Name:** `mic_and_pip_both_restrict_intersection`
- **Assertion:** Object has High MIC label (NO_WRITE_UP + NO_READ_UP) and a PIP trust label with mask allowing only READ_CONTROL. A Medium-integrity None-type caller gets nothing: MIC blocks read and write, PIP allows only READ_CONTROL but MIC already decided those bits as denied.
- **Subsystems:** MIC (11.13), PIP (11.15)
- **Target:** Cargo
- **Spec refs:** 11.13 (NO_READ_UP), 11.15 (PIP allowed set), 11.17 mandatory_decided

**Test 5**
- **Name:** `pip_trust_label_ordering_before_mic_label_in_sacl`
- **Assertion:** When the SACL has the PIP trust label ACE listed before the MIC mandatory label ACE, both are still correctly extracted and enforced. PreSACLWalk scans the entire SACL.
- **Subsystems:** MIC (11.13), PIP (11.15), SACL parsing
- **Target:** Cargo
- **Spec refs:** 11.17 PreSACLWalk (scan all ACEs)

**Test 6**
- **Name:** `mic_default_medium_plus_explicit_pip_label`
- **Assertion:** Object has no MIC label ACE (defaults to Medium/NO_WRITE_UP) but has an explicit PIP trust label. A Low-integrity caller who dominates PIP is still blocked by the default MIC label.
- **Subsystems:** MIC (11.13), PIP (11.15)
- **Target:** Cargo
- **Spec refs:** 11.13 (default label), 11.15 (no default)

### Category 2: Restricted Token + Confinement Combined

**Test 7**
- **Name:** `restricted_and_confined_both_intersect`
- **Assertion:** A token that is both restricted (restricting SIDs) and confined (confinement_sid). The DACL grants READ+WRITE to the user SID, READ to a restricting SID, and READ to the confinement SID. Result: READ only (three-way intersection: normal=READ+WRITE, restricted=READ, confinement=READ).
- **Subsystems:** Restricted tokens (11.7), Confinement (11.14)
- **Target:** Cargo
- **Spec refs:** 11.17 steps 8, 8a

**Test 8**
- **Name:** `restricted_pass_grants_write_confinement_blocks_it`
- **Assertion:** Restricted pass grants WRITE (restricting SID matches allow ACE). But confinement SID has no matching ACE for WRITE. Final result: WRITE is denied by confinement intersection.
- **Subsystems:** Restricted tokens (11.7), Confinement (11.14)
- **Target:** Cargo
- **Spec refs:** 11.14 (absolute intersection), 11.17 step 8a

**Test 9**
- **Name:** `privilege_orback_after_restricted_then_stripped_by_confinement`
- **Assertion:** Token has SeBackupPrivilege, restricting SIDs, and confinement. After restricted intersection, privilege-granted bits are OR'd back (step 8). But confinement in step 8a strips them again -- privileges do NOT bypass confinement.
- **Subsystems:** Restricted tokens (11.7), Confinement (11.14), Privileges (11.6)
- **Target:** Cargo
- **Spec refs:** 11.7 (privileges bypass restricted), 11.14 (no privilege bypass), 11.17 step 8 vs 8a ordering

**Test 10**
- **Name:** `write_restricted_plus_confinement_write_bits`
- **Assertion:** Write-restricted token with confinement. Normal pass grants READ+WRITE. Restricted intersection applies only to write bits. Confinement applies to ALL bits. Confinement that grants only READ strips WRITE regardless of write-restricted semantics.
- **Subsystems:** Restricted tokens (11.7 write-restricted), Confinement (11.14)
- **Target:** Cargo
- **Spec refs:** 11.7 (write-restricted definition), 11.14, 11.17

**Test 11**
- **Name:** `restricted_and_confined_null_dacl`
- **Assertion:** Object has NULL DACL. Normal pass grants all. Restricted pass on NULL DACL also grants all (NULL DACL grants to any SID matcher). Confinement pass on NULL DACL also grants all. Final: all granted.
- **Subsystems:** Restricted tokens (11.7), Confinement (11.14), NULL DACL (11.3)
- **Target:** Cargo
- **Spec refs:** 11.3 (NULL DACL), 11.14 (NULL DACL grants access to confined)

**Test 12**
- **Name:** `restricted_and_confined_empty_dacl`
- **Assertion:** Object has empty DACL (present, zero ACEs). Owner implicit rights in normal pass (if owner matches). Restricted pass: owner implicit rights evaluated if owner in restricting SIDs. Confinement: skip_owner_implicit=true, so no implicit rights. Result: confinement blocks owner implicit.
- **Subsystems:** Restricted tokens (11.7), Confinement (11.14), Owner implicit (11.4)
- **Target:** Cargo
- **Spec refs:** 11.4, 11.14 (owner implicit skipped), 11.17 EvaluateDACL skip_owner_implicit

### Category 3: Restricted + MIC + Privilege

**Test 13**
- **Name:** `backup_privilege_survives_mic_and_restricted_intersection`
- **Assertion:** Token has SeBackupPrivilege (with BACKUP_INTENT) and restricting SIDs. Object has Medium MIC label. Caller is Medium integrity, so MIC does not restrict. Backup grants all read bits. After restricted intersection, backup bits are OR'd back. Result: read access granted.
- **Subsystems:** Privileges (11.6), MIC (11.13), Restricted tokens (11.7)
- **Target:** Cargo
- **Spec refs:** 11.6 (SeBackupPrivilege), 11.7 (privilege OR-back), 11.13

**Test 14**
- **Name:** `backup_privilege_blocked_by_high_integrity_mic`
- **Assertion:** MIC does not constrain privileges (per 11.13). Token with SeBackupPrivilege, Low integrity, accessing High-integrity object with NO_WRITE_UP only. MIC blocks WRITE bits but not read bits. Backup privilege grants read bits before MIC runs. MIC only decides undecided bits. Backup read bits survive MIC.
- **Subsystems:** Privileges (11.6), MIC (11.13), Restricted tokens (11.7)
- **Target:** Cargo
- **Spec refs:** 11.13 ("MIC does not constrain privileges"), 11.17 step order (privileges at step 3, MIC at step 4)

**Test 15**
- **Name:** `restricted_token_with_backup_privilege_and_mic_write_up`
- **Assertion:** Low-integrity token with SeBackupPrivilege and restricting SIDs. Object is Medium integrity with NO_WRITE_UP. Backup grants read bits (step 3). MIC blocks write bits (step 4). Restricted intersection happens (step 8), but privilege bits are OR'd back. Write bits remain blocked by MIC. Final: read granted via privilege, write denied by MIC.
- **Subsystems:** Privileges (11.6), MIC (11.13), Restricted tokens (11.7)
- **Target:** Cargo
- **Spec refs:** 11.6, 11.7, 11.13, 11.17

**Test 16**
- **Name:** `take_ownership_privilege_blocked_by_mic_mandatory_decided`
- **Assertion:** SeTakeOwnershipPrivilege on a token accessing a High-integrity object. Caller is Medium integrity. MIC blocks write-up, which sets WRITE_OWNER in mandatory_decided. Step 7a checks mandatory_decided and does NOT override. WRITE_OWNER denied.
- **Subsystems:** Privileges (11.6), MIC (11.13)
- **Target:** Cargo
- **Spec refs:** 11.17 step 7a (mandatory_decided check), 11.13

**Test 17**
- **Name:** `relabel_privilege_punches_through_mic_for_write_owner`
- **Assertion:** SeRelabelPrivilege allows WRITE_OWNER through MIC even for non-dominant caller. The DACL must still grant WRITE_OWNER -- SeRelabelPrivilege loosens MIC, it doesn't grant the right.
- **Subsystems:** Privileges (11.6), MIC (11.13)
- **Target:** Cargo
- **Spec refs:** 11.13 (SeRelabelPrivilege), 11.17 EnforceMIC

### Category 4: Confinement + CAP

**Test 18**
- **Name:** `confinement_intersects_then_cap_intersects`
- **Assertion:** Confined token accessing object with a CAP scoped policy. Normal DACL grants WRITE. Confinement grants only READ. CAP rule grants READ+WRITE. Result: READ (confinement caps first, CAP intersects with already-capped result).
- **Subsystems:** Confinement (11.14), CAP (11.16)
- **Target:** Cargo
- **Spec refs:** 11.17 steps 8a (confinement) then 9 (CAP)

**Test 19**
- **Name:** `cap_rule_also_evaluated_with_confinement`
- **Assertion:** CAP rule evaluation uses the full pipeline (steps 1-8a per rule). If the token is confined, the confinement pass runs inside each CAP rule evaluation too. The CAP result inherits the confinement restriction.
- **Subsystems:** Confinement (11.14), CAP (11.16)
- **Target:** Cargo
- **Spec refs:** 11.16 ("Full pipeline per rule"), 11.17 step 9

**Test 20**
- **Name:** `confined_token_with_cap_capability_sid_ace`
- **Assertion:** Object has a CAP rule whose DACL grants access to a capability SID. The confined token has that capability SID in confinement_capabilities. The CAP evaluation's confinement pass matches. Access granted through the CAP rule.
- **Subsystems:** Confinement (11.14), CAP (11.16), Capability SIDs (11.14)
- **Target:** Cargo
- **Spec refs:** 11.14 (capability SIDs), 11.16

### Category 5: Impersonation + MIC + PIP

**Test 21**
- **Name:** `impersonation_mic_uses_effective_token_integrity`
- **Assertion:** High-integrity service impersonating a Low-integrity client. MIC reads from the effective token (Low). Object is Medium with NO_WRITE_UP. MIC blocks write because Low < Medium.
- **Subsystems:** Impersonation (12), MIC (11.13)
- **Target:** Cargo (unit) + Provium (integration)
- **Spec refs:** 12.5 ("MIC uses the effective token"), 8.3

**Test 22**
- **Name:** `impersonation_pip_uses_psb_not_effective_token`
- **Assertion:** Protected process (PSB pip_type=Protected, pip_trust=4096) impersonating a None-type client token. PIP reads from PSB, not effective token. Caller dominates PIP-protected object. Access granted.
- **Subsystems:** Impersonation (12), PIP (11.15), PSB (8)
- **Target:** Cargo (unit) + Provium (integration)
- **Spec refs:** 12.5 ("PIP uses the PSB"), 8.3, 11.15

**Test 23**
- **Name:** `impersonation_cannot_escalate_pip_via_token`
- **Assertion:** None-type process impersonates a token. Even if the impersonation token somehow carried PIP-like fields, PIP reads from PSB. The process remains None-type. Cannot access PIP-protected object.
- **Subsystems:** Impersonation (12), PIP (11.15), PSB (8)
- **Target:** Cargo
- **Spec refs:** 12.5, 8.3

**Test 24**
- **Name:** `impersonation_mic_plus_pip_combined`
- **Assertion:** Protected-process (High pip_trust) impersonating a Low-integrity client. Object has High MIC label and Protected trust label with pip_trust=2048. MIC blocks write (Low < High), PIP passes (pip_trust 4096 > 2048). Result: read only (MIC governs).
- **Subsystems:** Impersonation (12), MIC (11.13), PIP (11.15)
- **Target:** Cargo
- **Spec refs:** 12.5, 11.13, 11.15

**Test 25**
- **Name:** `identification_level_denied_regardless_of_pip_or_mic`
- **Assertion:** Identification-level impersonation token is denied at step 0, before MIC or PIP evaluation. Even with dominant integrity and PIP trust, access is denied.
- **Subsystems:** Impersonation (12.1), MIC (11.13), PIP (11.15)
- **Target:** Cargo
- **Spec refs:** 11.17 step 0, 12.1

### Category 6: Conditional ACE + Restricted Token

**Test 26**
- **Name:** `conditional_member_of_sees_normal_groups_in_normal_pass`
- **Assertion:** Conditional ACE with `Member_of({GroupA})`. GroupA is in the token's normal groups (enabled). Normal pass: condition TRUE, ACE fires. The restricting SIDs do not affect this evaluation.
- **Subsystems:** Conditional ACEs (11.12), Restricted tokens (11.7)
- **Target:** Cargo
- **Spec refs:** 11.12, 11.7

**Test 27**
- **Name:** `restricted_pass_conditional_member_of_uses_full_token`
- **Assertion:** In the restricted pass, conditional expressions still see the full token (user groups, claims). `Member_of` sees normal groups, not restricting SIDs. But the SID matcher only checks restricting SIDs. Both must pass for the ACE to fire in the restricted pass.
- **Subsystems:** Conditional ACEs (11.12), Restricted tokens (11.7)
- **Target:** Cargo
- **Spec refs:** 11.12 ("Conditional expressions see virtual groups"), 11.17 step 8 (restricted SID match + full token for expressions)

**Test 28**
- **Name:** `restricted_pass_conditional_ace_sid_not_in_restricting_sids`
- **Assertion:** Conditional ACE targets GroupA with condition `@User.department == "eng"`. GroupA is NOT in restricting SIDs. SID match fails in restricted pass. Condition is never evaluated. ACE does not fire in restricted pass. Intersection removes the bit.
- **Subsystems:** Conditional ACEs (11.12), Restricted tokens (11.7)
- **Target:** Cargo
- **Spec refs:** 11.12 ("SID matched first"), 11.7

**Test 29**
- **Name:** `restricted_pass_deny_only_group_conditional_deny_ace`
- **Assertion:** Token has GroupA as deny-only. Conditional deny ACE targets GroupA with condition TRUE. Normal pass: deny-only group matches deny ACE, condition evaluates, deny fires. Restricted pass: GroupA must be in restricting SIDs for the SID match. If not, the deny does not fire in the restricted pass -- but the normal pass already denied it.
- **Subsystems:** Conditional ACEs (11.12), Restricted tokens (11.7), Deny-only groups (11.3)
- **Target:** Cargo
- **Spec refs:** 11.3 (deny-only), 11.12, 11.7

**Test 30**
- **Name:** `restricted_pass_with_restricted_device_groups_conditional`
- **Assertion:** Token has restricted_device_groups. In the restricted pass, the r_token is built with `device_groups=token.restricted_device_groups`. A conditional ACE using `Device_Member_of({DeviceGroupA})` evaluates against the restricted device groups, not the unrestricted ones.
- **Subsystems:** Conditional ACEs (11.12), Restricted tokens (11.7), Device claims
- **Target:** Cargo
- **Spec refs:** 11.17 step 8 ("swap device groups")

### Category 7: Owner Implicit + Confinement

**Test 31**
- **Name:** `owner_implicit_rights_skipped_in_confinement_pass`
- **Assertion:** Confined token is the owner of an object. Normal pass grants READ_CONTROL + WRITE_DAC via owner implicit. Confinement pass: skip_owner_implicit=true, so no implicit grant. Confinement intersection strips READ_CONTROL + WRITE_DAC unless an explicit ACE grants them to the confinement SID.
- **Subsystems:** Owner implicit (11.4), Confinement (11.14)
- **Target:** Cargo
- **Spec refs:** 11.14 ("Owner implicit rights are skipped"), 11.17 step 8a (skip_owner_implicit=true)

**Test 32**
- **Name:** `owner_with_confinement_ace_granting_write_dac`
- **Assertion:** Confined token is owner. DACL has an ACE granting WRITE_DAC to the confinement SID. Normal pass: owner implicit grants READ_CONTROL + WRITE_DAC. Confinement pass: no implicit, but DACL ACE grants WRITE_DAC to confinement SID. Result: WRITE_DAC survives intersection.
- **Subsystems:** Owner implicit (11.4), Confinement (11.14)
- **Target:** Cargo
- **Spec refs:** 11.4, 11.14, 11.17

**Test 33**
- **Name:** `owner_rights_ace_plus_confinement`
- **Assertion:** Object has OWNER RIGHTS ACE granting READ_CONTROL only. Token is confined and is the owner. Normal pass: implicit suppressed by OWNER RIGHTS, OWNER RIGHTS ACE grants READ_CONTROL. Confinement pass: skip_owner_implicit=true (redundant here), confinement SID must match an ACE. If confinement SID has no ACE, result is 0.
- **Subsystems:** Owner implicit (11.4), OWNER RIGHTS, Confinement (11.14)
- **Target:** Cargo
- **Spec refs:** 11.4 (OWNER RIGHTS suppression), 11.14

### Category 8: MAXIMUM_ALLOWED + Restricted + Confinement

**Test 34**
- **Name:** `maximum_allowed_restricted_confinement_intersection`
- **Assertion:** MAXIMUM_ALLOWED request on a token that is both restricted and confined. The full pipeline runs to completion. Each intersection narrows the accumulated result. The final granted mask is the three-way intersection: normal DACL result intersected with restricted result intersected with confinement result.
- **Subsystems:** MAXIMUM_ALLOWED (11.5), Restricted tokens (11.7), Confinement (11.14)
- **Target:** Cargo
- **Spec refs:** 11.5 (no short-circuit), 11.7, 11.14, 11.17

**Test 35**
- **Name:** `maximum_allowed_with_privilege_orback_then_confinement`
- **Assertion:** MAXIMUM_ALLOWED with SeBackupPrivilege on a restricted+confined token. Backup bits are OR'd back after restricted intersection. Then confinement strips them. The MAXIMUM_ALLOWED result reflects the confinement constraint.
- **Subsystems:** MAXIMUM_ALLOWED (11.5), Privileges (11.6), Restricted tokens (11.7), Confinement (11.14)
- **Target:** Cargo
- **Spec refs:** 11.5, 11.6, 11.7, 11.14

**Test 36**
- **Name:** `maximum_allowed_zero_granted_succeeds`
- **Assertion:** MAXIMUM_ALLOWED on a confined token with empty DACL and no confinement ACE. Result: granted=0, allowed=true (asked for nothing, got nothing is valid).
- **Subsystems:** MAXIMUM_ALLOWED (11.5), Confinement (11.14)
- **Target:** Cargo
- **Spec refs:** 11.5 ("pure MAXIMUM_ALLOWED always succeeds")

**Test 37**
- **Name:** `maximum_allowed_combined_with_specific_bits_restricted_confined`
- **Assertion:** Request is `MAXIMUM_ALLOWED | READ_CONTROL`. Token is restricted + confined. If confinement blocks READ_CONTROL, allowed=false (specific bit not granted). Granted mask shows whatever the three-way intersection produces.
- **Subsystems:** MAXIMUM_ALLOWED (11.5), Restricted tokens (11.7), Confinement (11.14)
- **Target:** Cargo
- **Spec refs:** 11.5 (composition with specific bits)

### Category 9: CAP + MIC

**Test 38**
- **Name:** `cap_rule_evaluation_inherits_mic_constraint`
- **Assertion:** Object has Medium MIC label. CAP rule's effective DACL grants write to caller. But the CAP rule evaluation runs EvaluateSecurityDescriptor with the same SACL, so MIC is enforced inside the CAP rule. A Low-integrity caller gets write blocked by MIC inside the CAP evaluation.
- **Subsystems:** CAP (11.16), MIC (11.13)
- **Target:** Cargo
- **Spec refs:** 11.16 ("Full pipeline per rule"), 11.17 step 9

**Test 39**
- **Name:** `cap_rule_uses_object_sacl_not_rule_sacl_for_mic`
- **Assertion:** The CAP rule creates an eff_sd that copies the original SD's owner/group/SACL but substitutes the DACL. The MIC label in the SACL is preserved. MIC enforcement inside the CAP rule uses the object's actual integrity label.
- **Subsystems:** CAP (11.16), MIC (11.13)
- **Target:** Cargo
- **Spec refs:** 11.17 step 9 (`eff_sd = copy(sd), eff_sd.dacl = rule.effective_dacl`)

**Test 40**
- **Name:** `cap_recovery_policy_plus_mic_block`
- **Assertion:** Missing CAP policy triggers recovery policy (grant full to owner/admins/SYSTEM). But MIC still applies inside the recovery evaluation. A Low-integrity admin token is blocked from writes by MIC even under recovery.
- **Subsystems:** CAP (11.16), MIC (11.13)
- **Target:** Cargo
- **Spec refs:** 11.16 (recovery policy), 11.13

### Category 10: Write-Restricted + Append-Only

**Test 41**
- **Name:** `write_restricted_intersection_includes_file_append_data`
- **Assertion:** FILE_APPEND_DATA is a write-category bit (it maps from GENERIC_WRITE). A write-restricted token's restricted intersection applies to FILE_APPEND_DATA. If the restricting SID has no ACE granting FILE_APPEND_DATA, it is stripped.
- **Subsystems:** Restricted tokens (11.7 write-restricted), File access (FACS)
- **Target:** Cargo
- **Spec refs:** 11.7 ("write-restricted... GENERIC_WRITE maps to"), 11.17 step 8

**Test 42**
- **Name:** `write_restricted_read_bits_bypass_restricted_pass`
- **Assertion:** FILE_READ_DATA is a read-category bit. Write-restricted token: read bits come from the normal pass alone. Even if the restricting SID list has no matching ACE, FILE_READ_DATA is not intersected.
- **Subsystems:** Restricted tokens (11.7 write-restricted), File access
- **Target:** Cargo
- **Spec refs:** 11.7 ("Read and execute access comes from the normal pass alone")

**Test 43**
- **Name:** `write_restricted_token_file_write_data_vs_append_data`
- **Assertion:** DACL grants FILE_WRITE_DATA + FILE_APPEND_DATA to user. Restricting SID has ACE granting FILE_APPEND_DATA only. Write-restricted intersection: FILE_WRITE_DATA stripped (not in restricted grant), FILE_APPEND_DATA preserved (in both). Result: FILE_APPEND_DATA only.
- **Subsystems:** Restricted tokens (11.7 write-restricted)
- **Target:** Cargo
- **Spec refs:** 11.7, 11.17 step 8

### Category 11: Inheritance + CREATOR OWNER + Confinement

**Test 44**
- **Name:** `creator_owner_substitution_uses_token_owner_not_confinement_sid`
- **Assertion:** A confined process creates a file under a directory with CREATOR OWNER ACEs. The substitution uses the creating token's owner SID (user SID), NOT the confinement SID. The child file gets an ACE for the user's real SID.
- **Subsystems:** Inheritance (9.5), Confinement (11.14)
- **Target:** Cargo
- **Spec refs:** 9.5 ("replaced with the SID of the principal who created the child object"), 7.3 (owner_sid_index)

**Test 45**
- **Name:** `confined_process_creates_file_inherits_no_confinement_ace`
- **Assertion:** Parent directory has inheritable ACEs but none for the confinement SID. Confined process creates child file. Child inherits parent's ACEs. No ACE is auto-generated for the confinement SID. The confined process cannot access the child it just created (unless token default DACL includes confinement SID ACE).
- **Subsystems:** Inheritance (9.5), Confinement (11.14), Token default DACL (7.3)
- **Target:** Cargo
- **Spec refs:** 9.5 (inheritance algorithm), 11.14

**Test 46**
- **Name:** `confined_creator_with_default_dacl_containing_confinement_ace`
- **Assertion:** Confined token has a default DACL that includes an allow ACE for its confinement SID. When creating an object with no parent inheritable ACEs and no explicit SD, the default DACL is used. The confined process can access the newly created object.
- **Subsystems:** Inheritance (9.5), Confinement (11.14), Token default DACL
- **Target:** Cargo
- **Spec refs:** 9.5 ("no inheritable ACEs... token's default DACL"), 11.14

### Category 12: PIP + Privilege Revocation + Restricted OR-back

**Test 47**
- **Name:** `pip_revokes_backup_privilege_bits_before_restricted_orback`
- **Assertion:** PIP runs in PreSACLWalk (step 4). Backup privilege grants read bits (step 3). PIP revokes them immediately (clears from granted AND privilege_granted). Step 8 restricted OR-back uses privilege_granted -- which is now empty for backup bits. PIP wins.
- **Subsystems:** PIP (11.15), Privileges (11.6), Restricted tokens (11.7)
- **Target:** Cargo
- **Spec refs:** 11.15 ("revoke privilege-granted bits"), 11.17 EnforcePIP, step 8

**Test 48**
- **Name:** `pip_revokes_security_privilege_then_restricted_orback_empty`
- **Assertion:** SeSecurityPrivilege grants ACCESS_SYSTEM_SECURITY. PIP revokes it (ACCESS_SYSTEM_SECURITY is in all_bits). After PIP, privilege_granted has ACCESS_SYSTEM_SECURITY cleared. Restricted OR-back at step 8 cannot restore it.
- **Subsystems:** PIP (11.15), Privileges (11.6), Restricted tokens (11.7)
- **Target:** Cargo
- **Spec refs:** 11.15, 11.17 EnforcePIP ("all_bits = ... | ACCESS_SYSTEM_SECURITY")

**Test 49**
- **Name:** `pip_revokes_take_ownership_privilege_mandatory_decided`
- **Assertion:** SeTakeOwnershipPrivilege fires at step 7a. But PIP already set WRITE_OWNER in decided and cleared it from granted at step 4. Step 7a checks `not (mandatory_decided & WRITE_OWNER)` -- it IS in mandatory_decided (PIP populated it). Privilege does not fire.
- **Subsystems:** PIP (11.15), Privileges (11.6)
- **Target:** Cargo
- **Spec refs:** 11.17 step 7a (mandatory_decided), EnforcePIP

**Test 50**
- **Name:** `pip_allows_subset_privilege_orback_only_restores_subset`
- **Assertion:** PIP trust label allows READ_CONTROL only. Backup privilege grants all-read-mapped. PIP revokes everything except READ_CONTROL from privilege_granted. After restricted OR-back, only READ_CONTROL from privilege_granted is restored (it was the only surviving privilege bit).
- **Subsystems:** PIP (11.15), Privileges (11.6), Restricted tokens (11.7)
- **Target:** Cargo
- **Spec refs:** 11.15, 11.7 ("privilege OR-back"), 11.17

### Category 13: Token Adjustment + Cached AccessCheck

**Test 51**
- **Name:** `adjust_privileges_bumps_modified_id`
- **Assertion:** After AdjustPrivileges (enable a privilege), the token's modified_id changes. A cached access decision keyed on the old modified_id is invalidated.
- **Subsystems:** Token adjustment (7.6), Token identity (7.3)
- **Target:** Cargo (unit) + Provium (integration)
- **Spec refs:** 7.6 ("All bump modified_id")

**Test 52**
- **Name:** `adjust_groups_bumps_modified_id`
- **Assertion:** After AdjustGroups (disable a non-mandatory group), modified_id changes. Subsequent AccessCheck should use the updated group state.
- **Subsystems:** Token adjustment (7.6), AccessCheck (11)
- **Target:** Cargo (unit) + Provium (integration)
- **Spec refs:** 7.6

**Test 53**
- **Name:** `adjust_default_bumps_modified_id`
- **Assertion:** AdjustDefault changing the default DACL bumps modified_id. New objects created after the adjustment use the new default DACL.
- **Subsystems:** Token adjustment (7.6), Inheritance/creation (9.5)
- **Target:** Cargo
- **Spec refs:** 7.6 (AdjustDefault)

**Test 54**
- **Name:** `remove_privilege_then_access_check_no_longer_grants`
- **Assertion:** Remove SeBackupPrivilege via AdjustPrivileges. Subsequent AccessCheck with BACKUP_INTENT no longer grants read bits via privilege.
- **Subsystems:** Token adjustment (7.6), Privileges (11.6), AccessCheck (11)
- **Target:** Cargo
- **Spec refs:** 7.6 ("Remove: permanently delete"), 11.6

**Test 55**
- **Name:** `enable_privilege_then_access_check_grants`
- **Assertion:** Token has SeSecurityPrivilege present but disabled. AccessCheck requesting ACCESS_SYSTEM_SECURITY fails. After AdjustPrivileges enable, the same AccessCheck succeeds.
- **Subsystems:** Token adjustment (7.6), Privileges (11.6), AccessCheck (11)
- **Target:** Cargo
- **Spec refs:** 7.6, 11.6 (privilege must be enabled)

### Category 14: Fork + Impersonation + Exec

**Test 56**
- **Name:** `fork_drops_impersonation_child_gets_primary_only`
- **Assertion:** Parent is impersonating (Low-integrity client token as effective). Fork. Child's effective credential is set from real_cred (primary token), not cred (impersonation token). Child runs with primary (High-integrity) token.
- **Subsystems:** Fork (7.4), Impersonation (12)
- **Target:** Provium
- **Spec refs:** 7.4 ("impersonation token is not inherited")

**Test 57**
- **Name:** `exec_reverts_impersonation_new_program_uses_primary`
- **Assertion:** Thread is impersonating. After exec, impersonation is reverted. New program starts with primary token as effective.
- **Subsystems:** Exec (7.4), Impersonation (12)
- **Target:** Provium
- **Spec refs:** 7.4 ("impersonation is reverted before the new program runs")

**Test 58**
- **Name:** `fork_then_exec_token_survives_both`
- **Assertion:** Parent has primary token T. Fork: child gets deep copy of T. Child execs: token survives (no setuid, no NEW_PROCESS_MIN trigger). Token after exec is equivalent to T.
- **Subsystems:** Fork (7.4), Exec (7.4)
- **Target:** Provium
- **Spec refs:** 7.4 ("primary token survives execve unchanged")

**Test 59**
- **Name:** `fork_impersonating_exec_service_binary_primary_survives`
- **Assertion:** peinit-like flow: parent impersonating, forks, installs service token on child, child execs. At each stage: (1) after fork: child has parent's primary token, no impersonation; (2) after token install: child has service token; (3) after exec: service token survives.
- **Subsystems:** Fork (7.4), Exec (7.4), Impersonation (12), Token install
- **Target:** Provium
- **Spec refs:** 7.4, 12, 7.5 (SeAssignPrimaryTokenPrivilege)

### Additional Adversarial Compound Tests

**Test 60**
- **Name:** `all_layers_active_simultaneously`
- **Assertion:** Token is confined + restricted + has SeBackupPrivilege + Low integrity. Object has High MIC label (NO_WRITE_UP + NO_READ_UP) + PIP trust label + DACL + CAP scoped policy. Verify each layer's contribution is correct and the final result is the composition of all constraints.
- **Subsystems:** All
- **Target:** Cargo
- **Spec refs:** 11.17 (full pipeline)

**Test 61**
- **Name:** `confinement_blocks_access_system_security_via_privilege`
- **Assertion:** Confined token with SeSecurityPrivilege. ACCESS_SYSTEM_SECURITY is granted by privilege (step 3). Confinement (step 8a) intersects -- ACCESS_SYSTEM_SECURITY is not in any confinement ACE. Result: ACCESS_SYSTEM_SECURITY denied.
- **Subsystems:** Confinement (11.14), Privileges (11.6)
- **Target:** Cargo
- **Spec refs:** 11.14 ("SACL access is unreachable")

**Test 62**
- **Name:** `confinement_blocks_take_ownership_privilege`
- **Assertion:** Confined token with SeTakeOwnershipPrivilege. Step 7a grants WRITE_OWNER. Step 8a confinement strips it (no confinement ACE for WRITE_OWNER).
- **Subsystems:** Confinement (11.14), Privileges (11.6)
- **Target:** Cargo
- **Spec refs:** 11.14 ("Privileges do not bypass confinement")

**Test 63**
- **Name:** `restricted_owner_implicit_rights_owner_not_in_restricting_sids`
- **Assertion:** Token is owner of object. Restricted token where owner SID is NOT in restricting SIDs. Normal pass: owner gets READ_CONTROL + WRITE_DAC. Restricted pass: owner implicit not triggered (SidInRestrictingSids fails). Intersection: READ_CONTROL + WRITE_DAC removed. BUT: privilege OR-back does not help (these are not privilege-granted).
- **Subsystems:** Restricted tokens (11.7), Owner implicit (11.4)
- **Target:** Cargo
- **Spec refs:** 11.7 ("Owner implicit rights in the restricted pass"), 11.17

**Test 64**
- **Name:** `restricted_owner_implicit_rights_owner_in_restricting_sids`
- **Assertion:** Token is owner. Owner SID IS in restricting SIDs. Both normal and restricted passes grant owner implicit. Intersection preserves READ_CONTROL + WRITE_DAC.
- **Subsystems:** Restricted tokens (11.7), Owner implicit (11.4)
- **Target:** Cargo
- **Spec refs:** 11.7, 11.17

**Test 65**
- **Name:** `owner_rights_ace_suppresses_in_both_normal_and_restricted_passes`
- **Assertion:** DACL has OWNER RIGHTS ACE. Normal pass: owner implicit suppressed. Restricted pass: also evaluates owner implicit independently. If OWNER RIGHTS is present, implicit suppressed in both passes.
- **Subsystems:** Restricted tokens (11.7), Owner implicit (11.4), OWNER RIGHTS
- **Target:** Cargo
- **Spec refs:** 11.4, 11.7, 11.17

**Test 66**
- **Name:** `virtual_group_owner_rights_in_restricted_pass`
- **Assertion:** Owner SID is in restricting SIDs. The restricted pass builds restricted_sids with SID_OWNER_RIGHTS injected. ACEs targeting S-1-3-4 can match in the restricted pass SID matcher.
- **Subsystems:** Restricted tokens (11.7), OWNER RIGHTS, Virtual groups
- **Target:** Cargo
- **Spec refs:** 11.17 step 8 ("SidInRestrictingSids(sd.owner, restricted_sids) -> inject SID_OWNER_RIGHTS")

**Test 67**
- **Name:** `principal_self_in_restricted_pass`
- **Assertion:** self_sid matches a restricting SID. The restricted pass injects SID_PRINCIPAL_SELF into restricted_sids. ACEs targeting S-1-5-10 match in the restricted pass.
- **Subsystems:** Restricted tokens (11.7), PRINCIPAL_SELF (11.8)
- **Target:** Cargo
- **Spec refs:** 11.17 step 8 ("SidInRestrictingSids(self_sid, restricted_sids) -> inject SID_PRINCIPAL_SELF")

**Test 68**
- **Name:** `principal_self_in_confinement_pass_isolated_from_user`
- **Assertion:** Confined token, self_sid matches user's SID (not a confinement SID). Confinement pass: PRINCIPAL_SELF is NOT injected (self_sid not in confinement_sids). ACEs targeting S-1-5-10 do not match in confinement pass.
- **Subsystems:** Confinement (11.14), PRINCIPAL_SELF (11.8)
- **Target:** Cargo
- **Spec refs:** 11.14 ("PRINCIPAL_SELF is isolated from user identity")

**Test 69**
- **Name:** `confinement_conditional_sees_real_groups`
- **Assertion:** Conditional ACE targeting confinement SID with condition `Member_of({GroupA})`. GroupA is in the token's real groups. Confinement pass: SID match succeeds (confinement SID in confinement_sids). Condition evaluates against full token -- sees GroupA. ACE fires.
- **Subsystems:** Confinement (11.14), Conditional ACEs (11.12)
- **Target:** Cargo
- **Spec refs:** 11.14 ("Conditional expressions see the full token")

**Test 70**
- **Name:** `confinement_conditional_member_of_deny_only_group`
- **Assertion:** Conditional ACE targeting confinement SID with `Member_of({GroupB})`. GroupB is deny-only on the token. for_allow=true: deny-only groups do not satisfy Member_of. Condition returns FALSE. ACE skipped.
- **Subsystems:** Confinement (11.14), Conditional ACEs (11.12), Deny-only groups
- **Target:** Cargo
- **Spec refs:** 11.12 ("deny-only groups do not satisfy allow-ACE conditions"), 11.14

**Test 71**
- **Name:** `cap_no_backup_intent_inside_rule_evaluation`
- **Assertion:** Token has SeBackupPrivilege. Normal evaluation uses BACKUP_INTENT. CAP rule evaluation passes privilege_intent=0. Inside the CAP rule, backup privilege is invisible. CAP rule's DACL must independently grant read access.
- **Subsystems:** CAP (11.16), Privileges (11.6)
- **Target:** Cargo
- **Spec refs:** 11.17 step 9 ("privilege_intent=0")

**Test 72**
- **Name:** `cap_security_privilege_survives_intersection`
- **Assertion:** SeSecurityPrivilege grants ACCESS_SYSTEM_SECURITY in both the normal evaluation and each CAP rule evaluation (same token, same privilege). The AND preserves it.
- **Subsystems:** CAP (11.16), Privileges (11.6)
- **Target:** Cargo
- **Spec refs:** 11.17 step 9 ("Non-intent-gated privileges survive the AND")

**Test 73**
- **Name:** `cap_error_preserves_privilege_granted_only`
- **Assertion:** CAP rule evaluation errors. Fail-closed: `cap_effective &= privilege_granted`. Only privilege-granted bits survive. DACL-granted bits are stripped.
- **Subsystems:** CAP (11.16), Privileges (11.6)
- **Target:** Cargo
- **Spec refs:** 11.16 (error handling), 11.17 step 9

**Test 74**
- **Name:** `mic_plus_restricted_plus_confinement_plus_cap_all_narrow`
- **Assertion:** The gauntlet: MIC blocks write. Restricted intersection blocks DELETE. Confinement blocks WRITE_DAC. CAP blocks FILE_READ_ATTRIBUTES. Each layer removes one right from the original full grant. Final result is the set minus all four.
- **Subsystems:** MIC (11.13), Restricted (11.7), Confinement (11.14), CAP (11.16)
- **Target:** Cargo
- **Spec refs:** 11.17 (full pipeline)

**Test 75**
- **Name:** `new_process_min_lowers_integrity_at_exec`
- **Assertion:** Medium-integrity token with NEW_PROCESS_MIN policy. Exec a binary labeled Low integrity. Child token has Low integrity. Subsequent AccessCheck at Low integrity. Verify MIC prevents write to Medium objects.
- **Subsystems:** NEW_PROCESS_MIN (7.4), MIC (11.13)
- **Target:** Provium
- **Spec refs:** 7.4 (NEW_PROCESS_MIN), 11.13

**Test 76**
- **Name:** `new_process_min_does_not_raise_integrity`
- **Assertion:** Low-integrity token with NEW_PROCESS_MIN. Exec a binary labeled High. Token integrity stays Low (can only lower, never raise).
- **Subsystems:** NEW_PROCESS_MIN (7.4)
- **Target:** Provium
- **Spec refs:** 7.4 ("can only lower integrity, never raise it")

**Test 77**
- **Name:** `pip_plus_confinement_neither_bypasses_other`
- **Assertion:** Object has PIP trust label + DACL with confinement ACE. Non-dominant caller with confinement. PIP restricts to a subset. Confinement restricts to a different subset. Final: intersection of PIP allowed set with confinement intersection.
- **Subsystems:** PIP (11.15), Confinement (11.14)
- **Target:** Cargo
- **Spec refs:** 11.15, 11.14, 11.17

**Test 78**
- **Name:** `pip_revokes_then_confinement_intersects_empty`
- **Assertion:** PIP allows only READ_CONTROL. Confinement has no ACE granting READ_CONTROL. PIP + confinement together = 0. Neither can compensate for the other.
- **Subsystems:** PIP (11.15), Confinement (11.14)
- **Target:** Cargo
- **Spec refs:** 11.15, 11.14

**Test 79**
- **Name:** `anonymous_token_through_full_pipeline`
- **Assertion:** Anonymous token (S-1-5-7 only, Impersonation level Anonymous). Not blocked by step 0 (Anonymous is allowed through). DACL walk matches only if ACE targets S-1-5-7 or Everyone. MIC defaults apply. PIP if labeled.
- **Subsystems:** Impersonation (12.3), DACL walk (11.3), MIC (11.13)
- **Target:** Cargo
- **Spec refs:** 12.3 ("Anonymous tokens ARE allowed"), 11.17 step 0

**Test 80**
- **Name:** `deny_only_user_sid_plus_restricted_token`
- **Assertion:** Token has user SID marked deny-only. Token also has restricting SIDs. Normal pass: user SID matches deny ACEs but not allow ACEs. Restricted pass: uses restricting SIDs only. If a restricting SID matches an allow ACE, restricted grants it. But normal pass denied it via deny ACE targeting user SID.
- **Subsystems:** Deny-only user SID (11.3), Restricted tokens (11.7)
- **Target:** Cargo
- **Spec refs:** 11.3 ("User SID deny-only"), 11.7

**Test 81**
- **Name:** `elevation_limited_token_restricted_groups_plus_mic`
- **Assertion:** Filtered (Limited elevation) token has admin groups as deny-only and privileges stripped. DACL allows admin group WRITE. Deny-only group triggers deny ACE but not allow ACE. Combined with Medium MIC: even if DACL granted write, the limited token correctly cannot write to admin-protected objects.
- **Subsystems:** Linked tokens (7.7), Deny-only groups (11.3), MIC (11.13)
- **Target:** Cargo
- **Spec refs:** 7.7 (elevation), 11.3 (deny-only), 11.13

**Test 82**
- **Name:** `conditional_ace_resource_attribute_plus_cap_applies_to`
- **Assertion:** Object has resource attribute `@Resource.department = "finance"`. DACL has conditional ACE: allow if `@Resource.department == "finance"`. CAP rule has applies_to: `@Resource.department == "finance"`. Both evaluate the same resource attribute independently. The DACL conditional grants access. The CAP applies_to triggers the rule. The CAP rule's DACL further restricts.
- **Subsystems:** Conditional ACEs (11.12), Resource attributes (11.11), CAP (11.16)
- **Target:** Cargo
- **Spec refs:** 11.11, 11.12, 11.16

**Test 83**
- **Name:** `local_claims_in_conditional_plus_confinement`
- **Assertion:** Local claim `@Local.mfa = true`. Conditional ACE targeting confinement SID with condition `@Local.mfa == true`. Confinement pass: SID match on confinement SID succeeds. Condition evaluates against local_claims (injected at call site). If MFA true, ACE fires in confinement pass. Access granted.
- **Subsystems:** Conditional ACEs (11.12), Confinement (11.14), Local claims
- **Target:** Cargo
- **Spec refs:** 11.12 (@Local), 11.14 ("Conditional expressions see the full token")

**Test 84**
- **Name:** `multiple_cap_policies_compose_via_and`
- **Assertion:** Object has two SYSTEM_SCOPED_POLICY_ID_ACEs referencing two different policies. Policy 1 grants READ+WRITE. Policy 2 grants READ only. AND composition: final result includes only READ from the CAP layer.
- **Subsystems:** CAP (11.16)
- **Target:** Cargo
- **Spec refs:** 11.16 ("AND property means composing multiple policies is safe"), Peios divergence (multiple policies)

**Test 85**
- **Name:** `cap_staging_difference_logged_not_enforced`
- **Assertion:** CAP rule has effective DACL granting READ and staged DACL granting READ+WRITE. Effective governs access (READ only). Staged is shadow-evaluated. Difference is logged. Final access: READ.
- **Subsystems:** CAP (11.16)
- **Target:** Cargo
- **Spec refs:** 11.16 (staging)

**Test 86**
- **Name:** `restricted_plus_confinement_plus_pip_triple_constraint`
- **Assertion:** Token is restricted + confined. Object is PIP-protected. PIP allows READ_CONTROL + DELETE. DACL grants READ_CONTROL + DELETE + WRITE_DAC to user. Restricted SIDs have ACE for READ_CONTROL + DELETE. Confinement SID has ACE for READ_CONTROL only. Final: READ_CONTROL (the tightest constraint wins at each bit).
- **Subsystems:** PIP (11.15), Restricted (11.7), Confinement (11.14)
- **Target:** Cargo
- **Spec refs:** 11.15, 11.7, 11.14, 11.17

**Test 87**
- **Name:** `backup_privilege_without_intent_flag_is_invisible`
- **Assertion:** Token has SeBackupPrivilege enabled. AccessCheck called with privilege_intent=0 (no BACKUP_INTENT). Step 2b clears SeBackupPrivilege from effective_privileges. No backup grant at step 3. Verify combined with restricted token: the privilege OR-back at step 8 also has nothing to restore for backup.
- **Subsystems:** Privileges (11.6), Restricted tokens (11.7)
- **Target:** Cargo
- **Spec refs:** 11.6 (intent-gated), 11.17 step 2b

**Test 88**
- **Name:** `restore_privilege_with_intent_plus_pip_revocation`
- **Assertion:** SeRestorePrivilege with RESTORE_INTENT. Grants write+WRITE_DAC+WRITE_OWNER+DELETE+ACCESS_SYSTEM_SECURITY. PIP-protected object with allowed mask 0. PIP revokes ALL privilege-granted bits. Final: zero.
- **Subsystems:** Privileges (11.6), PIP (11.15)
- **Target:** Cargo
- **Spec refs:** 11.6 (SeRestorePrivilege), 11.15 (privilege revocation)

**Test 89**
- **Name:** `confinement_exempt_skips_confinement_pass`
- **Assertion:** Token has confinement_sid set but confinement_exempt=true. Step 8a: condition `token.confinement_sid is not null and not token.confinement_exempt` is false. Confinement pass is skipped. Access determined by normal+restricted+CAP only.
- **Subsystems:** Confinement (11.14)
- **Target:** Cargo
- **Spec refs:** 11.14 (confinement_exempt), 11.17 step 8a

**Test 90**
- **Name:** `strict_confinement_no_all_application_packages`
- **Assertion:** Strictly confined token (no ALL_APPLICATION_PACKAGES in capabilities). Object DACL has ACE for ALL_APPLICATION_PACKAGES granting READ. Confinement pass: ALL_APPLICATION_PACKAGES not in confinement_sids. ACE does not match. Object inaccessible to strictly confined token even though normal confinement would allow it.
- **Subsystems:** Confinement (11.14, strict confinement)
- **Target:** Cargo
- **Spec refs:** 11.14 ("Strict Confinement")

**Test 91**
- **Name:** `impersonation_integrity_ceiling_prevents_mic_escalation`
- **Assertion:** Medium-integrity service attempts to impersonate a High-integrity token at Impersonation level. The impersonation is capped to Identification (integrity ceiling). AccessCheck with the Identification token fails at step 0.
- **Subsystems:** Impersonation (12.2), MIC (11.13)
- **Target:** Provium
- **Spec refs:** 12.2 (integrity ceiling), 12.1, 11.17 step 0

**Test 92**
- **Name:** `thread_impersonation_does_not_affect_sibling_thread`
- **Assertion:** Thread A impersonates client. Thread B in the same process retains the primary token. Thread B's AccessCheck uses the primary token, not the impersonation token.
- **Subsystems:** Impersonation (12), Tokens (7.4)
- **Target:** Provium
- **Spec refs:** 7.4 ("each thread maintains independent impersonation state")

**Test 93**
- **Name:** `psb_no_child_process_plus_pip_protection`
- **Assertion:** Process with no_child_process=true and pip_type=Protected. Fork attempt blocked by no_child_process. PIP protection is orthogonal -- it protects the process from external access. Both enforced independently.
- **Subsystems:** PSB (8.1), PIP (13)
- **Target:** Provium
- **Spec refs:** 8.1 (no_child_process), 13 (PIP process protection)

**Test 94**
- **Name:** `pip_protection_lost_at_exec_unsigned_binary`
- **Assertion:** Protected process execs an unsigned binary. PSB pip_type resets to None at exec. Subsequent PIP checks use None-type. Object previously accessible is now blocked by PIP.
- **Subsystems:** PSB (8.2), PIP (11.15)
- **Target:** Provium
- **Spec refs:** 8.2 ("PIP fields are reset based on the new binary's signature")

**Test 95**
- **Name:** `multiple_sacl_label_aces_only_first_used_mic_and_pip`
- **Assertion:** SACL has two MIC labels (Medium, then High) and two PIP trust labels (Protected/4096, then Isolated/8192). Only the first of each is used. Subsequent labels ignored.
- **Subsystems:** MIC (11.13), PIP (11.15), SACL parsing
- **Target:** Cargo
- **Spec refs:** 11.13 ("Only the first label matters"), 11.15 ("Only the first trust label matters")

**Test 96**
- **Name:** `conditional_owner_rights_ace_suppresses_implicit_even_when_false`
- **Assertion:** DACL has conditional OWNER RIGHTS ACE with condition that evaluates to FALSE. Pre-scan finds OWNER RIGHTS ACE (does not check condition). Implicit rights suppressed. Condition FALSE means ACE does not grant. Combined with restricted token: restricted pass also has implicit suppressed.
- **Subsystems:** OWNER RIGHTS (11.4), Conditional ACEs (11.12), Restricted tokens (11.7)
- **Target:** Cargo
- **Spec refs:** 11.12 ("conditional ACE targeting OWNER RIGHTS suppresses the implicit grant even if the condition later evaluates to FALSE")

**Test 97**
- **Name:** `claim_deny_only_flag_plus_conditional_allow_ace`
- **Assertion:** Token has claim `@User.clearance = 5` with USE_FOR_DENY_ONLY flag. Conditional allow ACE with `@User.clearance >= 3`. For allow ACE, deny-only claim resolves as absent. Condition: absent >= 3 is UNKNOWN. Allow ACE skipped. Combined with the same condition on a deny ACE: deny-only claim is visible, condition evaluates to TRUE, deny fires.
- **Subsystems:** Conditional ACEs (11.12), Claim flags (11.12)
- **Target:** Cargo
- **Spec refs:** 11.12 (USE_FOR_DENY_ONLY on claims)

**Test 98**
- **Name:** `confinement_plus_restricted_plus_cap_triple_intersection_with_privileges`
- **Assertion:** Token is confined + restricted + has SeSecurityPrivilege. CAP rule active. Privilege grants ACCESS_SYSTEM_SECURITY in normal eval and in CAP rule eval. Restricted OR-back restores it. But confinement strips it (runs after restricted). CAP rule's confinement pass also strips it. Final: ACCESS_SYSTEM_SECURITY denied.
- **Subsystems:** Confinement (11.14), Restricted (11.7), CAP (11.16), Privileges (11.6)
- **Target:** Cargo
- **Spec refs:** 11.14 ("SACL access is unreachable"), 11.17

**Test 99**
- **Name:** `enriched_token_virtual_groups_visible_in_cap_applies_to`
- **Assertion:** CAP rule's applies_to condition uses `Member_of({S-1-3-4})`. Caller is the owner. EnrichToken injects S-1-3-4 before CAP evaluation. applies_to evaluates against enriched_token. Condition TRUE. Rule applies.
- **Subsystems:** CAP (11.16), Virtual groups, Owner identity
- **Target:** Cargo
- **Spec refs:** 11.17 step 9 ("enriched_token = EnrichToken(token, sd.owner, self_sid)")

**Test 100**
- **Name:** `mandatory_policy_no_write_up_cleared_skips_mic`
- **Assertion:** Token has mandatory_policy without TOKEN_MANDATORY_POLICY_NO_WRITE_UP (cleared at creation by authd). MIC is effectively disabled for this token. Combined with PIP: PIP still enforces independently (PIP does not check mandatory_policy). A Low-integrity token with MIC disabled can write to High-integrity objects, but PIP can still block it.
- **Subsystems:** MIC (11.13), PIP (11.15), Token policy
- **Target:** Cargo
- **Spec refs:** 11.13 (token mandatory policy flag), 11.17 EnforceMIC (early return)

---

## Summary

100 compound interaction tests generated across 14 categories:

| Category | Count | Key Insight |
|----------|-------|-------------|
| MIC + PIP | 6 | Two independent mandatory checks, both extracted from SACL. MIC is default-on, PIP is opt-in. MIC does not constrain privileges, PIP does. |
| Restricted + Confinement | 6 | Three-pass evaluation. Privilege OR-back after restricted is nullified by confinement (ordering is load-bearing). |
| Restricted + MIC + Privilege | 5 | Privilege grants at step 3 survive MIC (step 4), but MIC sets mandatory_decided which blocks SeTakeOwnership at step 7a. |
| Confinement + CAP | 3 | CAP rule evaluation runs the full pipeline including confinement. Double confinement intersection. |
| Impersonation + MIC + PIP | 5 | MIC reads effective token (safe due to integrity ceiling). PIP reads PSB (no ceiling exists for PIP dimensions). |
| Conditional ACE + Restricted | 5 | Restricted pass uses restricted SID matcher but full token for conditions. SID match is the gate; condition is the secondary filter. |
| Owner Implicit + Confinement | 3 | Confinement pass skips owner implicit (skip_owner_implicit=true). Owner must have explicit confinement ACE. |
| MAXIMUM_ALLOWED + Restricted + Confinement | 4 | Full pipeline runs to completion, three-way intersection, zero-granted is valid success. |
| CAP + MIC | 3 | CAP rule inherits the object's SACL (including MIC label). MIC enforced inside each CAP evaluation. |
| Write-Restricted + Append | 3 | GENERIC_WRITE mapping determines which bits are write-category. FILE_APPEND_DATA is a write bit. |
| Inheritance + CREATOR OWNER + Confinement | 3 | CREATOR OWNER substitutes user SID, not confinement SID. Confined creator must have confinement ACE in default DACL. |
| PIP + Privilege Revocation + Restricted OR-back | 4 | PIP revokes from both granted AND privilege_granted at step 4. Restricted OR-back at step 8 uses the (now empty) privilege_granted. PIP wins. |
| Token Adjustment + Cached AccessCheck | 5 | All adjustments bump modified_id. Privilege removal is permanent. |
| Fork + Impersonation + Exec | 4 | Fork drops impersonation. Exec reverts impersonation. Primary token survives both. |
| Additional adversarial | 21 | Full-pipeline composition, edge cases (anonymous tokens, deny-only user SID, elevation, strict confinement, confinement_exempt, multiple SACL labels, conditional OWNER RIGHTS). |

All tests target Cargo (the `no_std` evaluation core) except for lifecycle/process tests (fork/exec/impersonation state transitions) which require Provium for kernel integration testing. Some tests (marked both) should have Cargo unit tests for the AccessCheck logic and Provium integration tests for the kernel-level enforcement.
