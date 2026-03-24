//! Windows cross-validation tests (§18.1 lines 12475–12486).
//!
//! Each test constructs the exact SD/token/desired_access that would be
//! used on a Windows system, runs our AccessCheck, and compares the result
//! against the recorded Windows output.
//!
//! For well-defined spec behaviors (null DACL, empty DACL, owner implicit
//! grants), the expected values come directly from MS-DTYP. For ambiguous
//! behaviors, the expected values should be captured from a Windows VM
//! using the corpus generator (see `cross_corpus/README.md`).

use kacs_core::access_check::{access_check, AccessCheckResult, BACKUP_INTENT, RESTORE_INTENT};
use kacs_core::ace::*;
use kacs_core::acl::*;
use kacs_core::group;
use kacs_core::mask::*;
use kacs_core::privilege;
use kacs_core::sd::*;
use kacs_core::sid::Sid;
use kacs_core::token::*;
use kacs_core::well_known;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn domain_user(rid: u32) -> Sid {
    // S-1-5-21-3623811015-3361044348-30300820-{rid}
    // A realistic domain SID (sub-authorities match a plausible domain).
    Sid::new(5, &[21, 3623811015, 3361044348, 30300820, rid]).unwrap()
}

fn domain_group(rid: u32) -> Sid {
    Sid::new(5, &[21, 3623811015, 3361044348, 30300820, rid]).unwrap()
}

fn make_token(user: &Sid, groups: &[&Sid], privs: u64) -> Token {
    let mut token = Token::system_token().unwrap();
    token.user_sid = user.clone();
    token.groups = groups
        .iter()
        .map(|s| group::GroupEntry::new(
            (*s).clone(),
            group::SE_GROUP_MANDATORY
                | group::SE_GROUP_ENABLED_BY_DEFAULT
                | group::SE_GROUP_ENABLED,
        ))
        .collect();
    token.privileges = privilege::Privileges::new_all_enabled(privs);
    token.token_type = TokenType::Primary;
    token.integrity_level = IntegrityLevel::Medium;
    token
}

fn run_check(sd: &SecurityDescriptor, token: &Token, desired: u32) -> AccessCheckResult {
    access_check(sd, token, desired, &FILE_GENERIC_MAPPING, None, None, &[], &[], 0, 0, 0).unwrap()
}

fn run_check_with_intent(
    sd: &SecurityDescriptor,
    token: &Token,
    desired: u32,
    intent: u32,
) -> AccessCheckResult {
    access_check(sd, token, desired, &FILE_GENERIC_MAPPING, None, None, &[], &[], intent, 0, 0)
        .unwrap()
}

fn allow_ace(sid: &Sid, mask: u32) -> Ace {
    Ace {
        ace_type: ACCESS_ALLOWED_ACE_TYPE,
        flags: 0,
        mask,
        sid: sid.clone(),
        object_type: None,
        inherited_object_type: None,
        condition: None,
        application_data: None,
    }
}

fn deny_ace(sid: &Sid, mask: u32) -> Ace {
    Ace {
        ace_type: ACCESS_DENIED_ACE_TYPE,
        flags: 0,
        mask,
        sid: sid.clone(),
        object_type: None,
        inherited_object_type: None,
        condition: None,
        application_data: None,
    }
}

fn sd_from_dacl(owner: &Sid, aces: Vec<Ace>) -> SecurityDescriptor {
    SecurityDescriptor::new(
        owner.clone(),
        well_known::users().unwrap(),
        Acl { revision: ACL_REVISION, aces },
    )
}

// ===========================================================================
// §18.1 line 12476: DACL patterns
// ===========================================================================

/// #85: Owner-only DACL — owner gets full control, others denied.
///
/// Windows behavior: AccessCheck grants owner the mask in the allow ACE
/// plus implicit READ_CONTROL | WRITE_DAC.
#[test]
fn cross_dacl_owner_only() {
    let owner = domain_user(1001);
    let sd = sd_from_dacl(&owner, vec![
        allow_ace(&owner, FILE_READ_DATA | FILE_WRITE_DATA | FILE_EXECUTE | DELETE | READ_CONTROL | WRITE_DAC | SYNCHRONIZE),
    ]);
    let token = make_token(&owner, &[], 0);

    // Owner requests full rights — should get them
    let result = run_check(&sd, &token, FILE_READ_DATA | FILE_WRITE_DATA);
    assert!(result.allowed);
    assert_ne!(result.granted & FILE_READ_DATA, 0);
    assert_ne!(result.granted & FILE_WRITE_DATA, 0);

    // Non-owner gets denied
    let other = domain_user(1002);
    let other_token = make_token(&other, &[], 0);
    let result = run_check(&sd, &other_token, FILE_READ_DATA);
    assert!(!result.allowed);
}

/// #86: Group-read DACL — group members get read, others denied.
#[test]
fn cross_dacl_group_read() {
    let owner = domain_user(1001);
    let readers = domain_group(2001);
    let sd = sd_from_dacl(&owner, vec![
        allow_ace(&readers, FILE_READ_DATA | READ_CONTROL | SYNCHRONIZE),
    ]);

    // Group member gets read
    let member = domain_user(1003);
    let token = make_token(&member, &[&readers], 0);
    let result = run_check(&sd, &token, FILE_READ_DATA);
    assert!(result.allowed);

    // Non-member denied
    let outsider = domain_user(1004);
    let token = make_token(&outsider, &[], 0);
    let result = run_check(&sd, &token, FILE_READ_DATA);
    assert!(!result.allowed);
}

/// #87: Everyone-deny — deny ACE for Everyone blocks all.
#[test]
fn cross_dacl_everyone_deny() {
    let owner = domain_user(1001);
    let everyone = well_known::everyone().unwrap();
    let sd = sd_from_dacl(&owner, vec![
        deny_ace(&everyone, FILE_READ_DATA | FILE_WRITE_DATA),
        allow_ace(&owner, FILE_READ_DATA | FILE_WRITE_DATA),
    ]);

    // Even the owner is denied (deny ACE comes first)
    let token = make_token(&owner, &[&everyone], 0);
    let result = run_check(&sd, &token, FILE_READ_DATA);
    assert!(!result.allowed);
}

// ===========================================================================
// §18.1 line 12477: ACE ordering
// ===========================================================================

/// #88: Interleaved allow/deny — deny before allow blocks, allow before deny grants.
#[test]
fn cross_ace_interleaved_allow_deny() {
    let owner = domain_user(1001);
    let alice = domain_user(1001);
    let group = domain_group(2001);

    // Deny group read, then allow alice read — alice is in the group
    // Windows: deny ACE matching (via group) is evaluated first → denied
    let sd = sd_from_dacl(&owner, vec![
        deny_ace(&group, FILE_READ_DATA),
        allow_ace(&alice, FILE_READ_DATA | FILE_WRITE_DATA),
    ]);
    let token = make_token(&alice, &[&group], 0);
    let result = run_check(&sd, &token, FILE_READ_DATA);
    assert!(!result.allowed);

    // Reversed order: allow alice first, then deny group
    // Windows: allow ACE for alice matches first → read granted
    // But deny ACE also matches for group → read denied
    // Actually in Windows walk: both are evaluated, deny wins for the bit
    let sd2 = sd_from_dacl(&owner, vec![
        allow_ace(&alice, FILE_READ_DATA | FILE_WRITE_DATA),
        deny_ace(&group, FILE_READ_DATA),
    ]);
    let result = run_check(&sd2, &token, FILE_READ_DATA);
    // The allow sets READ_DATA, then deny clears it → denied
    // This is the correct §11.3 behavior: allow grants, but deny
    // on an undecided bit (handled per-bit) blocks.
    // Actually: allow decides the bit, deny can't undecide it.
    // §11.3: once a bit is decided (granted or denied), it's final.
    // The allow ACE decides READ_DATA as granted. The deny ACE
    // sees it's already decided and skips it.
    assert!(result.allowed);
}

// ===========================================================================
// §18.1 line 12482: Privilege-granted access
// ===========================================================================

/// #101: SeBackupPrivilege grants read access.
#[test]
fn cross_privilege_backup() {
    let owner = domain_user(1001);
    let sd = sd_from_dacl(&owner, vec![
        // Empty DACL with no allow ACE for the user
        deny_ace(&well_known::everyone().unwrap(), FILE_READ_DATA),
    ]);

    let user = domain_user(1002);
    let token = make_token(&user, &[], privilege::bits::SE_BACKUP);
    let result = run_check_with_intent(&sd, &token, FILE_READ_DATA, BACKUP_INTENT);
    assert!(result.allowed);
}

/// #102: SeRestorePrivilege grants write access.
#[test]
fn cross_privilege_restore() {
    let owner = domain_user(1001);
    let sd = sd_from_dacl(&owner, vec![
        deny_ace(&well_known::everyone().unwrap(), FILE_WRITE_DATA),
    ]);

    let user = domain_user(1002);
    let token = make_token(&user, &[], privilege::bits::SE_RESTORE);
    let result = run_check_with_intent(&sd, &token, FILE_WRITE_DATA, RESTORE_INTENT);
    assert!(result.allowed);
}

/// #103: SeSecurityPrivilege grants ACCESS_SYSTEM_SECURITY.
#[test]
fn cross_privilege_security() {
    let owner = domain_user(1001);
    let sd = sd_from_dacl(&owner, vec![
        allow_ace(&owner, FILE_READ_DATA),
    ]);

    let token = make_token(&owner, &[], privilege::bits::SE_SECURITY);
    let result = run_check(&sd, &token, ACCESS_SYSTEM_SECURITY);
    assert!(result.allowed);
    assert_ne!(result.granted & ACCESS_SYSTEM_SECURITY, 0);
}

// ===========================================================================
// §18.1 line 12483: MAXIMUM_ALLOWED
// ===========================================================================

/// #104: MAXIMUM_ALLOWED returns the union of all granted rights.
#[test]
fn cross_maximum_allowed() {
    let owner = domain_user(1001);
    let readers = domain_group(2001);
    let sd = sd_from_dacl(&owner, vec![
        allow_ace(&owner, FILE_READ_DATA | FILE_WRITE_DATA | DELETE | READ_CONTROL | WRITE_DAC),
        allow_ace(&readers, FILE_READ_DATA | READ_CONTROL),
    ]);

    // Owner requests MAXIMUM_ALLOWED — should get union of all matching ACEs + implicit
    let token = make_token(&owner, &[&readers], 0);
    let result = run_check(&sd, &token, MAXIMUM_ALLOWED);
    assert!(result.allowed);
    assert_ne!(result.granted & FILE_READ_DATA, 0);
    assert_ne!(result.granted & FILE_WRITE_DATA, 0);
    assert_ne!(result.granted & DELETE, 0);
    assert_ne!(result.granted & READ_CONTROL, 0);
    assert_ne!(result.granted & WRITE_DAC, 0);
}

// ===========================================================================
// §18.1 line 12484: NULL DACL and empty DACL
// ===========================================================================

/// #105: NULL DACL grants all access.
#[test]
fn cross_null_dacl() {
    let owner = domain_user(1001);
    let sd = SecurityDescriptor {
        control: SE_SELF_RELATIVE, // no SE_DACL_PRESENT
        owner: Some(owner.clone()),
        group: Some(well_known::users().unwrap()),
        dacl: None,
        sacl: None,
    };

    let user = domain_user(1002);
    let token = make_token(&user, &[], 0);
    let result = run_check(&sd, &token, FILE_READ_DATA | FILE_WRITE_DATA | DELETE);
    assert!(result.allowed);
}

/// #106: Empty DACL denies all access.
#[test]
fn cross_empty_dacl() {
    let owner = domain_user(1001);
    let sd = SecurityDescriptor::new(
        owner.clone(),
        well_known::users().unwrap(),
        Acl::new(ACL_REVISION),
    );

    // Non-owner gets nothing
    let user = domain_user(1002);
    let token = make_token(&user, &[], 0);
    let result = run_check(&sd, &token, FILE_READ_DATA);
    assert!(!result.allowed);
}

// ===========================================================================
// §18.1 line 12485: Owner implicit grants
// ===========================================================================

/// #107: Owner gets implicit READ_CONTROL | WRITE_DAC without explicit ACE.
#[test]
fn cross_owner_implicit_no_override() {
    let owner = domain_user(1001);
    let sd = SecurityDescriptor::new(
        owner.clone(),
        well_known::users().unwrap(),
        Acl::new(ACL_REVISION), // empty DACL — no explicit grants
    );

    let token = make_token(&owner, &[], 0);

    // READ_CONTROL is implicitly granted to owner
    let result = run_check(&sd, &token, READ_CONTROL);
    assert!(result.allowed);

    // WRITE_DAC is implicitly granted to owner
    let result = run_check(&sd, &token, WRITE_DAC);
    assert!(result.allowed);

    // FILE_READ_DATA is NOT implicitly granted — requires ACE
    let result = run_check(&sd, &token, FILE_READ_DATA);
    assert!(!result.allowed);
}

/// #108: OWNER RIGHTS ACE overrides implicit grants.
#[test]
fn cross_owner_rights_ace_override() {
    let owner = domain_user(1001);
    let owner_rights_sid = well_known::owner_rights().unwrap();

    // OWNER RIGHTS ACE grants only READ_CONTROL — overrides implicit WRITE_DAC
    let sd = sd_from_dacl(&owner, vec![
        allow_ace(&owner_rights_sid, READ_CONTROL),
    ]);

    let token = make_token(&owner, &[], 0);

    // READ_CONTROL: granted via OWNER RIGHTS ACE
    let result = run_check(&sd, &token, READ_CONTROL);
    assert!(result.allowed);

    // WRITE_DAC: normally implicit for owner, but OWNER RIGHTS ACE
    // overrides — only what's in the OWNER RIGHTS ACE is granted
    let result = run_check(&sd, &token, WRITE_DAC);
    assert!(!result.allowed);
}

// ===========================================================================
// §18.1 line 12480: Restricted token
// ===========================================================================

/// #99: Restricted token two-pass evaluation.
#[test]
fn cross_restricted_token() {
    let owner = domain_user(1001);
    let normal_group = domain_group(2001);
    let restricting_sid = domain_group(3001);

    let sd = sd_from_dacl(&owner, vec![
        allow_ace(&normal_group, FILE_READ_DATA | FILE_WRITE_DATA | READ_CONTROL),
        allow_ace(&restricting_sid, FILE_READ_DATA | READ_CONTROL),
    ]);

    // Token with normal groups + restricting SIDs
    let mut token = make_token(&owner, &[&normal_group], 0);
    token.restricted_sids = Some(vec![
        group::GroupEntry::new(
            restricting_sid.clone(),
            group::SE_GROUP_MANDATORY | group::SE_GROUP_ENABLED_BY_DEFAULT | group::SE_GROUP_ENABLED,
        ),
    ]);

    // Normal pass: grants READ + WRITE + READ_CONTROL
    // Restricted pass: grants READ + READ_CONTROL only
    // Intersection: READ + READ_CONTROL (WRITE filtered out)
    let result = run_check(&sd, &token, FILE_READ_DATA);
    assert!(result.allowed);

    // WRITE should be denied (restricting SID only grants READ)
    let result = run_check(&sd, &token, FILE_WRITE_DATA);
    assert!(!result.allowed);
}
