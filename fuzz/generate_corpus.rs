#!/usr/bin/env -S cargo +nightly -Zscript
//! Generate seed corpus files for fuzz targets.
//! Run from the fuzz directory: cargo +nightly -Zscript generate_corpus.rs

//! ```cargo
//! [dependencies]
//! kacs-core = { path = "../crates/kacs-core" }
//! ```

use kacs_core::ace::*;
use kacs_core::acl::{Acl, ACL_REVISION};
use kacs_core::guid::Guid;
use kacs_core::sid::Sid;
use kacs_core::sd::SecurityDescriptor;
use std::fs;

fn main() {
    generate_sid_corpus();
    generate_ace_corpus();
    generate_acl_corpus();
    generate_sd_corpus();
    generate_conditional_corpus();
    eprintln!("corpus generated");
}

fn write(dir: &str, name: &str, data: &[u8]) {
    let path = format!("corpus/{dir}/{name}");
    fs::write(&path, data).unwrap();
}

fn generate_sid_corpus() {
    // S-1-5-18 (SYSTEM)
    write("fuzz_sid", "system", &Sid::new(5, &[18]).unwrap().to_bytes().unwrap());
    // S-1-5-32-544 (Administrators)
    write("fuzz_sid", "admins", &Sid::new(5, &[32, 544]).unwrap().to_bytes().unwrap());
    // S-1-1-0 (Everyone)
    write("fuzz_sid", "everyone", &Sid::new(1, &[0]).unwrap().to_bytes().unwrap());
    // Domain user with 5 sub-authorities
    write("fuzz_sid", "domain_user", &Sid::new(5, &[21, 100, 200, 300, 1001]).unwrap().to_bytes().unwrap());
    // Max sub-authorities (15)
    let max_subs: Vec<u32> = (1..=15).collect();
    write("fuzz_sid", "max_subs", &Sid::new(5, &max_subs).unwrap().to_bytes().unwrap());
    // Zero sub-authorities
    write("fuzz_sid", "zero_subs", &Sid::new(5, &[]).unwrap().to_bytes().unwrap());
    // Integrity SID
    write("fuzz_sid", "integrity_medium", &Sid::new(16, &[8192]).unwrap().to_bytes().unwrap());
}

fn make_ace(ace_type: u8, mask: u32, sid: &Sid) -> Vec<u8> {
    let ace = Ace {
        ace_type, flags: 0, mask, sid: sid.clone(),
        object_type: None, inherited_object_type: None,
        condition: None, application_data: None,
    };
    ace.to_bytes().unwrap()
}

fn generate_ace_corpus() {
    let system = Sid::new(5, &[18]).unwrap();
    let everyone = Sid::new(1, &[0]).unwrap();

    write("fuzz_ace", "allow_basic", &make_ace(ACCESS_ALLOWED_ACE_TYPE, 0x1F01FF, &system));
    write("fuzz_ace", "deny_basic", &make_ace(ACCESS_DENIED_ACE_TYPE, 0x10000, &everyone));
    write("fuzz_ace", "audit", &make_ace(SYSTEM_AUDIT_ACE_TYPE, 0x1F01FF, &system));
    write("fuzz_ace", "label", &make_ace(SYSTEM_MANDATORY_LABEL_ACE_TYPE, 0x03, &Sid::new(16, &[8192]).unwrap()));

    // Object ACE with GUIDs
    let obj_ace = Ace {
        ace_type: ACCESS_ALLOWED_OBJECT_ACE_TYPE,
        flags: 0, mask: 0x100,
        sid: system.clone(),
        object_type: Some(Guid { data1: 0xDEADBEEF, data2: 0xCAFE, data3: 0xBABE, data4: [1,2,3,4,5,6,7,8] }),
        inherited_object_type: Some(Guid { data1: 0x12345678, data2: 0xABCD, data3: 0xEF01, data4: [8,7,6,5,4,3,2,1] }),
        condition: None, application_data: None,
    };
    write("fuzz_ace", "object_both_guids", &obj_ace.to_bytes().unwrap());
}

fn generate_acl_corpus() {
    let system = Sid::new(5, &[18]).unwrap();
    let everyone = Sid::new(1, &[0]).unwrap();

    // Empty ACL
    let empty = Acl::new(ACL_REVISION);
    write("fuzz_acl", "empty", &empty.to_bytes().unwrap());

    // Single allow ACE
    let single = Acl {
        revision: ACL_REVISION,
        aces: vec![Ace {
            ace_type: ACCESS_ALLOWED_ACE_TYPE, flags: 0, mask: 0x1F01FF,
            sid: system.clone(), object_type: None, inherited_object_type: None,
            condition: None, application_data: None,
        }],
    };
    write("fuzz_acl", "single_allow", &single.to_bytes().unwrap());

    // Mixed deny + allow
    let mixed = Acl {
        revision: ACL_REVISION,
        aces: vec![
            Ace {
                ace_type: ACCESS_DENIED_ACE_TYPE, flags: 0, mask: 0x10000,
                sid: everyone.clone(), object_type: None, inherited_object_type: None,
                condition: None, application_data: None,
            },
            Ace {
                ace_type: ACCESS_ALLOWED_ACE_TYPE, flags: 0, mask: 0x1F01FF,
                sid: system.clone(), object_type: None, inherited_object_type: None,
                condition: None, application_data: None,
            },
        ],
    };
    write("fuzz_acl", "deny_then_allow", &mixed.to_bytes().unwrap());
}

fn generate_sd_corpus() {
    let system = Sid::new(5, &[18]).unwrap();
    let admins = Sid::new(5, &[32, 544]).unwrap();
    let everyone = Sid::new(1, &[0]).unwrap();

    let dacl = Acl {
        revision: ACL_REVISION,
        aces: vec![Ace {
            ace_type: ACCESS_ALLOWED_ACE_TYPE, flags: 0, mask: 0x1F01FF,
            sid: everyone.clone(), object_type: None, inherited_object_type: None,
            condition: None, application_data: None,
        }],
    };

    // Basic SD
    let sd = SecurityDescriptor::new(system.clone(), admins.clone(), dacl.clone());
    write("fuzz_sd", "basic", &sd.to_bytes().unwrap());

    // SD with SACL
    let sacl = Acl {
        revision: ACL_REVISION,
        aces: vec![Ace {
            ace_type: SYSTEM_AUDIT_ACE_TYPE, flags: 0xC0, mask: 0x1F01FF,
            sid: everyone.clone(), object_type: None, inherited_object_type: None,
            condition: None, application_data: None,
        }],
    };
    let sd2 = SecurityDescriptor::with_sacl(system, admins, dacl, sacl);
    write("fuzz_sd", "with_sacl", &sd2.to_bytes().unwrap());
}

fn generate_conditional_corpus() {
    // artx header (0x61 0x72 0x74 0x78) + minimal expressions
    // Integer literal 42
    let mut expr = vec![0x61, 0x72, 0x74, 0x78]; // artx header
    expr.extend_from_slice(&[0x04, 42, 0, 0, 0, 0, 0, 0, 0, 0x00]); // int64 literal
    write("fuzz_conditional", "int_literal", &expr);

    // Empty expression (just header)
    write("fuzz_conditional", "empty", &[0x61, 0x72, 0x74, 0x78]);

    // Invalid header (should be rejected cleanly)
    write("fuzz_conditional", "bad_header", &[0x00, 0x00, 0x00, 0x00]);
}
