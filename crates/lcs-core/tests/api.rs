//! lcs-core integration tests: api.
//! Each submodule is one behavioural test file; shared helpers live in `common`.

mod common;

#[path = "api/abi_reserved_zero_primitive.rs"]
mod abi_reserved_zero_primitive;
#[path = "api/fd_lifecycle.rs"]
mod fd_lifecycle;
#[path = "api/ioctl_access_requirements.rs"]
mod ioctl_access_requirements;
#[path = "api/ioctl_access_source_contact_gate.rs"]
mod ioctl_access_source_contact_gate;
#[path = "api/ioctl_fd_access_errno.rs"]
mod ioctl_fd_access_errno;
#[path = "api/ioctl_output_copy_plans.rs"]
mod ioctl_output_copy_plans;
#[path = "api/memory_bounds.rs"]
mod memory_bounds;
#[path = "api/output_buffer_erange_plan.rs"]
mod output_buffer_erange_plan;
#[path = "api/syscall_path_c_string_validation.rs"]
mod syscall_path_c_string_validation;
