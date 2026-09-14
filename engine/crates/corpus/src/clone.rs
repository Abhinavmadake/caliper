// Copyright 2026 Abhinav Ajit Madake, Sahil Tatyabhau Waje,
// Ritesh Aresh Saindane, Yogesh Babaji Palve
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Clone and unshare flags (`corpus/README.md`, committed set). Both
//! probes here get their answer from flag validation, which runs before
//! any namespace is created, any capability is checked, or any LSM hook
//! fires; the per-flag probes of the committed family (#14) are the ones
//! that reach those.

use caliper_engine::{
    Applicability, Errno, Isolates, KernelDependency, Oracle, Probe, RawResult, SideEffects,
};

use crate::common::{result, ONE_CALL};

/// Bit 0 is not an unshare flag (`check_unshare_flags`), and `CLONE_NEWUSER`
/// alongside it is the flag a policy is most likely to match on.
const INVALID_UNSHARE: libc::c_int = libc::CLONE_NEWUSER | 0x1;

fn unshare_invalid() -> RawResult {
    // SAFETY: one integer argument.
    result(unsafe { libc::syscall(libc::SYS_unshare, INVALID_UNSHARE) })
}

fn clone3_short() -> RawResult {
    // SAFETY: a null pointer the kernel never reads, because a size of zero
    // is rejected before copy_from_user.
    result(unsafe { libc::syscall(libc::SYS_clone3, std::ptr::null::<libc::c_void>(), 0usize) })
}

pub const UNSHARE_INVALID_FLAGS: Probe = Probe {
    id: "unshare.flags.invalid",
    family: "clone",
    description: "unshare(CLONE_NEWUSER | 0x1): an invalid flag set, guaranteed EINVAL",
    risk: ONE_CALL,
    arch: Applicability::All,
    kernel: KernelDependency::NONE,
    oracle: Oracle {
        guarantees: Some(Errno::EINVAL),
        isolates: Isolates::Seccomp,
        reason: "ksys_unshare validates the flag set in check_unshare_flags before any \
                 namespace is created or capability checked; bit 0 is not an unshare \
                 flag, so EINVAL comes before create_user_ns and its LSM hook, and only a \
                 filter at syscall entry answers EPERM first",
    },
    // CLONE_NEWUSER needs no capability; the flags that do are the
    // committed family's.
    capability: None,
    effects: SideEffects::NONE,
    run: unshare_invalid,
};

/// `clone3` is where the ENOSYS-is-a-filter rule bites: Docker's default
/// profile answers it with ENOSYS on every kernel, and every supported
/// kernel implements it.
pub const CLONE3_SHORT_ARGS: Probe = Probe {
    id: "clone3.args.short",
    family: "clone",
    description: "clone3(NULL, 0): a size below CLONE_ARGS_SIZE_VER0, guaranteed EINVAL",
    risk: ONE_CALL,
    arch: Applicability::All,
    kernel: KernelDependency {
        since: Some((5, 3)),
        absent_errno: Some(Errno::ENOSYS),
    },
    oracle: Oracle {
        guarantees: Some(Errno::EINVAL),
        isolates: Isolates::Seccomp,
        reason: "copy_clone_args_from_user rejects a size below CLONE_ARGS_SIZE_VER0 with \
                 EINVAL before reading anything; nothing runs before it. ENOSYS from a \
                 kernel at or past 5.3 is a filter answering in the kernel's voice",
    },
    capability: None,
    effects: SideEffects::NONE,
    run: clone3_short,
};
