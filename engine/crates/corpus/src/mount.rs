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

//! Mount filesystem types (`corpus/README.md`, committed set). One probe
//! here: whether `mount(2)` is reachable at all, with an answer produced
//! before the capability check and the LSM hook. The per-type probes of
//! the committed family (#13) need a real target and carry a mount-table
//! side effect; this one, by construction, cannot mount anything.

use caliper_engine::{
    Applicability, Capability, Errno, Isolates, KernelDependency, Oracle, Probe, RawResult,
    ResidualClass, SideEffects,
};

use crate::common::{result, ONE_CALL};

/// A target that does not exist. `do_mount` resolves it with `user_path_at`
/// before `path_mount` reaches `may_mount` or `security_sb_mount`.
const TARGET: &std::ffi::CStr = c"/caliper-no-such-dir";
const FSTYPE: &std::ffi::CStr = c"proc";

fn reach() -> RawResult {
    // SAFETY: two NUL-terminated string constants, a null source and null
    // data, both of which mount(2) accepts.
    let r = unsafe {
        libc::syscall(
            libc::SYS_mount,
            std::ptr::null::<libc::c_char>(),
            TARGET.as_ptr(),
            FSTYPE.as_ptr(),
            0 as libc::c_ulong,
            std::ptr::null::<libc::c_void>(),
        )
    };
    if r == 0 {
        // The target existed and the cell let the mount through. The child
        // owns it: unmount before returning, and let the residual snapshot
        // say whether that worked.
        // SAFETY: the same constant path.
        unsafe { libc::syscall(libc::SYS_umount2, TARGET.as_ptr(), 0 as libc::c_int) };
    }
    result(r)
}

pub const REACH: Probe = Probe {
    id: "mount.reach",
    family: "mount",
    description: "mount(NULL, \"/caliper-no-such-dir\", \"proc\", 0, NULL): guaranteed ENOENT",
    risk: ONE_CALL,
    arch: Applicability::All,
    kernel: KernelDependency::NONE,
    oracle: Oracle {
        guarantees: Some(Errno::ENOENT),
        isolates: Isolates::Seccomp,
        reason: "do_mount resolves the target path before path_mount calls may_mount \
                 (CAP_SYS_ADMIN, EPERM) and security_sb_mount; a target that does not exist \
                 is ENOENT before either, so only a filter at syscall entry answers EPERM \
                 first",
    },
    capability: Some(Capability::SysAdmin),
    effects: SideEffects::Declared {
        // Only if the target exists on this cell and the mount is permitted;
        // the child unmounts it, and the snapshot checks.
        residual: &[ResidualClass::Mounts],
        module_autoload: false,
    },
    run: reach,
};
