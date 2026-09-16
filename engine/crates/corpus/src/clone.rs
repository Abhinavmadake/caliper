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
    Applicability, Capability, Errno, Isolates, KernelDependency, Oracle, Probe, RawResult,
    ResidualClass, SideEffects,
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

fn unshare_flag(flags: libc::c_int) -> RawResult {
    // SAFETY: one integer argument.
    result(unsafe { libc::syscall(libc::SYS_unshare, flags) })
}

fn clone_flag(flags: libc::c_int) -> RawResult {
    // SAFETY: no stack (fork-like), null tids/tls; pointer-argument order
    // differs between x86_64 and aarch64 but every pointer is null.
    let pid = unsafe {
        libc::syscall(
            libc::SYS_clone,
            flags | libc::SIGCHLD,
            0usize,
            0usize,
            0usize,
            0usize,
        )
    };
    if pid == 0 {
        unsafe { libc::syscall(libc::SYS_exit_group, 0) };
        unreachable!()
    }
    if pid < 0 {
        return Err(Errno::last());
    }
    // SAFETY: reap our own child; no status wanted.
    unsafe { libc::syscall(libc::SYS_wait4, pid, 0usize, 0, 0usize) };
    Ok(())
}

fn unshare_newuser() -> RawResult {
    unshare_flag(libc::CLONE_NEWUSER)
}
fn unshare_newns() -> RawResult {
    unshare_flag(libc::CLONE_NEWNS)
}
fn unshare_newnet() -> RawResult {
    unshare_flag(libc::CLONE_NEWNET)
}
fn unshare_newpid() -> RawResult {
    unshare_flag(libc::CLONE_NEWPID)
}
fn unshare_newipc() -> RawResult {
    unshare_flag(libc::CLONE_NEWIPC)
}
fn unshare_newuts() -> RawResult {
    unshare_flag(libc::CLONE_NEWUTS)
}
fn unshare_newcgroup() -> RawResult {
    unshare_flag(libc::CLONE_NEWCGROUP)
}
fn unshare_newtime() -> RawResult {
    unshare_flag(libc::CLONE_NEWTIME)
}
fn unshare_newuser_newnet() -> RawResult {
    unshare_flag(libc::CLONE_NEWUSER | libc::CLONE_NEWNET)
}

fn clone_newuser() -> RawResult {
    clone_flag(libc::CLONE_NEWUSER)
}
fn clone_newns() -> RawResult {
    clone_flag(libc::CLONE_NEWNS)
}
fn clone_newnet() -> RawResult {
    clone_flag(libc::CLONE_NEWNET)
}
fn clone_newpid() -> RawResult {
    clone_flag(libc::CLONE_NEWPID)
}
fn clone_newipc() -> RawResult {
    clone_flag(libc::CLONE_NEWIPC)
}
fn clone_newuts() -> RawResult {
    clone_flag(libc::CLONE_NEWUTS)
}
fn clone_newcgroup() -> RawResult {
    clone_flag(libc::CLONE_NEWCGROUP)
}
fn clone_newtime() -> RawResult {
    clone_flag(libc::CLONE_NEWTIME)
}
fn clone_newuser_newnet() -> RawResult {
    clone_flag(libc::CLONE_NEWUSER | libc::CLONE_NEWNET)
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

pub const UNSHARE_FLAGS_NEWUSER: Probe = Probe {
    id: "unshare.flags.newuser",
    family: "clone",
    description: "unshare(CLONE_NEWUSER): user namespace creation without host privilege",
    risk: ONE_CALL,
    arch: Applicability::All,
    kernel: KernelDependency::NONE,
    oracle: Oracle {
        guarantees: None,
        isolates: Isolates::SeccompOrLsm,
        reason: "create_user_ns in ksys_unshare requires no capability; EPERM is seccomp filter \
                 or userns policy (e.g. Debian kernel.unprivileged_userns_clone or AppArmor \
                 security_create_user_ns hook answering EACCES/EPERM)",
    },
    capability: None,
    effects: SideEffects::NONE,
    run: unshare_newuser,
};

pub const UNSHARE_FLAGS_NEWNS: Probe = Probe {
    id: "unshare.flags.newns",
    family: "clone",
    description: "unshare(CLONE_NEWNS): mount namespace creation, CAP_SYS_ADMIN",
    risk: ONE_CALL,
    arch: Applicability::All,
    kernel: KernelDependency::NONE,
    oracle: Oracle {
        guarantees: None,
        isolates: Isolates::Undecidable,
        reason: "create_new_namespaces in ksys_unshare checks ns_capable(user_ns, CAP_SYS_ADMIN) \
                 and answers EPERM itself; nothing separates seccomp from a missing capability",
    },
    capability: Some(Capability::SysAdmin),
    effects: SideEffects::NONE,
    run: unshare_newns,
};

pub const UNSHARE_FLAGS_NEWNET: Probe = Probe {
    id: "unshare.flags.newnet",
    family: "clone",
    description: "unshare(CLONE_NEWNET): network namespace creation, CAP_SYS_ADMIN",
    risk: ONE_CALL,
    arch: Applicability::All,
    kernel: KernelDependency::NONE,
    oracle: Oracle {
        guarantees: None,
        isolates: Isolates::Undecidable,
        reason: "create_new_namespaces in ksys_unshare checks ns_capable(user_ns, CAP_SYS_ADMIN) \
                 and answers EPERM itself; nothing separates seccomp from a missing capability",
    },
    capability: Some(Capability::SysAdmin),
    effects: SideEffects::Declared {
        residual: &[ResidualClass::NetNamespaces],
        module_autoload: false,
    },
    run: unshare_newnet,
};

pub const UNSHARE_FLAGS_NEWPID: Probe = Probe {
    id: "unshare.flags.newpid",
    family: "clone",
    description: "unshare(CLONE_NEWPID): PID namespace creation, CAP_SYS_ADMIN",
    risk: ONE_CALL,
    arch: Applicability::All,
    kernel: KernelDependency::NONE,
    oracle: Oracle {
        guarantees: None,
        isolates: Isolates::Undecidable,
        reason: "create_new_namespaces in ksys_unshare checks ns_capable(user_ns, CAP_SYS_ADMIN) \
                 and answers EPERM itself; nothing separates seccomp from a missing capability",
    },
    capability: Some(Capability::SysAdmin),
    effects: SideEffects::NONE,
    run: unshare_newpid,
};

pub const UNSHARE_FLAGS_NEWIPC: Probe = Probe {
    id: "unshare.flags.newipc",
    family: "clone",
    description: "unshare(CLONE_NEWIPC): IPC namespace creation, CAP_SYS_ADMIN",
    risk: ONE_CALL,
    arch: Applicability::All,
    kernel: KernelDependency::NONE,
    oracle: Oracle {
        guarantees: None,
        isolates: Isolates::Undecidable,
        reason: "create_new_namespaces in ksys_unshare checks ns_capable(user_ns, CAP_SYS_ADMIN) \
                 and answers EPERM itself; nothing separates seccomp from a missing capability",
    },
    capability: Some(Capability::SysAdmin),
    effects: SideEffects::NONE,
    run: unshare_newipc,
};

pub const UNSHARE_FLAGS_NEWUTS: Probe = Probe {
    id: "unshare.flags.newuts",
    family: "clone",
    description: "unshare(CLONE_NEWUTS): UTS namespace creation, CAP_SYS_ADMIN",
    risk: ONE_CALL,
    arch: Applicability::All,
    kernel: KernelDependency::NONE,
    oracle: Oracle {
        guarantees: None,
        isolates: Isolates::Undecidable,
        reason: "create_new_namespaces in ksys_unshare checks ns_capable(user_ns, CAP_SYS_ADMIN) \
                 and answers EPERM itself; nothing separates seccomp from a missing capability",
    },
    capability: Some(Capability::SysAdmin),
    effects: SideEffects::NONE,
    run: unshare_newuts,
};

pub const UNSHARE_FLAGS_NEWCGROUP: Probe = Probe {
    id: "unshare.flags.newcgroup",
    family: "clone",
    description: "unshare(CLONE_NEWCGROUP): cgroup namespace creation, CAP_SYS_ADMIN",
    risk: ONE_CALL,
    arch: Applicability::All,
    kernel: KernelDependency::NONE,
    oracle: Oracle {
        guarantees: None,
        isolates: Isolates::Undecidable,
        reason: "create_new_namespaces in ksys_unshare checks ns_capable(user_ns, CAP_SYS_ADMIN) \
                 and answers EPERM itself; nothing separates seccomp from a missing capability",
    },
    capability: Some(Capability::SysAdmin),
    effects: SideEffects::NONE,
    run: unshare_newcgroup,
};

pub const UNSHARE_FLAGS_NEWTIME: Probe = Probe {
    id: "unshare.flags.newtime",
    family: "clone",
    description: "unshare(CLONE_NEWTIME): time namespace creation, CAP_SYS_ADMIN",
    risk: ONE_CALL,
    arch: Applicability::All,
    kernel: KernelDependency::NONE,
    oracle: Oracle {
        guarantees: None,
        isolates: Isolates::Undecidable,
        reason: "create_new_namespaces in ksys_unshare checks ns_capable(user_ns, CAP_SYS_ADMIN) \
                 and answers EPERM itself; nothing separates seccomp from a missing capability",
    },
    capability: Some(Capability::SysAdmin),
    effects: SideEffects::NONE,
    run: unshare_newtime,
};

pub const UNSHARE_FLAGS_NEWUSER_NEWNET: Probe = Probe {
    id: "unshare.flags.newuser_newnet",
    family: "clone",
    description: "unshare(CLONE_NEWUSER | CLONE_NEWNET): user+net namespace creation escalation path",
    risk: ONE_CALL,
    arch: Applicability::All,
    kernel: KernelDependency::NONE,
    oracle: Oracle {
        guarantees: None,
        isolates: Isolates::SeccompOrLsm,
        reason: "CLONE_NEWUSER creates a user namespace first in ksys_unshare, granting \
                 CAP_SYS_ADMIN inside it so create_new_namespaces succeeds without host privileges; \
                 EPERM is seccomp or userns policy",
    },
    capability: None,
    effects: SideEffects::Declared {
        residual: &[ResidualClass::NetNamespaces],
        module_autoload: false,
    },
    run: unshare_newuser_newnet,
};

pub const CLONE_FLAGS_NEWUSER: Probe = Probe {
    id: "clone.flags.newuser",
    family: "clone",
    description: "clone(CLONE_NEWUSER | SIGCHLD): process creation in a new user namespace",
    risk: ONE_CALL,
    arch: Applicability::All,
    kernel: KernelDependency::NONE,
    oracle: Oracle {
        guarantees: None,
        isolates: Isolates::SeccompOrLsm,
        reason: "create_user_ns in copy_process requires no capability; EPERM is seccomp filter \
                 or userns policy",
    },
    capability: None,
    effects: SideEffects::NONE,
    run: clone_newuser,
};

pub const CLONE_FLAGS_NEWNS: Probe = Probe {
    id: "clone.flags.newns",
    family: "clone",
    description:
        "clone(CLONE_NEWNS | SIGCHLD): process creation in a new mount namespace, CAP_SYS_ADMIN",
    risk: ONE_CALL,
    arch: Applicability::All,
    kernel: KernelDependency::NONE,
    oracle: Oracle {
        guarantees: None,
        isolates: Isolates::Undecidable,
        reason: "copy_namespaces in copy_process checks ns_capable(user_ns, CAP_SYS_ADMIN) and \
                 answers EPERM itself; nothing separates seccomp from a missing capability",
    },
    capability: Some(Capability::SysAdmin),
    effects: SideEffects::NONE,
    run: clone_newns,
};

pub const CLONE_FLAGS_NEWNET: Probe = Probe {
    id: "clone.flags.newnet",
    family: "clone",
    description:
        "clone(CLONE_NEWNET | SIGCHLD): process creation in a new net namespace, CAP_SYS_ADMIN",
    risk: ONE_CALL,
    arch: Applicability::All,
    kernel: KernelDependency::NONE,
    oracle: Oracle {
        guarantees: None,
        isolates: Isolates::Undecidable,
        reason: "copy_namespaces in copy_process checks ns_capable(user_ns, CAP_SYS_ADMIN) and \
                 answers EPERM itself; nothing separates seccomp from a missing capability",
    },
    capability: Some(Capability::SysAdmin),
    effects: SideEffects::Declared {
        residual: &[ResidualClass::NetNamespaces],
        module_autoload: false,
    },
    run: clone_newnet,
};

pub const CLONE_FLAGS_NEWPID: Probe = Probe {
    id: "clone.flags.newpid",
    family: "clone",
    description:
        "clone(CLONE_NEWPID | SIGCHLD): process creation in a new PID namespace, CAP_SYS_ADMIN",
    risk: ONE_CALL,
    arch: Applicability::All,
    kernel: KernelDependency::NONE,
    oracle: Oracle {
        guarantees: None,
        isolates: Isolates::Undecidable,
        reason: "copy_namespaces in copy_process checks ns_capable(user_ns, CAP_SYS_ADMIN) and \
                 answers EPERM itself; nothing separates seccomp from a missing capability",
    },
    capability: Some(Capability::SysAdmin),
    effects: SideEffects::NONE,
    run: clone_newpid,
};

pub const CLONE_FLAGS_NEWIPC: Probe = Probe {
    id: "clone.flags.newipc",
    family: "clone",
    description:
        "clone(CLONE_NEWIPC | SIGCHLD): process creation in a new IPC namespace, CAP_SYS_ADMIN",
    risk: ONE_CALL,
    arch: Applicability::All,
    kernel: KernelDependency::NONE,
    oracle: Oracle {
        guarantees: None,
        isolates: Isolates::Undecidable,
        reason: "copy_namespaces in copy_process checks ns_capable(user_ns, CAP_SYS_ADMIN) and \
                 answers EPERM itself; nothing separates seccomp from a missing capability",
    },
    capability: Some(Capability::SysAdmin),
    effects: SideEffects::NONE,
    run: clone_newipc,
};

pub const CLONE_FLAGS_NEWUTS: Probe = Probe {
    id: "clone.flags.newuts",
    family: "clone",
    description:
        "clone(CLONE_NEWUTS | SIGCHLD): process creation in a new UTS namespace, CAP_SYS_ADMIN",
    risk: ONE_CALL,
    arch: Applicability::All,
    kernel: KernelDependency::NONE,
    oracle: Oracle {
        guarantees: None,
        isolates: Isolates::Undecidable,
        reason: "copy_namespaces in copy_process checks ns_capable(user_ns, CAP_SYS_ADMIN) and \
                 answers EPERM itself; nothing separates seccomp from a missing capability",
    },
    capability: Some(Capability::SysAdmin),
    effects: SideEffects::NONE,
    run: clone_newuts,
};

pub const CLONE_FLAGS_NEWCGROUP: Probe = Probe {
    id: "clone.flags.newcgroup",
    family: "clone",
    description: "clone(CLONE_NEWCGROUP | SIGCHLD): process creation in a new cgroup namespace, CAP_SYS_ADMIN",
    risk: ONE_CALL,
    arch: Applicability::All,
    kernel: KernelDependency::NONE,
    oracle: Oracle {
        guarantees: None,
        isolates: Isolates::Undecidable,
        reason: "copy_namespaces in copy_process checks ns_capable(user_ns, CAP_SYS_ADMIN) and \
                 answers EPERM itself; nothing separates seccomp from a missing capability",
    },
    capability: Some(Capability::SysAdmin),
    effects: SideEffects::NONE,
    run: clone_newcgroup,
};

pub const CLONE_FLAGS_NEWTIME: Probe = Probe {
    id: "clone.flags.newtime",
    family: "clone",
    description:
        "clone(CLONE_NEWTIME | SIGCHLD): process creation in a new time namespace, CAP_SYS_ADMIN",
    risk: ONE_CALL,
    arch: Applicability::All,
    kernel: KernelDependency::NONE,
    oracle: Oracle {
        guarantees: None,
        isolates: Isolates::Undecidable,
        reason: "copy_namespaces in copy_process checks ns_capable(user_ns, CAP_SYS_ADMIN) and \
                 answers EPERM itself; nothing separates seccomp from a missing capability",
    },
    capability: Some(Capability::SysAdmin),
    effects: SideEffects::NONE,
    run: clone_newtime,
};

pub const CLONE_FLAGS_NEWUSER_NEWNET: Probe = Probe {
    id: "clone.flags.newuser_newnet",
    family: "clone",
    description: "clone(CLONE_NEWUSER | CLONE_NEWNET | SIGCHLD): user+net namespace process creation escalation path",
    risk: ONE_CALL,
    arch: Applicability::All,
    kernel: KernelDependency::NONE,
    oracle: Oracle {
        guarantees: None,
        isolates: Isolates::SeccompOrLsm,
        reason: "CLONE_NEWUSER creates a user namespace first in copy_process, granting \
                 CAP_SYS_ADMIN inside it so copy_namespaces succeeds without host privileges; \
                 EPERM is seccomp or userns policy",
    },
    capability: None,
    effects: SideEffects::Declared {
        residual: &[ResidualClass::NetNamespaces],
        module_autoload: false,
    },
    run: clone_newuser_newnet,
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
