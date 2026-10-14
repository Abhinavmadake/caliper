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

//! The deferred set (#20): the nine families §9.2 leaves for later,
//! specified in the frozen probe format and marked `Status::Deferred`. The
//! engine records each as unmeasured without forking (#19), so their absence
//! is on every fingerprint rather than discovered later.
//!
//! Promoting a probe is an implementation plus `Status::Committed`
//! (`spec/probe.md`, the committed/deferred split); nothing here is
//! respecified. The description is the exact argument set the
//! implementation must issue, and the oracle is the argument for it.

use caliper_engine::{
    Applicability, Capability, Errno, Isolates, KernelDependency, Oracle, Probe, RawResult,
    SideEffects, Status,
};

use crate::common::ONE_CALL;

/// Never run: `measure` returns `Unmeasurable::Deferred` before the fork.
fn deferred() -> RawResult {
    Err(Errno::ENOSYS)
}

/// The syscall is compiled out when its config option is off (`CONFIG_BPF_SYSCALL`,
/// `CONFIG_KEYS`, `CONFIG_PERF_EVENTS`, `CONFIG_USERFAULTFD`, `CONFIG_FHANDLE`,
/// `CONFIG_MODULES`, `CONFIG_SECCOMP`): `ENOSYS` is absence.
const CONFIG_GATED: KernelDependency = KernelDependency {
    since: None,
    absent_errno: Some(Errno::ENOSYS),
    module: None,
    ..KernelDependency::NONE
};

const fn probe(
    id: &'static str,
    family: &'static str,
    description: &'static str,
    kernel: KernelDependency,
    oracle: Oracle,
    capability: Option<Capability>,
) -> Probe {
    Probe {
        id,
        family,
        status: Status::Deferred,
        description,
        risk: ONE_CALL,
        arch: Applicability::All,
        kernel,
        oracle,
        capability,
        effects: SideEffects::NONE,
        run: deferred,
    }
}

// ioctl request codes. A bad descriptor answers EBADF before the request
// code is looked at, so each probe measures whether a filter matches on the
// code itself.

pub const IOCTL_FIOCLEX: Probe = probe(
    "ioctl.request.fioclex",
    "ioctl",
    "ioctl(-1, FIOCLEX, 0): the request every workload issues",
    KernelDependency::NONE,
    Oracle {
        guarantees: Some(Errno::EBADF),
        isolates: Isolates::Seccomp,
        reason: "SYSCALL_DEFINE3(ioctl) resolves the descriptor with fdget before security_file_ioctl, so EBADF comes before any LSM hook; only a filter at entry answers EPERM first",
    },
    None,
);

pub const IOCTL_TIOCSTI: Probe = probe(
    "ioctl.request.tiocsti",
    "ioctl",
    "ioctl(-1, TIOCSTI, NULL): terminal input injection",
    KernelDependency::NONE,
    Oracle {
        guarantees: Some(Errno::EBADF),
        isolates: Isolates::Seccomp,
        reason: "fdget fails before security_file_ioctl and before tiocsti checks CAP_SYS_ADMIN (dev.tty.legacy_tiocsti=0, 6.2+), so EPERM can only be a filter matching the request code",
    },
    Some(Capability::SysAdmin),
);

pub const IOCTL_TIOCLINUX: Probe = probe(
    "ioctl.request.tioclinux",
    "ioctl",
    "ioctl(-1, TIOCLINUX, NULL): virtual console control",
    KernelDependency::NONE,
    Oracle {
        guarantees: Some(Errno::EBADF),
        isolates: Isolates::Seccomp,
        reason: "fdget fails before security_file_ioctl and before tioclinux reaches its per-subcode CAP_SYS_ADMIN checks, so EPERM can only be a filter matching the request code",
    },
    Some(Capability::SysAdmin),
);

// bpf commands and program types. The command is a register; the program
// type sits behind the attr pointer, where no filter can see it, so the
// type probes measure the kernel's own gate.

pub const BPF_MAP_CREATE: Probe = probe(
    "bpf.cmd.map_create",
    "bpf",
    "bpf(BPF_MAP_CREATE, attr, sizeof(union bpf_attr) + 8) with a non-zero byte past the union",
    CONFIG_GATED,
    Oracle {
        guarantees: Some(Errno::E2BIG),
        isolates: Isolates::Undecidable,
        reason: "__sys_bpf runs bpf_check_uarg_tail_zero before security_bpf, so E2BIG precedes every LSM hook; before 6.3, __sys_bpf also refused BPF_MAP_CREATE with EPERM under kernel.unprivileged_bpf_disabled ahead of that check, which a filter cannot be separated from",
    },
    Some(Capability::Bpf),
);

pub const BPF_PROG_LOAD: Probe = probe(
    "bpf.cmd.prog_load",
    "bpf",
    "bpf(BPF_PROG_LOAD, attr, sizeof(union bpf_attr) + 8) with a non-zero byte past the union",
    CONFIG_GATED,
    Oracle {
        guarantees: Some(Errno::E2BIG),
        isolates: Isolates::Undecidable,
        reason: "bpf_check_uarg_tail_zero answers E2BIG before security_bpf; before 6.3 the unprivileged_bpf_disabled EPERM for BPF_PROG_LOAD in __sys_bpf comes first, as for map_create",
    },
    Some(Capability::Bpf),
);

pub const BPF_BTF_LOAD: Probe = probe(
    "bpf.cmd.btf_load",
    "bpf",
    "bpf(BPF_BTF_LOAD, attr, sizeof(union bpf_attr) + 8) with a non-zero byte past the union",
    CONFIG_GATED,
    Oracle {
        guarantees: Some(Errno::E2BIG),
        isolates: Isolates::Seccomp,
        reason: "bpf_check_uarg_tail_zero runs before security_bpf and before bpf_btf_load checks bpf_capable, on every supported kernel, so only a filter answers EPERM first",
    },
    Some(Capability::Bpf),
);

pub const BPF_PROG_TYPE_SOCKET_FILTER: Probe = probe(
    "bpf.prog_type.socket_filter",
    "bpf",
    "bpf(BPF_PROG_LOAD, {prog_type: SOCKET_FILTER, insn_cnt: 1, insns: NULL}, sizeof(union bpf_attr)): the type unprivileged loaders may use",
    CONFIG_GATED,
    Oracle {
        guarantees: Some(Errno::EFAULT),
        isolates: Isolates::Undecidable,
        reason: "bpf_prog_load copies the instructions with copy_from_bpfptr after its type and unprivileged_bpf_disabled checks, so a reached load answers EFAULT; EPERM is security_bpf, a filter, or the sysctl",
    },
    Some(Capability::Bpf),
);

pub const BPF_PROG_TYPE_KPROBE: Probe = probe(
    "bpf.prog_type.kprobe",
    "bpf",
    "bpf(BPF_PROG_LOAD, {prog_type: KPROBE, insn_cnt: 1, insns: NULL}, sizeof(union bpf_attr)): a tracing type",
    CONFIG_GATED,
    Oracle {
        guarantees: Some(Errno::EFAULT),
        isolates: Isolates::Undecidable,
        reason: "bpf_prog_load refuses a perfmon program type without CAP_PERFMON and CAP_BPF with EPERM before copy_from_bpfptr reads the instructions, so EPERM is the capability, security_bpf or a filter",
    },
    Some(Capability::Perfmon),
);

// keyctl operations, and the two other key syscalls. The kernel keyring is
// not namespaced. A serial that cannot exist answers ENOKEY from the lookup,
// before any key permission hook.

pub const KEYCTL_READ: Probe = probe(
    "keyctl.op.read",
    "keyctl",
    "keyctl(KEYCTL_READ, 0x7fffffff, NULL, 0)",
    CONFIG_GATED,
    Oracle {
        guarantees: Some(Errno::ENOKEY),
        isolates: Isolates::Seccomp,
        reason: "lookup_user_key fails in key_lookup before key_task_permission calls security_key_permission, so ENOKEY comes before any LSM hook",
    },
    None,
);

pub const KEYCTL_OUT_OF_RANGE: Probe = probe(
    "keyctl.op.out_of_range",
    "keyctl",
    "keyctl(0x7fffffff, 0, 0, 0, 0): an operation no kernel defines",
    CONFIG_GATED,
    Oracle {
        guarantees: Some(Errno::EOPNOTSUPP),
        isolates: Isolates::Seccomp,
        reason: "SYSCALL_DEFINE5(keyctl) dispatches on the option with no hook before its default case, so EOPNOTSUPP comes before anything but a filter",
    },
    None,
);

pub const KEYCTL_ADD_KEY: Probe = probe(
    "keyctl.add_key",
    "keyctl",
    "add_key(\"user\", \"caliper\", NULL, 0, 0x7fffffff)",
    CONFIG_GATED,
    Oracle {
        guarantees: Some(Errno::ENOKEY),
        isolates: Isolates::Seccomp,
        reason: "add_key resolves the destination with lookup_user_key, which fails in key_lookup before any permission hook and before key_create_or_update, so nothing is created",
    },
    None,
);

pub const KEYCTL_REQUEST_KEY: Probe = probe(
    "keyctl.request_key",
    "keyctl",
    "request_key(\"user\", \"caliper\", NULL, 0x7fffffff)",
    CONFIG_GATED,
    Oracle {
        guarantees: Some(Errno::ENOKEY),
        isolates: Isolates::Seccomp,
        reason: "request_key looks up the destination keyring with lookup_user_key before request_key_and_link, so a missing serial answers ENOKEY before any hook or upcall",
    },
    None,
);

// prctl options. security_task_prctl runs before the option switch, so no
// oracle here separates a filter from an LSM.

pub const PRCTL_OUT_OF_RANGE: Probe = probe(
    "prctl.option.out_of_range",
    "prctl",
    "prctl(0x7fffffff, 0, 0, 0, 0): an option no kernel defines",
    KernelDependency::NONE,
    Oracle {
        guarantees: Some(Errno::EINVAL),
        isolates: Isolates::SeccompOrLsm,
        reason: "SYSCALL_DEFINE5(prctl) calls security_task_prctl first and reaches its default EINVAL only when every module returns ENOSYS",
    },
    None,
);

pub const PRCTL_SET_MM: Probe = probe(
    "prctl.option.set_mm",
    "prctl",
    "prctl(PR_SET_MM, PR_SET_MM_START_CODE, 0, 0, 1): a non-zero arg5",
    KernelDependency::NONE,
    Oracle {
        guarantees: Some(Errno::EINVAL),
        isolates: Isolates::SeccompOrLsm,
        reason: "prctl_set_mm rejects a non-zero arg5 with EINVAL before it checks CAP_SYS_RESOURCE, but after security_task_prctl",
    },
    Some(Capability::SysResource),
);

pub const PRCTL_SET_DUMPABLE: Probe = probe(
    "prctl.option.set_dumpable",
    "prctl",
    "prctl(PR_SET_DUMPABLE, 2, 0, 0, 0): SUID_DUMP_ROOT, which prctl refuses",
    KernelDependency::NONE,
    Oracle {
        guarantees: Some(Errno::EINVAL),
        isolates: Isolates::SeccompOrLsm,
        reason: "the PR_SET_DUMPABLE case accepts only SUID_DUMP_DISABLE and SUID_DUMP_USER, after security_task_prctl, so nothing changes",
    },
    None,
);

// perf_event_open. The flags are a register; the event type sits in the
// attr, behind the LSM hook and kernel.perf_event_paranoid.

pub const PERF_FLAGS_INVALID: Probe = probe(
    "perf_event_open.flags.invalid",
    "perf_event_open",
    "perf_event_open(&attr, 0, -1, -1, ~0UL)",
    CONFIG_GATED,
    Oracle {
        guarantees: Some(Errno::EINVAL),
        isolates: Isolates::Seccomp,
        reason: "SYSCALL_DEFINE5(perf_event_open) rejects flags outside PERF_FLAG_ALL before perf_copy_attr and before security_perf_event_open",
    },
    None,
);

pub const PERF_ATTR_SIZE: Probe = probe(
    "perf_event_open.attr.bad_size",
    "perf_event_open",
    "perf_event_open({size: 1}, 0, -1, -1, 0)",
    CONFIG_GATED,
    Oracle {
        guarantees: Some(Errno::E2BIG),
        isolates: Isolates::Seccomp,
        reason: "perf_copy_attr answers E2BIG for a size below PERF_ATTR_SIZE_VER0 before security_perf_event_open runs",
    },
    None,
);

pub const PERF_CPU_WIDE: Probe = probe(
    "perf_event_open.cpu_wide",
    "perf_event_open",
    "perf_event_open({type: SOFTWARE, config: CPU_CLOCK}, -1, 0, -1, PERF_FLAG_FD_CLOEXEC): every task on CPU 0",
    CONFIG_GATED,
    Oracle {
        guarantees: None,
        isolates: Isolates::SeccompOrLsm,
        reason: "security_perf_event_open runs after perf_copy_attr, then perf_allow_cpu answers EACCES under perf_event_paranoid > 0 without CAP_PERFMON; a reached call returns a descriptor the child's exit closes",
    },
    Some(Capability::Perfmon),
);

// userfaultfd. Kernel-mode faults are gated on vm.unprivileged_userfaultfd
// or CAP_SYS_PTRACE; UFFD_USER_MODE_ONLY is always allowed.

pub const UFFD_FLAGS_INVALID: Probe = probe(
    "userfaultfd.flags.invalid",
    "userfaultfd",
    "userfaultfd(UFFD_USER_MODE_ONLY | 2)",
    CONFIG_GATED,
    Oracle {
        guarantees: Some(Errno::EINVAL),
        isolates: Isolates::Seccomp,
        reason: "userfaultfd_syscall_allowed passes UFFD_USER_MODE_ONLY, then new_userfaultfd rejects the unknown bit before anon_inode_create_getfd reaches any LSM hook",
    },
    None,
);

pub const UFFD_USER_MODE: Probe = probe(
    "userfaultfd.user_mode_only",
    "userfaultfd",
    "userfaultfd(UFFD_USER_MODE_ONLY | O_CLOEXEC)",
    CONFIG_GATED,
    Oracle {
        guarantees: None,
        isolates: Isolates::SeccompOrLsm,
        reason: "no capability gates user-mode-only; anon_inode_create_getfd calls security_inode_init_security_anon, so EPERM is a filter or an LSM; a reached call returns a descriptor the child's exit closes",
    },
    None,
);

pub const UFFD_KERNEL_FAULTS: Probe = probe(
    "userfaultfd.kernel_faults",
    "userfaultfd",
    "userfaultfd(O_CLOEXEC): kernel-mode faults",
    CONFIG_GATED,
    Oracle {
        guarantees: None,
        isolates: Isolates::Undecidable,
        reason: "userfaultfd_syscall_allowed answers EPERM without vm.unprivileged_userfaultfd or CAP_SYS_PTRACE, the same answer a filter gives",
    },
    Some(Capability::SysPtrace),
);

// open_by_handle_at, the shocker entry point, and its counterpart.

pub const FHANDLE_OPEN: Probe = probe(
    "open_by_handle_at.open",
    "open_by_handle_at",
    "open_by_handle_at(AT_FDCWD, NULL, O_RDONLY)",
    CONFIG_GATED,
    Oracle {
        guarantees: Some(Errno::EFAULT),
        isolates: Isolates::Undecidable,
        reason: "before 6.10 handle_to_path checks CAP_DAC_READ_SEARCH before copy_from_user reads the handle; from 6.10 the copy comes first and may_decode_fh decides later, so EFAULT is guaranteed only to a capable caller on older kernels",
    },
    Some(Capability::DacReadSearch),
);

pub const FHANDLE_NAME_TO_HANDLE: Probe = probe(
    "open_by_handle_at.name_to_handle_at",
    "open_by_handle_at",
    "name_to_handle_at(AT_FDCWD, \"/\", NULL, NULL, ~0)",
    CONFIG_GATED,
    Oracle {
        guarantees: Some(Errno::EINVAL),
        isolates: Isolates::Seccomp,
        reason: "SYSCALL_DEFINE5(name_to_handle_at) rejects unknown flags before user_path_at resolves the path, so EINVAL comes before any LSM hook",
    },
    None,
);

// Module loading. capability.sys_module already measures finit_module;
// these are the other two entry points. The capability check comes first in
// both, so EPERM is never separable from a filter.

pub const MODULE_INIT: Probe = probe(
    "module.init_module",
    "module",
    "init_module(NULL, 0, \"\")",
    CONFIG_GATED,
    Oracle {
        guarantees: Some(Errno::ENOEXEC),
        isolates: Isolates::Undecidable,
        reason: "may_init_module checks CAP_SYS_MODULE and modules_disabled first; copy_module_from_user then answers ENOEXEC for a length below the ELF header, before security_kernel_load_data",
    },
    Some(Capability::SysModule),
);

pub const MODULE_DELETE: Probe = probe(
    "module.delete_module",
    "module",
    "delete_module(\"caliper_absent\", O_NONBLOCK)",
    CONFIG_GATED,
    Oracle {
        guarantees: Some(Errno::ENOENT),
        isolates: Isolates::Undecidable,
        reason: "SYSCALL_DEFINE2(delete_module) checks CAP_SYS_MODULE and modules_disabled before find_module, which answers ENOENT for a name no module has",
    },
    Some(Capability::SysModule),
);

// seccomp user notification. seccomp(2) has no LSM hook, so a reached call
// can only be pre-empted by a filter.

pub const SECCOMP_NEW_LISTENER: Probe = probe(
    "seccomp_notify.new_listener",
    "seccomp_notify",
    "seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, NULL)",
    CONFIG_GATED,
    Oracle {
        guarantees: Some(Errno::EFAULT),
        isolates: Isolates::Seccomp,
        reason: "seccomp_set_mode_filter validates the flags, then seccomp_prepare_user_filter copies the program with copy_from_user before any check that installs anything, so EFAULT comes before any filter is added",
    },
    None,
);

pub const SECCOMP_NOTIF_SIZES: Probe = probe(
    "seccomp_notify.get_notif_sizes",
    "seccomp_notify",
    "seccomp(SECCOMP_GET_NOTIF_SIZES, 0, NULL)",
    CONFIG_GATED,
    Oracle {
        guarantees: Some(Errno::EFAULT),
        isolates: Isolates::Seccomp,
        reason: "do_seccomp passes straight to seccomp_get_notif_sizes, whose copy_to_user faults on NULL, with no hook before it",
    },
    None,
);

pub const SECCOMP_NOTIF_RECV: Probe = probe(
    "seccomp_notify.ioctl_recv",
    "seccomp_notify",
    "ioctl(-1, SECCOMP_IOCTL_NOTIF_RECV, NULL)",
    CONFIG_GATED,
    Oracle {
        guarantees: Some(Errno::EBADF),
        isolates: Isolates::Seccomp,
        reason: "SYSCALL_DEFINE3(ioctl) fails fdget before security_file_ioctl, so EBADF comes before any LSM hook",
    },
    None,
);
