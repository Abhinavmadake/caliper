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

//! Masked and read-only path coverage (`corpus/README.md`, committed set).
//!
//! The lists are pinned from containerd `v2.2.1` and `v1.7.12`
//! (`pkg/oci/spec.go`), Moby's `oci/defaults.go`, and Podman's
//! `containers/common/pkg/config/default.go`. Containerd and Moby mask
//! `/proc/asound`; Podman makes it read-only. It is consequently one probe:
//! the filesystem type distinguishes a mask and `ST_RDONLY` distinguishes the
//! Podman mount flag.
//!
//! Every probe opens its target with `O_PATH | O_NOFOLLOW | O_CLOEXEC` and
//! inspects it with `fstatfs`; it never reads or writes the target. A different
//! filesystem magic is encoded as `ENODATA` (the runtime mask), `ST_RDONLY`
//! as `EROFS` (a read-only mount), and the expected filesystem as success.

use std::ffi::CStr;

use caliper_engine::{
    Applicability, Errno, Isolates, KernelDependency, Oracle, Probe, RawResult, SideEffects,
};

use crate::common::ONE_CALL;

const PATH_DEPENDENCY: KernelDependency = KernelDependency {
    since: None,
    absent_errno: Some(Errno::ENOENT),
};

fn check_path(path: &CStr, expected_magic: libc::c_long) -> RawResult {
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat,
            libc::AT_FDCWD,
            path.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(Errno::last());
    }

    let fd = fd as libc::c_int;
    let mut statfs: libc::statfs = unsafe { std::mem::zeroed() };
    let result = unsafe { libc::syscall(libc::SYS_fstatfs, fd, &mut statfs as *mut libc::statfs) };
    // Preserve fstatfs's result before close can alter the thread-local errno.
    let errno = (result < 0).then(Errno::last);
    unsafe { libc::syscall(libc::SYS_close, fd) };
    if let Some(errno) = errno {
        return Err(errno);
    }

    if statfs.f_type as libc::c_long != expected_magic {
        Err(Errno::ENODATA)
    } else if statfs.f_flags & libc::ST_RDONLY as libc::c_ulong != 0 {
        Err(Errno::EROFS)
    } else {
        Ok(())
    }
}

macro_rules! path_probe {
    ($name:ident, $path:expr, $magic:expr) => {
        fn $name() -> RawResult {
            check_path($path, $magic as libc::c_long)
        }
    };
}

path_probe!(masked_proc_kcore, c"/proc/kcore", libc::PROC_SUPER_MAGIC);
path_probe!(masked_proc_keys, c"/proc/keys", libc::PROC_SUPER_MAGIC);
path_probe!(
    masked_proc_latency_stats,
    c"/proc/latency_stats",
    libc::PROC_SUPER_MAGIC
);
path_probe!(
    masked_proc_timer_list,
    c"/proc/timer_list",
    libc::PROC_SUPER_MAGIC
);
path_probe!(
    masked_proc_timer_stats,
    c"/proc/timer_stats",
    libc::PROC_SUPER_MAGIC
);
path_probe!(
    masked_proc_sched_debug,
    c"/proc/sched_debug",
    libc::PROC_SUPER_MAGIC
);
path_probe!(masked_proc_acpi, c"/proc/acpi", libc::PROC_SUPER_MAGIC);
path_probe!(masked_proc_asound, c"/proc/asound", libc::PROC_SUPER_MAGIC);
path_probe!(masked_proc_scsi, c"/proc/scsi", libc::PROC_SUPER_MAGIC);
path_probe!(masked_sys_firmware, c"/sys/firmware", libc::SYSFS_MAGIC);
path_probe!(
    masked_sys_powercap,
    c"/sys/devices/virtual/powercap",
    libc::SYSFS_MAGIC
);
path_probe!(readonly_proc_bus, c"/proc/bus", libc::PROC_SUPER_MAGIC);
path_probe!(readonly_proc_fs, c"/proc/fs", libc::PROC_SUPER_MAGIC);
path_probe!(readonly_proc_irq, c"/proc/irq", libc::PROC_SUPER_MAGIC);
path_probe!(readonly_proc_sys, c"/proc/sys", libc::PROC_SUPER_MAGIC);
path_probe!(
    readonly_proc_sysrq_trigger,
    c"/proc/sysrq-trigger",
    libc::PROC_SUPER_MAGIC
);
path_probe!(
    control_proc_self_status,
    c"/proc/self/status",
    libc::PROC_SUPER_MAGIC
);

macro_rules! define_probe {
    ($constant:ident, $function:ident, $id:literal) => {
        pub const $constant: Probe = Probe {
            id: $id,
            family: "path",
            description: "openat(O_PATH) + fstatfs: mask (ENODATA), read-only mount (EROFS), or reachable path",
            risk: ONE_CALL,
            arch: Applicability::All,
            kernel: PATH_DEPENDENCY,
            oracle: Oracle {
                guarantees: None,
                isolates: Isolates::SeccompOrLsm,
                reason: "openat(O_PATH) and fstatfs inspect the mount without reading or writing: a different filesystem magic is encoded as ENODATA for a runtime mask, ST_RDONLY as EROFS for a read-only mount, and the expected filesystem as reachable",
            },
            capability: None,
            effects: SideEffects::NONE,
            run: $function,
        };
    };
}

define_probe!(
    MASKED_PROC_KCORE,
    masked_proc_kcore,
    "path.masked.proc_kcore"
);
define_probe!(MASKED_PROC_KEYS, masked_proc_keys, "path.masked.proc_keys");
define_probe!(
    MASKED_PROC_LATENCY_STATS,
    masked_proc_latency_stats,
    "path.masked.proc_latency_stats"
);
define_probe!(
    MASKED_PROC_TIMER_LIST,
    masked_proc_timer_list,
    "path.masked.proc_timer_list"
);
define_probe!(
    MASKED_PROC_TIMER_STATS,
    masked_proc_timer_stats,
    "path.masked.proc_timer_stats"
);
define_probe!(
    MASKED_PROC_SCHED_DEBUG,
    masked_proc_sched_debug,
    "path.masked.proc_sched_debug"
);
define_probe!(MASKED_PROC_ACPI, masked_proc_acpi, "path.masked.proc_acpi");
define_probe!(
    MASKED_PROC_ASOUND,
    masked_proc_asound,
    "path.masked.proc_asound"
);
define_probe!(MASKED_PROC_SCSI, masked_proc_scsi, "path.masked.proc_scsi");
define_probe!(
    MASKED_SYS_FIRMWARE,
    masked_sys_firmware,
    "path.masked.sys_firmware"
);
define_probe!(
    MASKED_SYS_POWERCAP,
    masked_sys_powercap,
    "path.masked.sys_powercap"
);
define_probe!(
    READONLY_PROC_BUS,
    readonly_proc_bus,
    "path.readonly.proc_bus"
);
define_probe!(READONLY_PROC_FS, readonly_proc_fs, "path.readonly.proc_fs");
define_probe!(
    READONLY_PROC_IRQ,
    readonly_proc_irq,
    "path.readonly.proc_irq"
);
define_probe!(
    READONLY_PROC_SYS,
    readonly_proc_sys,
    "path.readonly.proc_sys"
);
define_probe!(
    READONLY_PROC_SYSRQ_TRIGGER,
    readonly_proc_sysrq_trigger,
    "path.readonly.proc_sysrq_trigger"
);
define_probe!(
    CONTROL_PROC_SELF_STATUS,
    control_proc_self_status,
    "path.control.proc_self_status"
);
