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

//! Mount filesystem types (`corpus/README.md`, committed set; #13).
//!
//! The order in `fs/namespace.c`, 6.x: `path_mount` resolves the target
//! (`ENOENT`), then `may_mount` checks `CAP_SYS_ADMIN` in the mount
//! namespace's owner (`EPERM`), then `do_new_mount` looks the type up
//! with `get_fs_type` (asking the kernel to load `fs-<name>` if nothing is
//! registered; `ENODEV` if still nothing), then `security_sb_mount`, then
//! the filesystem's own `get_tree`. So for a caller without the capability
//! `mount(2)` answers `EPERM` before the type name is read: the type is
//! unreachable through the syscall, and every `mount(2)` probe here
//! measures the capability, with the type recorded for the cell that has
//! it.
//!
//! Three kinds of probe, then:
//!
//! - **Reach.** `mount.reach`, a target that does not exist: `ENOENT` is
//!   produced before `may_mount`, so `EPERM` there is a filter at entry.
//! - **Type presence**, one per filesystem type, through the enumeration
//!   interface the proposal prefers (§6.2): `/proc/filesystems` lists the
//!   registered types, needs no privilege, and loads nothing. Absent is
//!   `ENODEV`, the errno `get_fs_type` answers with and one `read(2)`
//!   never produces (the encoding `spec/probe.md`'s decision allows),
//!   declared as the kernel dependency so it reads `unimplemented`. This
//!   is what the diff engine needs to exclude kernel-version-explained
//!   divergence probe by probe: a type the kernel does not have is not
//!   policy.
//! - **Mount**, for the three types the posture asserts on (`proc`,
//!   `overlay`, `fuse`): a real `mount(2)` onto a directory the child
//!   creates under `/tmp`, unmounted and removed by the child before it
//!   returns. Unprivileged it is `EPERM` at `may_mount`; on a cell that
//!   grants `CAP_SYS_ADMIN` the mount happens and the record says so. The
//!   mount table is declared, the child owns the mount, and the residual
//!   snapshot checks that nothing outlived it.

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

// --- type presence ---------------------------------------------------------

/// `/proc/filesystems` into a stack buffer. Lines are `nodev\t<name>` or
/// `\t<name>`. Returns `ENODEV` if `name` is not registered.
fn registered(name: &[u8]) -> RawResult {
    const PATH: &std::ffi::CStr = c"/proc/filesystems";
    // SAFETY: a NUL-terminated path and constant flags.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat,
            libc::AT_FDCWD,
            PATH.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    } as libc::c_int;
    if fd < 0 {
        return Err(Errno::last());
    }
    let mut buf = [0u8; 4096];
    // SAFETY: fd is open and buf is valid for its full length.
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    let read_errno = (n < 0).then(Errno::last);
    // SAFETY: fd is a descriptor this function owns and closes once.
    unsafe { libc::close(fd) };
    if let Some(e) = read_errno {
        return Err(e);
    }
    let text = &buf[..n as usize];
    let found = text.split(|&b| b == b'\n').any(|line| {
        let entry = line.rsplit(|&b| b == b'\t').next().unwrap_or(line);
        entry == name
    });
    if found {
        Ok(())
    } else {
        Err(Errno::ENODEV)
    }
}

/// A registered type may be absent from this kernel: `ENODEV` from the
/// lookup is absence, never policy.
const TYPE_GATED: KernelDependency = KernelDependency {
    since: None,
    absent_errno: Some(Errno::ENODEV),
};

macro_rules! fstype {
    ($konst:ident, $f:ident, $id:literal, $name:literal, $what:literal) => {
        fn $f() -> RawResult {
            registered($name.as_bytes())
        }
        pub const $konst: Probe = Probe {
            id: $id,
            family: "mount",
            description: concat!("/proc/filesystems lists ", $name, ": ", $what),
            risk: ONE_CALL,
            arch: Applicability::All,
            kernel: TYPE_GATED,
            oracle: Oracle {
                guarantees: None,
                isolates: Isolates::Undecidable,
                reason: "enumeration, not execution: the type is read from /proc/filesystems, \
                         which needs no privilege and loads nothing. Absence is returned as \
                         ENODEV, the errno get_fs_type answers with and one read(2) never \
                         produces, and reads as unimplemented. An EPERM here is /proc itself \
                         unreadable, not a filter on mount(2); mount.reach measures that",
            },
            capability: None,
            effects: SideEffects::NONE,
            run: $f,
        };
    };
}

fstype!(
    TYPE_PROC,
    type_proc,
    "mount.type.proc",
    "proc",
    "procfs, mountable anywhere the capability allows"
);
fstype!(TYPE_SYSFS, type_sysfs, "mount.type.sysfs", "sysfs", "sysfs");
fstype!(TYPE_TMPFS, type_tmpfs, "mount.type.tmpfs", "tmpfs", "tmpfs");
fstype!(
    TYPE_DEVTMPFS,
    type_devtmpfs,
    "mount.type.devtmpfs",
    "devtmpfs",
    "the kernel's own /dev"
);
fstype!(
    TYPE_DEVPTS,
    type_devpts,
    "mount.type.devpts",
    "devpts",
    "pseudoterminals"
);
fstype!(
    TYPE_OVERLAY,
    type_overlay,
    "mount.type.overlay",
    "overlay",
    "overlayfs, every container's root"
);
fstype!(
    TYPE_FUSE,
    type_fuse,
    "mount.type.fuse",
    "fuse",
    "user-space filesystems"
);
fstype!(
    TYPE_FUSECTL,
    type_fusectl,
    "mount.type.fusectl",
    "fusectl",
    "the FUSE control filesystem"
);
fstype!(
    TYPE_CGROUP2,
    type_cgroup2,
    "mount.type.cgroup2",
    "cgroup2",
    "the unified cgroup hierarchy"
);
fstype!(
    TYPE_CGROUP,
    type_cgroup,
    "mount.type.cgroup",
    "cgroup",
    "the v1 cgroup hierarchy"
);
fstype!(
    TYPE_BPF,
    type_bpf,
    "mount.type.bpf",
    "bpf",
    "pinned BPF objects"
);
fstype!(
    TYPE_DEBUGFS,
    type_debugfs,
    "mount.type.debugfs",
    "debugfs",
    "kernel debugging interfaces"
);
fstype!(
    TYPE_TRACEFS,
    type_tracefs,
    "mount.type.tracefs",
    "tracefs",
    "ftrace"
);
fstype!(
    TYPE_CONFIGFS,
    type_configfs,
    "mount.type.configfs",
    "configfs",
    "kernel object configuration"
);
fstype!(
    TYPE_SECURITYFS,
    type_securityfs,
    "mount.type.securityfs",
    "securityfs",
    "LSM interfaces"
);
fstype!(
    TYPE_EFIVARFS,
    type_efivarfs,
    "mount.type.efivarfs",
    "efivarfs",
    "UEFI variables"
);
fstype!(
    TYPE_PSTORE,
    type_pstore,
    "mount.type.pstore",
    "pstore",
    "persistent storage for crash logs"
);
fstype!(
    TYPE_BINFMT_MISC,
    type_binfmt_misc,
    "mount.type.binfmt_misc",
    "binfmt_misc",
    "interpreter registration"
);
fstype!(
    TYPE_HUGETLBFS,
    type_hugetlbfs,
    "mount.type.hugetlbfs",
    "hugetlbfs",
    "huge pages"
);
fstype!(
    TYPE_MQUEUE,
    type_mqueue,
    "mount.type.mqueue",
    "mqueue",
    "POSIX message queues"
);
fstype!(
    TYPE_AUTOFS,
    type_autofs,
    "mount.type.autofs",
    "autofs",
    "automounter"
);
fstype!(
    TYPE_ECRYPTFS,
    type_ecryptfs,
    "mount.type.ecryptfs",
    "ecryptfs",
    "stacked encryption"
);
fstype!(
    TYPE_SQUASHFS,
    type_squashfs,
    "mount.type.squashfs",
    "squashfs",
    "compressed read-only images"
);
fstype!(
    TYPE_ISO9660,
    type_iso9660,
    "mount.type.iso9660",
    "iso9660",
    "optical media images"
);
fstype!(TYPE_VFAT, type_vfat, "mount.type.vfat", "vfat", "FAT");
fstype!(TYPE_EXT4, type_ext4, "mount.type.ext4", "ext4", "ext4");
fstype!(TYPE_BTRFS, type_btrfs, "mount.type.btrfs", "btrfs", "btrfs");
fstype!(TYPE_XFS, type_xfs, "mount.type.xfs", "xfs", "xfs");
fstype!(TYPE_NFS, type_nfs, "mount.type.nfs", "nfs", "NFS v3");
fstype!(TYPE_NFS4, type_nfs4, "mount.type.nfs4", "nfs4", "NFS v4");
fstype!(TYPE_CIFS, type_cifs, "mount.type.cifs", "cifs", "SMB");
fstype!(
    TYPE_9P,
    type_9p,
    "mount.type.9p",
    "9p",
    "Plan 9 transport (virtio-9p)"
);
fstype!(
    TYPE_VIRTIOFS,
    type_virtiofs,
    "mount.type.virtiofs",
    "virtiofs",
    "virtio-fs"
);
fstype!(
    TYPE_NTFS3,
    type_ntfs3,
    "mount.type.ntfs3",
    "ntfs3",
    "NTFS, the in-kernel driver"
);

// --- mount, for the cell that can -----------------------------------------

/// Where a mount probe mounts: a directory the child makes and removes
/// under `/tmp`, which the probe image carries writable for exactly this
/// (`Dockerfile`). `ENOENT` from `mkdir` is the target unresolvable and
/// the probe's answer; `mount(2)` is never reached.
const MOUNT_DIR: &std::ffi::CStr = c"/tmp/caliper-mount";
/// Two lower layers for the overlay probe, made and removed alongside.
const LOWER_A: &std::ffi::CStr = c"/tmp/caliper-mount/a";
const LOWER_B: &std::ffi::CStr = c"/tmp/caliper-mount/b";
const NO_SOURCE: &std::ffi::CStr = c"none";

fn mkdir(path: &std::ffi::CStr) -> libc::c_long {
    // SAFETY: a NUL-terminated path and a mode.
    unsafe { libc::syscall(libc::SYS_mkdirat, libc::AT_FDCWD, path.as_ptr(), 0o700) }
}

fn rmdir(path: &std::ffi::CStr) {
    // SAFETY: a NUL-terminated path this child made.
    unsafe {
        libc::syscall(
            libc::SYS_unlinkat,
            libc::AT_FDCWD,
            path.as_ptr(),
            libc::AT_REMOVEDIR,
        )
    };
}

/// `mkdir`, `mount(2)`, and if the mount happened `umount2`; then `rmdir`.
/// The kernel's answer is `mount(2)`'s; the clean-up is the child's own and
/// the residual snapshot is what says whether it worked.
fn mount_type(fstype: &std::ffi::CStr, data: Option<&std::ffi::CStr>) -> RawResult {
    let made = mkdir(MOUNT_DIR);
    if made < 0 && Errno::last() != Errno::EEXIST {
        return Err(Errno::last());
    }
    let lowers = data.is_some();
    if lowers {
        mkdir(LOWER_A);
        mkdir(LOWER_B);
    }
    // SAFETY: NUL-terminated string constants, a null or constant data
    // pointer, all of which mount(2) accepts.
    let r = unsafe {
        libc::syscall(
            libc::SYS_mount,
            NO_SOURCE.as_ptr(),
            MOUNT_DIR.as_ptr(),
            fstype.as_ptr(),
            0 as libc::c_ulong,
            data.map_or(std::ptr::null(), |d| d.as_ptr()),
        )
    };
    let answer = result(r);
    if r == 0 {
        // The child owns the mount; take it down before returning. If
        // umount2 fails the mount outlives the child, and the residual
        // snapshot says so against this probe.
        // SAFETY: the same constant path.
        unsafe { libc::syscall(libc::SYS_umount2, MOUNT_DIR.as_ptr(), 0 as libc::c_int) };
    }
    if lowers {
        rmdir(LOWER_A);
        rmdir(LOWER_B);
    }
    if made == 0 {
        rmdir(MOUNT_DIR);
    }
    answer
}

fn mount_proc() -> RawResult {
    mount_type(c"proc", None)
}

/// A read-only overlay needs at least two lower layers (`ovl_get_tree`
/// answers `EINVAL` to one and no upper); the child makes two empty ones.
fn mount_overlay() -> RawResult {
    mount_type(
        c"overlay",
        Some(c"lowerdir=/tmp/caliper-mount/a:/tmp/caliper-mount/b"),
    )
}

/// `fuse` needs an open `/dev/fuse` descriptor in `data`; without one the
/// filesystem's own `get_tree` answers `EINVAL`, after `may_mount` and after
/// `security_sb_mount`. So on a cell with the capability the answer is
/// `EINVAL`, structurally, and the mount never happens.
fn mount_fuse() -> RawResult {
    mount_type(c"fuse", None)
}

macro_rules! mount_probe {
    ($konst:ident, $f:ident, $id:literal, $desc:literal, $guarantees:expr, $reason:literal) => {
        pub const $konst: Probe = Probe {
            id: $id,
            family: "mount",
            description: $desc,
            risk: ONE_CALL,
            arch: Applicability::All,
            kernel: KernelDependency::NONE,
            oracle: Oracle {
                guarantees: $guarantees,
                isolates: Isolates::Undecidable,
                reason: $reason,
            },
            capability: Some(Capability::SysAdmin),
            effects: SideEffects::Declared {
                residual: &[ResidualClass::Mounts],
                module_autoload: false,
            },
            run: $f,
        };
    };
}

mount_probe!(
    MOUNT_PROC,
    mount_proc,
    "mount.fs.proc",
    "mount(none, /tmp/caliper-mount, proc): a second procfs, unmounted by the child",
    None,
    "path_mount resolves the target, then may_mount answers EPERM without CAP_SYS_ADMIN, \
     before get_fs_type reads the type: EPERM is the capability or a filter, not \
     separable. With the capability the mount happens and the child unmounts it; the \
     mount-table snapshot verifies the rollback"
);

mount_probe!(
    MOUNT_OVERLAY,
    mount_overlay,
    "mount.fs.overlay",
    "mount(none, /tmp/caliper-mount, overlay, lowerdir=a:b): a read-only overlay, unmounted by the child",
    None,
    "path_mount resolves the target, then may_mount answers EPERM without CAP_SYS_ADMIN, \
     before get_fs_type reads the type. With the capability, ovl_get_tree mounts a \
     read-only overlay over two empty lower layers and the child unmounts it; the \
     mount-table snapshot verifies the rollback"
);

mount_probe!(MOUNT_FUSE, mount_fuse, "mount.fs.fuse",
    "mount(none, /tmp/caliper-mount, fuse): fuse without a descriptor, guaranteed EINVAL past the capability",
    Some(Errno::EINVAL),
    "path_mount resolves the target, then may_mount answers EPERM without CAP_SYS_ADMIN. \
     With it, get_fs_type finds fuse, security_sb_mount runs, and fuse_get_tree \
     rejects a mount with no fd= option with EINVAL: the guarantee is produced after \
     the capability check and the LSM hook, so it proves both were passed, and \
     nothing is mounted");
