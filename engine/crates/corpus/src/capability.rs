// Copyright 2026 Abhinav Ajit Madake, Sahil Tatyabhau Waje,
// Ritesh Aresh Saindane, Yogesh Babaji Palve
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

//! Capability-effect probes. Each call reaches the kernel's capability check;
//! successful descriptors and namespace state die with the isolated child.
//! The mknod probe also creates a temporary `/tmp` node on the capable path
//! and removes it before returning when the child is not killed. The oracle
//! is intentionally
//! `Undecidable`: an EPERM/EACCES answer is the syscall's own missing-
//! capability result, which is correlated with `Cell::capabilities`.

use caliper_engine::{
    Applicability, Arch, Capability, Errno, Isolates, KernelDependency, Oracle, Probe, RawResult,
    SideEffects, Status,
};

use crate::common::{result, ONE_CALL};

fn sys_time() -> RawResult {
    result(unsafe { libc::syscall(libc::SYS_settimeofday, 0, 0) })
}

fn sys_boot() -> RawResult {
    // reboot(2) checks CAP_SYS_BOOT before validating the magic command.
    result(unsafe { libc::syscall(libc::SYS_reboot, 0, 0, libc::LINUX_REBOOT_CMD_CAD_OFF, 0) })
}

fn sys_module() -> RawResult {
    result(unsafe { libc::syscall(libc::SYS_finit_module, -1, c"".as_ptr(), 0) })
}

fn mknod() -> RawResult {
    let mode = libc::S_IFCHR | 0o600;
    let dev = libc::makedev(1, 3);
    let path = c"/tmp/caliper-mknod";
    // Keep the parent valid so filename_create succeeds and vfs_mknod reaches
    // the CAP_MKNOD check. A capable child may create the node; remove it
    // before returning when the child is not killed.
    let outcome = result(unsafe {
        libc::syscall(libc::SYS_mknodat, libc::AT_FDCWD, path.as_ptr(), mode, dev)
    });
    unsafe { libc::unlink(path.as_ptr()) };
    outcome
}

fn sys_ptrace() -> RawResult {
    let parent = unsafe { libc::syscall(libc::SYS_getppid) };
    let mut local = 0u8;
    let local_iov = libc::iovec {
        iov_base: (&mut local as *mut u8).cast(),
        iov_len: 1,
    };
    let remote_iov = libc::iovec {
        // A non-null, invalid address makes the privileged path fail safely
        // with EFAULT after ptrace_may_access has been evaluated.
        iov_base: std::ptr::dangling::<libc::c_void>().cast_mut(),
        iov_len: 1,
    };
    result(unsafe {
        libc::syscall(
            libc::SYS_process_vm_readv,
            parent,
            &local_iov,
            1,
            &remote_iov,
            1,
            0,
        )
    })
}

fn net_bind_service() -> RawResult {
    let fd = unsafe {
        libc::syscall(
            libc::SYS_socket,
            libc::AF_INET,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(Errno::last());
    }

    let mut address: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    address.sin_family = libc::AF_INET as libc::sa_family_t;
    address.sin_port = 1u16.to_be();
    result(unsafe {
        libc::syscall(
            libc::SYS_bind,
            fd,
            &address as *const libc::sockaddr_in,
            std::mem::size_of::<libc::sockaddr_in>(),
        )
    })
}

fn sys_nice() -> RawResult {
    result(unsafe { libc::syscall(libc::SYS_setpriority, libc::PRIO_PROCESS, 0, -1) })
}

fn sys_rawio() -> RawResult {
    #[cfg(target_arch = "x86_64")]
    {
        result(unsafe { libc::syscall(libc::SYS_iopl, 3) })
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        Ok(())
    }
}

const UNDECIDABLE: Isolates = Isolates::Undecidable;

pub const SYS_TIME: Probe = Probe {
    id: "capability.sys_time",
    family: "capability",
    status: Status::Committed,
    description: "settimeofday(NULL, NULL): capability-only time check",
    risk: ONE_CALL,
    arch: Applicability::All,
    kernel: KernelDependency::NONE,
    oracle: Oracle {
        guarantees: None,
        isolates: UNDECIDABLE,
        reason: "do_sys_settimeofday64 checks CAP_SYS_TIME before the null/no-op update; settimeofday(2) returns EPERM without it",
    },
    capability: Some(Capability::SysTime),
    effects: SideEffects::NONE,
    run: sys_time,
};

pub const SYS_BOOT: Probe = Probe {
    id: "capability.sys_boot",
    family: "capability",
    status: Status::Committed,
    description: "reboot(0, 0, LINUX_REBOOT_CMD_CAD_OFF, NULL): capability check",
    risk: ONE_CALL,
    arch: Applicability::All,
    kernel: KernelDependency::NONE,
    oracle: Oracle {
        guarantees: Some(Errno::EINVAL),
        isolates: UNDECIDABLE,
        reason: "SYSCALL_DEFINE4(reboot) checks CAP_SYS_BOOT before the bad magic validation; reboot(2) documents EINVAL for the malformed command",
    },
    capability: Some(Capability::SysBoot),
    effects: SideEffects::NONE,
    run: sys_boot,
};

pub const SYS_MODULE: Probe = Probe {
    id: "capability.sys_module",
    family: "capability",
    status: Status::Committed,
    description: "finit_module(-1, \"\", 0): module capability check",
    risk: ONE_CALL,
    arch: Applicability::All,
    kernel: KernelDependency::NONE,
    oracle: Oracle {
        guarantees: Some(Errno::EBADF),
        isolates: UNDECIDABLE,
        reason: "finit_module checks CAP_SYS_MODULE and modules_disabled before fdget_raw; finit_module(2) documents EBADF for fd -1",
    },
    capability: Some(Capability::SysModule),
    effects: SideEffects::NONE,
    run: sys_module,
};

pub const MKNOD: Probe = Probe {
    id: "capability.mknod",
    family: "capability",
    status: Status::Committed,
    description: "mknodat(AT_FDCWD, /tmp/caliper-mknod, S_IFCHR|0600, makedev(1,3))",
    risk: ONE_CALL,
    arch: Applicability::All,
    kernel: KernelDependency::NONE,
    oracle: Oracle {
        guarantees: None,
        isolates: UNDECIDABLE,
        reason: "filename_create resolves the existing /tmp parent before vfs_mknod checks CAP_MKNOD; without it mknodat returns EPERM, while a capable child creates and then unlinks the node. If the child is killed before cleanup, /tmp/caliper-mknod can remain",
    },
    capability: Some(Capability::Mknod),
    effects: SideEffects::NONE,
    run: mknod,
};

pub const SYS_PTRACE: Probe = Probe {
    id: "capability.sys_ptrace",
    family: "capability",
    status: Status::Committed,
    description: "process_vm_readv(getppid(), valid local iovec, invalid remote iovec): access check",
    risk: ONE_CALL,
    arch: Applicability::All,
    kernel: KernelDependency::NONE,
    oracle: Oracle {
        guarantees: None,
        isolates: UNDECIDABLE,
        reason: "a non-zero iovec forces process_vm_readv through ptrace_may_access before the remote copy; the non-dumpable probe parent therefore returns EPERM without CAP_SYS_PTRACE, including Yama and AppArmor ptrace policy denials, while a capable path reaches the deliberate EFAULT",
    },
    capability: Some(Capability::SysPtrace),
    effects: SideEffects::NONE,
    run: sys_ptrace,
};

pub const NET_BIND_SERVICE: Probe = Probe {
    id: "capability.net_bind_service",
    family: "capability",
    status: Status::Committed,
    description: "socket(AF_INET) + bind(0.0.0.0:1): privileged-port check",
    risk: ONE_CALL,
    arch: Applicability::All,
    kernel: KernelDependency::NONE,
    oracle: Oracle {
        guarantees: None,
        isolates: UNDECIDABLE,
        reason: "inet_bind checks the privileged port against CAP_NET_BIND_SERVICE after socket creation; bind(2) documents EACCES without the capability, subject to net.ipv4.ip_unprivileged_port_start",
    },
    capability: Some(Capability::NetBindService),
    effects: SideEffects::NONE,
    run: net_bind_service,
};

pub const SYS_NICE: Probe = Probe {
    id: "capability.sys_nice",
    family: "capability",
    status: Status::Committed,
    description: "setpriority(PRIO_PROCESS, 0, -1): priority capability check",
    risk: ONE_CALL,
    arch: Applicability::All,
    kernel: KernelDependency::NONE,
    oracle: Oracle {
        guarantees: None,
        isolates: UNDECIDABLE,
        reason: "set_user_nice checks CAP_SYS_NICE before changing the isolated child's nice value; setpriority(2) documents EACCES without permission",
    },
    capability: Some(Capability::SysNice),
    effects: SideEffects::NONE,
    run: sys_nice,
};

pub const SYS_RAWIO: Probe = Probe {
    id: "capability.sys_rawio",
    family: "capability",
    status: Status::Committed,
    description: "iopl(3): x86 I/O privilege capability check",
    risk: ONE_CALL,
    arch: Applicability::Only(&[Arch::X86_64]),
    kernel: KernelDependency::NONE,
    oracle: Oracle {
        guarantees: None,
        isolates: UNDECIDABLE,
        reason: "iopl checks CAP_SYS_RAWIO before changing the child's I/O privilege level; iopl(2) documents EPERM without it",
    },
    capability: Some(Capability::SysRawio),
    effects: SideEffects::NONE,
    run: sys_rawio,
};
