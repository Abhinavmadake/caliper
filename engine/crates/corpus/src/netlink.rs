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

//! Netlink protocol numbers (`corpus/README.md`, committed set; #11). One
//! `socket(AF_NETLINK, SOCK_RAW, <protocol>)` per protocol.
//!
//! The order, from `net/netlink/af_netlink.c`: `__sock_create` runs
//! `security_socket_create` and the family lookup (netlink is built in, so
//! it is always registered), then `netlink_create` rejects a type other
//! than `SOCK_RAW`/`SOCK_DGRAM` with `ESOCKTNOSUPPORT`, a protocol outside
//! `0..MAX_LINKS` (32) with `EPROTONOSUPPORT`, asks the kernel to load
//! `net-pf-16-proto-<N>` if the protocol has no handler — no capability
//! check on the caller — and answers `EPROTONOSUPPORT` if it still has none.
//! Creating the socket checks no capability for any protocol; the checks
//! (`CAP_NET_ADMIN` for netfilter and xfrm changes, `CAP_AUDIT_*` for
//! audit) are on `bind` and `sendmsg`, which no probe here issues. So:
//! `EPERM` is seccomp or an LSM (AppArmor 4 and SELinux both mediate
//! netlink by protocol); `EPROTONOSUPPORT` is the protocol absent from this
//! kernel or its module not loadable, `unimplemented`, and the module
//! snapshot shows which; success is reach.
//!
//! Descriptor-shaped, reclaimed by the child's exit; `module_autoload`
//! declared where the protocol lives in a module. Raw `SYS_socket`, as in
//! `socket.rs`.

use caliper_engine::{
    Applicability, Errno, Isolates, KernelDependency, Oracle, Probe, RawResult, SideEffects,
};

use crate::common::{result, ONE_CALL};

/// `NETLINK_SMC` (`include/uapi/linux/netlink.h`), which the libc crate
/// does not name.
const NETLINK_SMC: libc::c_int = 22;
/// `MAX_LINKS`: the first protocol number `netlink_create` rejects.
const MAX_LINKS: libc::c_int = 32;

fn netlink(protocol: libc::c_int) -> RawResult {
    // SAFETY: three integer arguments; a descriptor is the only effect and
    // the child's exit reclaims it.
    result(unsafe { libc::syscall(libc::SYS_socket, libc::AF_NETLINK, libc::SOCK_RAW, protocol) })
}

/// A protocol this kernel may not build or may not load:
/// `EPROTONOSUPPORT` from `netlink_create` is absence, not policy.
const CONFIG_GATED_PROTOCOL: KernelDependency = KernelDependency {
    since: None,
    absent_errno: Some(Errno::EPROTONOSUPPORT),
};

/// A netlink protocol probe. `$autoload` is whether the handler lives in a
/// module the call can make the kernel load (`net-pf-16-proto-<N>`).
macro_rules! protocol {
    ($konst:ident, $f:ident, $id:literal, $proto:expr, $desc:literal,
     kernel: $kernel:expr, autoload: $autoload:expr, reason: $reason:literal) => {
        fn $f() -> RawResult {
            netlink($proto)
        }
        pub const $konst: Probe = Probe {
            id: $id,
            family: "netlink",
            description: $desc,
            risk: ONE_CALL,
            arch: Applicability::All,
            kernel: $kernel,
            oracle: Oracle {
                guarantees: None,
                isolates: Isolates::SeccompOrLsm,
                reason: $reason,
            },
            capability: None,
            effects: SideEffects::Declared {
                residual: &[],
                module_autoload: $autoload,
            },
            run: $f,
        };
    };
}

// A protocol every kernel builds: the family-level control for the netlink
// probes.
protocol!(ROUTE, route, "netlink.protocol.route", libc::NETLINK_ROUTE,
    "socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE): rtnetlink is reachable",
    kernel: KernelDependency::NONE, autoload: false,
    reason: "netlink_create checks the protocol number after security_socket_create and \
             after the family lookup, so EPERM is seccomp or an LSM; NETLINK_ROUTE is built \
             into every supported kernel, so EPROTONOSUPPORT cannot be absence");

protocol!(USERSOCK, usersock, "netlink.protocol.usersock", libc::NETLINK_USERSOCK,
    "socket(AF_NETLINK, SOCK_RAW, NETLINK_USERSOCK): the user-space-to-user-space protocol",
    kernel: KernelDependency::NONE, autoload: false,
    reason: "always registered by af_netlink itself; netlink_create checks no capability, \
             so EPERM is seccomp or an LSM and EPROTONOSUPPORT cannot be absence");

protocol!(SOCK_DIAG, sock_diag, "netlink.protocol.sock_diag", libc::NETLINK_SOCK_DIAG,
    "socket(AF_NETLINK, SOCK_RAW, NETLINK_SOCK_DIAG): socket enumeration (ss, inet_diag)",
    kernel: CONFIG_GATED_PROTOCOL, autoload: false,
    reason: "sock_diag registers the handler at init where CONFIG_INET_DIAG or unix_diag is \
             built; EPERM is seccomp or an LSM after the hook; EPROTONOSUPPORT is absence");

protocol!(NFLOG, nflog, "netlink.protocol.nflog", libc::NETLINK_NFLOG,
    "socket(AF_NETLINK, SOCK_RAW, NETLINK_NFLOG): the legacy netfilter log protocol",
    kernel: CONFIG_GATED_PROTOCOL, autoload: true,
    reason: "no in-tree handler since ipt_ULOG was removed; netlink_create asks for \
             net-pf-16-proto-5 and answers EPROTONOSUPPORT when nothing registers, which \
             is absence. EPERM is seccomp or an LSM after the hook");

protocol!(XFRM, xfrm, "netlink.protocol.xfrm", libc::NETLINK_XFRM,
    "socket(AF_NETLINK, SOCK_RAW, NETLINK_XFRM): IPsec transform configuration",
    kernel: CONFIG_GATED_PROTOCOL, autoload: true,
    reason: "xfrm_user registers the handler; netlink_create loads net-pf-16-proto-6 with \
             no capability check (CAP_NET_ADMIN is on sendmsg). EPERM is seccomp or an LSM; \
             EPROTONOSUPPORT is xfrm_user absent");

protocol!(SELINUX, selinux, "netlink.protocol.selinux", libc::NETLINK_SELINUX,
    "socket(AF_NETLINK, SOCK_RAW, NETLINK_SELINUX): SELinux event notifications",
    kernel: CONFIG_GATED_PROTOCOL, autoload: false,
    reason: "selnl_init registers the handler only when SELinux is built and enabled; on an \
             AppArmor cell EPROTONOSUPPORT is that absence. EPERM is seccomp or an LSM");

protocol!(ISCSI, iscsi, "netlink.protocol.iscsi", libc::NETLINK_ISCSI,
    "socket(AF_NETLINK, SOCK_RAW, NETLINK_ISCSI): the open-iSCSI transport",
    kernel: CONFIG_GATED_PROTOCOL, autoload: true,
    reason: "scsi_transport_iscsi registers the handler; netlink_create loads \
             net-pf-16-proto-8 with no capability check. EPERM is seccomp or an LSM; \
             EPROTONOSUPPORT is the module absent");

protocol!(AUDIT, audit, "netlink.protocol.audit", libc::NETLINK_AUDIT,
    "socket(AF_NETLINK, SOCK_RAW, NETLINK_AUDIT): the audit subsystem",
    kernel: CONFIG_GATED_PROTOCOL, autoload: false,
    reason: "audit_init registers the handler where CONFIG_AUDIT=y; creating the socket \
             checks nothing (CAP_AUDIT_READ/WRITE/CONTROL are checked in audit_receive). \
             EPERM is seccomp or an LSM; EPROTONOSUPPORT is absence");

protocol!(FIB_LOOKUP, fib_lookup, "netlink.protocol.fib_lookup", libc::NETLINK_FIB_LOOKUP,
    "socket(AF_NETLINK, SOCK_RAW, NETLINK_FIB_LOOKUP): route lookups from user space",
    kernel: CONFIG_GATED_PROTOCOL, autoload: false,
    reason: "nl_fib_lookup_init registers the handler per network namespace where \
             CONFIG_IP_MULTIPLE_TABLES=y; EPERM is seccomp or an LSM; EPROTONOSUPPORT \
             is absence");

protocol!(CONNECTOR, connector, "netlink.protocol.connector", libc::NETLINK_CONNECTOR,
    "socket(AF_NETLINK, SOCK_RAW, NETLINK_CONNECTOR): the kernel connector (proc events)",
    kernel: CONFIG_GATED_PROTOCOL, autoload: true,
    reason: "cn registers the handler; netlink_create loads net-pf-16-proto-11 with no \
             capability check. EPERM is seccomp or an LSM; EPROTONOSUPPORT is absence");

protocol!(NETFILTER, netfilter, "netlink.protocol.netfilter", libc::NETLINK_NETFILTER,
    "socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER): nfnetlink, the nf_tables entry point",
    kernel: CONFIG_GATED_PROTOCOL, autoload: true,
    reason: "nfnetlink registers the handler; netlink_create loads net-pf-16-proto-12 with \
             no capability check (CAP_NET_ADMIN is on the messages). EPERM is seccomp or \
             an LSM; EPROTONOSUPPORT is nfnetlink absent");

protocol!(KOBJECT_UEVENT, kobject_uevent, "netlink.protocol.kobject_uevent",
    libc::NETLINK_KOBJECT_UEVENT,
    "socket(AF_NETLINK, SOCK_RAW, NETLINK_KOBJECT_UEVENT): device hotplug events",
    kernel: CONFIG_GATED_PROTOCOL, autoload: false,
    reason: "kobject_uevent_init registers the handler per network namespace where \
             CONFIG_NET=y; no capability to create, none to listen. EPERM is seccomp or \
             an LSM; EPROTONOSUPPORT is absence");

protocol!(GENERIC, generic, "netlink.protocol.generic", libc::NETLINK_GENERIC,
    "socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC): generic netlink, every modern family's bus",
    kernel: KernelDependency::NONE, autoload: false,
    reason: "genl_init registers the handler in every supported kernel; EPERM is seccomp or \
             an LSM after the hook, and EPROTONOSUPPORT cannot be absence");

protocol!(SCSITRANSPORT, scsitransport, "netlink.protocol.scsitransport",
    libc::NETLINK_SCSITRANSPORT,
    "socket(AF_NETLINK, SOCK_RAW, NETLINK_SCSITRANSPORT): the SCSI transport netlink",
    kernel: CONFIG_GATED_PROTOCOL, autoload: false,
    reason: "scsi_netlink_init registers the handler where CONFIG_SCSI_NETLINK=y (a \
             dependency of the FC transport); EPERM is seccomp or an LSM; EPROTONOSUPPORT \
             is absence");

protocol!(RDMA, rdma, "netlink.protocol.rdma", libc::NETLINK_RDMA,
    "socket(AF_NETLINK, SOCK_RAW, NETLINK_RDMA): the RDMA subsystem's netlink",
    kernel: CONFIG_GATED_PROTOCOL, autoload: true,
    reason: "ib_core registers the handler; netlink_create loads net-pf-16-proto-20 with no \
             capability check. EPERM is seccomp or an LSM; EPROTONOSUPPORT is absence");

protocol!(CRYPTO, crypto, "netlink.protocol.crypto", libc::NETLINK_CRYPTO,
    "socket(AF_NETLINK, SOCK_RAW, NETLINK_CRYPTO): the crypto user configuration API",
    kernel: CONFIG_GATED_PROTOCOL, autoload: true,
    reason: "crypto_user registers the handler; netlink_create loads net-pf-16-proto-21 with \
             no capability check (CAP_NET_ADMIN is on the messages). EPERM is seccomp or \
             an LSM; EPROTONOSUPPORT is crypto_user absent");

protocol!(SMC, smc, "netlink.protocol.smc", NETLINK_SMC,
    "socket(AF_NETLINK, SOCK_RAW, NETLINK_SMC): the SMC protocol's netlink",
    kernel: CONFIG_GATED_PROTOCOL, autoload: true,
    reason: "smc registers the handler; netlink_create loads net-pf-16-proto-22 with no \
             capability check. EPERM is seccomp or an LSM; EPROTONOSUPPORT is absence");

fn out_of_range() -> RawResult {
    netlink(MAX_LINKS)
}

/// Reach of the netlink family with an answer produced after the hook:
/// the post-hook oracle that makes an `EPERM` on the protocol probes
/// readable.
pub const OUT_OF_RANGE_PROTOCOL: Probe = Probe {
    id: "netlink.protocol.out_of_range",
    family: "netlink",
    description:
        "socket(AF_NETLINK, SOCK_RAW, 32): a protocol at MAX_LINKS, guaranteed EPROTONOSUPPORT",
    risk: ONE_CALL,
    arch: Applicability::All,
    kernel: KernelDependency::NONE,
    oracle: Oracle {
        guarantees: Some(Errno::EPROTONOSUPPORT),
        isolates: Isolates::SeccompOrLsm,
        reason: "netlink_create rejects a protocol at or beyond MAX_LINKS before looking for a \
                 handler, but after security_socket_create and the family lookup: \
                 EPROTONOSUPPORT here proves the netlink family itself is reachable, and \
                 EPERM instead is seccomp or an LSM, not separable",
    },
    capability: None,
    effects: SideEffects::NONE,
    run: out_of_range,
};
