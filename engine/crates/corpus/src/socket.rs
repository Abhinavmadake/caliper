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

//! Socket address families (`corpus/README.md`, committed set; #11). The
//! hook order these oracles rest on, from `net/socket.c`:
//! `__sys_socket_create` rejects unknown type flags with `EINVAL`;
//! `__sock_create` rejects a family outside `0..NPROTO` with `EAFNOSUPPORT`
//! and an out-of-range type with `EINVAL`, *then* calls
//! `security_socket_create`, *then* looks the family up — asking the kernel
//! to load `net-pf-<N>` if nothing is registered, with no capability check
//! on the caller — and lets the family's own `create` run its checks. So an
//! answer produced before the hook isolates seccomp; one produced after it
//! does not.
//!
//! Three answers after the hook, and what they are:
//!
//! - `EAFNOSUPPORT` from the family lookup is the family absent from this
//!   kernel, or its module not loadable: `unimplemented`, and the module
//!   snapshot shows which. Several families also answer `EAFNOSUPPORT` from
//!   their own `create` when the caller is not in the initial network
//!   namespace (`if (!net_eq(net, &init_net))`): AX.25, AppleTalk, X.25,
//!   IEEE 802.15.4. Inside a container that is the answer every time, and it
//!   is indistinguishable from absence by errno alone — the module having
//!   loaded (`module_delta`) is what separates them, which is the
//!   attributor's job, not this file's. The `reason` on each says so.
//! - `EPERM` from the family's `create` is its own capability check
//!   (`AF_PACKET`, `AF_KEY`, `AF_XDP`): undecidable from a filter, and the
//!   capability field is the correlate.
//! - `ESOCKTNOSUPPORT` / `EPROTONOSUPPORT` from `create` is a type or
//!   protocol the family does not offer: an argument mistake in this file,
//!   never a policy finding; the argument sets below are chosen so it does
//!   not happen.
//!
//! Every family probe here is one `socket(2)` call; the descriptor is the
//! only effect and the child's exit reclaims it. Where the family is a
//! module, `module_autoload` is declared. Raw `SYS_socket` throughout:
//! musl's `socket()` retries without `SOCK_CLOEXEC` on `EINVAL`, which
//! would put a second call between the oracle and the record.
//!
//! The netlink protocol numbers are `netlink.rs`.

use caliper_engine::{
    Applicability, Capability, Errno, Isolates, KernelDependency, Oracle, Probe, RawResult,
    SideEffects,
};

use crate::common::{result, ONE_CALL};

fn socket(family: libc::c_int, ty: libc::c_int, protocol: libc::c_int) -> RawResult {
    // SAFETY: three integer arguments; a descriptor is the only effect and
    // the child's exit reclaims it.
    result(unsafe { libc::syscall(libc::SYS_socket, family, ty, protocol) })
}

fn af_alg() -> RawResult {
    socket(libc::AF_ALG, libc::SOCK_SEQPACKET, 0)
}

fn af_inet() -> RawResult {
    socket(libc::AF_INET, libc::SOCK_STREAM, 0)
}

fn af_packet() -> RawResult {
    socket(libc::AF_PACKET, libc::SOCK_RAW, 0)
}

/// Well past `NPROTO` (46 in every supported kernel) and small enough that a
/// filter matching on the family argument still sees a plausible integer.
const OUT_OF_RANGE: libc::c_int = 1000;

fn out_of_range() -> RawResult {
    socket(OUT_OF_RANGE, libc::SOCK_STREAM, 0)
}

/// A family this kernel may not build: `EAFNOSUPPORT` from the family
/// lookup is absence, not policy. Configuration-gated, so no version.
const CONFIG_GATED_FAMILY: KernelDependency = KernelDependency {
    since: None,
    absent_errno: Some(Errno::EAFNOSUPPORT),
};

/// The motivating case (CVE-2026-31431): `RuntimeDefault` permits this.
pub const AF_ALG: Probe = Probe {
    id: "socket.family.af_alg",
    family: "socket",
    description: "socket(AF_ALG, SOCK_SEQPACKET, 0): the crypto user API is reachable",
    risk: ONE_CALL,
    arch: Applicability::All,
    kernel: CONFIG_GATED_FAMILY,
    oracle: Oracle {
        guarantees: None,
        isolates: Isolates::SeccompOrLsm,
        reason: "security_socket_create runs before the family lookup in __sock_create, so \
                 EPERM is seccomp or an LSM; EAFNOSUPPORT is the family absent from this \
                 kernel (CONFIG_CRYPTO_USER_API) or its module not loadable, which is \
                 unimplemented",
    },
    capability: None,
    effects: SideEffects::Declared {
        residual: &[],
        // net-pf-38: the af_alg module, on a node that permits autoload.
        module_autoload: true,
    },
    run: af_alg,
};

/// The control: a family every cell permits.
pub const AF_INET: Probe = Probe {
    id: "socket.family.af_inet",
    family: "socket",
    description: "socket(AF_INET, SOCK_STREAM, 0): the family every workload uses",
    risk: ONE_CALL,
    arch: Applicability::All,
    kernel: KernelDependency::NONE,
    oracle: Oracle {
        guarantees: None,
        isolates: Isolates::SeccompOrLsm,
        reason: "security_socket_create runs before the family lookup in __sock_create, so \
                 EPERM is seccomp or an LSM; AF_INET is built into every supported kernel",
    },
    capability: None,
    effects: SideEffects::NONE,
    run: af_inet,
};

/// Capability effect: the family's own `create` answers `EPERM` for a
/// caller without `CAP_NET_RAW`, which is what a filter answers too.
pub const AF_PACKET: Probe = Probe {
    id: "socket.family.af_packet",
    family: "socket",
    description: "socket(AF_PACKET, SOCK_RAW, 0): raw link-layer access, CAP_NET_RAW",
    risk: ONE_CALL,
    arch: Applicability::All,
    kernel: CONFIG_GATED_FAMILY,
    oracle: Oracle {
        guarantees: None,
        isolates: Isolates::Undecidable,
        reason: "packet_create checks CAP_NET_RAW after security_socket_create and answers \
                 EPERM itself, so EPERM is seccomp, an LSM, or the capability absent from \
                 the effective set; the capability field is the correlate. An LSM that \
                 denies the family answers EACCES",
    },
    capability: Some(Capability::NetRaw),
    effects: SideEffects::NONE,
    run: af_packet,
};

/// Reachability of `socket(2)` itself, with an answer produced before the
/// hook: the seccomp-isolating oracle for the family.
pub const OUT_OF_RANGE_FAMILY: Probe = Probe {
    id: "socket.family.out_of_range",
    family: "socket",
    description: "socket(1000, SOCK_STREAM, 0): a family beyond NPROTO, guaranteed EAFNOSUPPORT",
    risk: ONE_CALL,
    arch: Applicability::All,
    kernel: KernelDependency::NONE,
    oracle: Oracle {
        guarantees: Some(Errno::EAFNOSUPPORT),
        isolates: Isolates::Seccomp,
        reason: "__sock_create rejects a family at or beyond NPROTO with EAFNOSUPPORT before \
                 security_socket_create and before the family table is consulted; only a \
                 filter at syscall entry can answer EPERM first",
    },
    capability: None,
    effects: SideEffects::NONE,
    run: out_of_range,
};

/// Families the libc crate does not name for the musl targets
/// (`include/linux/socket.h`).
const PF_KCM: libc::c_int = 41;
const PF_QIPCRTR: libc::c_int = 42;
const PF_SMC: libc::c_int = 43;
const PF_MCTP: libc::c_int = 45;
/// `PF_KEY_V2`, the only protocol `AF_KEY` accepts (`include/uapi/linux/pfkeyv2.h`).
const PF_KEY_V2: libc::c_int = 2;
/// `BTPROTO_RFCOMM` (`include/net/bluetooth/bluetooth.h`): the one
/// Bluetooth protocol an unprivileged caller may open a socket for.
const BTPROTO_RFCOMM: libc::c_int = 3;
/// `CAN_RAW` (`include/uapi/linux/can.h`).
const CAN_RAW: libc::c_int = 1;

/// A family probe: one `socket(2)` call whose success is the guaranteed
/// answer when nothing intercepts it. `$kernel` says what `EAFNOSUPPORT`
/// means, `$isolates` what `EPERM` can be pinned to, `$autoload` whether the
/// family is a module the call can make the kernel load.
macro_rules! family {
    ($konst:ident, $f:ident, $id:literal, ($af:expr, $ty:expr, $proto:expr),
     $desc:literal, kernel: $kernel:expr, isolates: $isolates:expr,
     capability: $cap:expr, autoload: $autoload:expr, reason: $reason:literal) => {
        fn $f() -> RawResult {
            socket($af, $ty, $proto)
        }
        pub const $konst: Probe = Probe {
            id: $id,
            family: "socket",
            description: $desc,
            risk: ONE_CALL,
            arch: Applicability::All,
            kernel: $kernel,
            oracle: Oracle {
                guarantees: None,
                isolates: $isolates,
                reason: $reason,
            },
            capability: $cap,
            effects: SideEffects::Declared {
                residual: &[],
                module_autoload: $autoload,
            },
            run: $f,
        };
    };
}

family!(AF_UNIX, af_unix, "socket.family.af_unix",
    (libc::AF_UNIX, libc::SOCK_STREAM, 0),
    "socket(AF_UNIX, SOCK_STREAM, 0): the local family every runtime needs",
    kernel: KernelDependency::NONE, isolates: Isolates::SeccompOrLsm,
    capability: None, autoload: false,
    reason: "unix_create runs after security_socket_create and checks nothing; EPERM is \
             seccomp or an LSM. Built into every kernel: EAFNOSUPPORT cannot be absence");

family!(AF_INET6, af_inet6, "socket.family.af_inet6",
    (libc::AF_INET6, libc::SOCK_STREAM, 0),
    "socket(AF_INET6, SOCK_STREAM, 0): IPv6 is reachable",
    kernel: CONFIG_GATED_FAMILY, isolates: Isolates::SeccompOrLsm,
    capability: None, autoload: true,
    reason: "inet6_create runs after security_socket_create; EPERM is seccomp or an LSM. \
             EAFNOSUPPORT is CONFIG_IPV6=n, ipv6.disable=1, or the ipv6 module not loadable \
             (net-pf-10): absence, not policy");

family!(AF_KEY, af_key, "socket.family.af_key",
    (libc::AF_KEY, libc::SOCK_RAW, PF_KEY_V2),
    "socket(AF_KEY, SOCK_RAW, PF_KEY_V2): the IPsec key management interface, CAP_NET_ADMIN",
    kernel: CONFIG_GATED_FAMILY, isolates: Isolates::Undecidable,
    capability: Some(Capability::NetAdmin), autoload: true,
    reason: "pfkey_create checks ns_capable(CAP_NET_ADMIN) first and answers EPERM itself, \
             after security_socket_create and the family lookup; nothing separates a filter \
             from the missing capability. EAFNOSUPPORT is af_key absent (net-pf-15)");

family!(AF_BLUETOOTH_RFCOMM, af_bluetooth_rfcomm, "socket.family.af_bluetooth",
    (libc::AF_BLUETOOTH, libc::SOCK_STREAM, BTPROTO_RFCOMM),
    "socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM): the Bluetooth stack is reachable",
    kernel: CONFIG_GATED_FAMILY, isolates: Isolates::SeccompOrLsm,
    capability: None, autoload: true,
    reason: "bt_sock_create runs after security_socket_create, loads bt-proto-3 (rfcomm) if \
             unregistered, and rfcomm_sock_create checks no capability for SOCK_STREAM; \
             EPERM is seccomp or an LSM. EAFNOSUPPORT is bluetooth absent (net-pf-31); \
             EPROTONOSUPPORT is rfcomm absent with the family present");

family!(AF_CAN_RAW, af_can_raw, "socket.family.af_can",
    (libc::AF_CAN, libc::SOCK_RAW, CAN_RAW),
    "socket(AF_CAN, SOCK_RAW, CAN_RAW): the CAN bus stack is reachable",
    kernel: CONFIG_GATED_FAMILY, isolates: Isolates::SeccompOrLsm,
    capability: None, autoload: true,
    reason: "can_create runs after security_socket_create, loads can-proto-1 (can_raw) if \
             unregistered, and raw_init checks no capability; EPERM is seccomp or an LSM. \
             EAFNOSUPPORT is can absent (net-pf-29); EPROTONOSUPPORT is can_raw absent");

family!(AF_TIPC, af_tipc, "socket.family.af_tipc",
    (libc::AF_TIPC, libc::SOCK_RDM, 0),
    "socket(AF_TIPC, SOCK_RDM, 0): the TIPC cluster stack is reachable",
    kernel: CONFIG_GATED_FAMILY, isolates: Isolates::SeccompOrLsm,
    capability: None, autoload: true,
    reason: "tipc_sk_create runs after security_socket_create and checks no capability; \
             EPERM is seccomp or an LSM. EAFNOSUPPORT is tipc absent (net-pf-30)");

family!(AF_RDS, af_rds, "socket.family.af_rds",
    (libc::AF_RDS, libc::SOCK_SEQPACKET, 0),
    "socket(AF_RDS, SOCK_SEQPACKET, 0): Reliable Datagram Sockets are reachable",
    kernel: CONFIG_GATED_FAMILY, isolates: Isolates::SeccompOrLsm,
    capability: None, autoload: true,
    reason: "rds_create runs after security_socket_create and checks no capability; EPERM \
             is seccomp or an LSM. EAFNOSUPPORT is rds absent (net-pf-21)");

family!(AF_XDP, af_xdp, "socket.family.af_xdp",
    (libc::AF_XDP, libc::SOCK_RAW, 0),
    "socket(AF_XDP, SOCK_RAW, 0): AF_XDP zero-copy sockets, CAP_NET_RAW",
    kernel: CONFIG_GATED_FAMILY, isolates: Isolates::Undecidable,
    capability: Some(Capability::NetRaw), autoload: false,
    reason: "xsk_create checks ns_capable(CAP_NET_RAW) first and answers EPERM itself, after \
             security_socket_create; nothing separates a filter from the missing \
             capability. Built in where CONFIG_XDP_SOCKETS=y: EAFNOSUPPORT is absence");

family!(AF_RXRPC, af_rxrpc, "socket.family.af_rxrpc",
    (libc::AF_RXRPC, libc::SOCK_DGRAM, libc::PF_INET),
    "socket(AF_RXRPC, SOCK_DGRAM, PF_INET): the RxRPC transport is reachable",
    kernel: CONFIG_GATED_FAMILY, isolates: Isolates::SeccompOrLsm,
    capability: None, autoload: true,
    reason: "rxrpc_create runs after security_socket_create and checks no capability; \
             EPERM is seccomp or an LSM. EAFNOSUPPORT is rxrpc absent (net-pf-33)");

family!(AF_PHONET, af_phonet, "socket.family.af_phonet",
    (libc::AF_PHONET, libc::SOCK_DGRAM, 0),
    "socket(AF_PHONET, SOCK_DGRAM, 0): the Phonet stack, CAP_SYS_ADMIN",
    kernel: CONFIG_GATED_FAMILY, isolates: Isolates::Undecidable,
    capability: Some(Capability::SysAdmin), autoload: true,
    reason: "pn_socket_create checks capable(CAP_SYS_ADMIN) first, for every socket type, \
             and answers EPERM itself, after security_socket_create and the family lookup; \
             nothing separates a filter from the missing capability. EAFNOSUPPORT is \
             phonet absent (net-pf-35), or a network namespace other than the initial one");

family!(AF_IEEE802154, af_ieee802154, "socket.family.af_ieee802154",
    (libc::AF_IEEE802154, libc::SOCK_DGRAM, 0),
    "socket(AF_IEEE802154, SOCK_DGRAM, 0): the 802.15.4 stack is reachable",
    kernel: CONFIG_GATED_FAMILY, isolates: Isolates::SeccompOrLsm,
    capability: None, autoload: true,
    reason: "ieee802154_create answers EAFNOSUPPORT for any network namespace but the initial \
             one, after the family lookup has loaded af_802154 (net-pf-36): inside a \
             container the errno is the same as absence and the module snapshot is what \
             tells them apart. EPERM is seccomp or an LSM; SOCK_RAW would need CAP_NET_RAW");

family!(AF_NFC, af_nfc, "socket.family.af_nfc",
    (libc::AF_NFC, libc::SOCK_STREAM, 1),
    "socket(AF_NFC, SOCK_STREAM, NFC_SOCKPROTO_LLCP): the NFC stack is reachable",
    kernel: CONFIG_GATED_FAMILY, isolates: Isolates::SeccompOrLsm,
    capability: None, autoload: true,
    reason: "nfc_sock_create runs after security_socket_create; the LLCP protocol checks no \
             capability (raw would need CAP_NET_RAW). EPERM is seccomp or an LSM. \
             EAFNOSUPPORT is nfc absent (net-pf-39)");

family!(AF_VSOCK, af_vsock, "socket.family.af_vsock",
    (libc::AF_VSOCK, libc::SOCK_STREAM, 0),
    "socket(AF_VSOCK, SOCK_STREAM, 0): the host-guest vsock family is reachable",
    kernel: CONFIG_GATED_FAMILY, isolates: Isolates::SeccompOrLsm,
    capability: None, autoload: true,
    reason: "vsock_create runs after security_socket_create and checks no capability for \
             protocol 0; EPERM is seccomp or an LSM. EAFNOSUPPORT is vsock absent \
             (net-pf-40), the usual state on a node with no hypervisor transport");

family!(AF_KCM, af_kcm, "socket.family.af_kcm",
    (PF_KCM, libc::SOCK_DGRAM, 0),
    "socket(AF_KCM, SOCK_DGRAM, KCMPROTO_CONNECTED): kernel connection multiplexor",
    kernel: CONFIG_GATED_FAMILY, isolates: Isolates::SeccompOrLsm,
    capability: None, autoload: true,
    reason: "kcm_create runs after security_socket_create and checks no capability; EPERM \
             is seccomp or an LSM. EAFNOSUPPORT is kcm absent (net-pf-41)");

family!(AF_QIPCRTR, af_qipcrtr, "socket.family.af_qipcrtr",
    (PF_QIPCRTR, libc::SOCK_DGRAM, PF_QIPCRTR),
    "socket(AF_QIPCRTR, SOCK_DGRAM, PF_QIPCRTR): the Qualcomm IPC router is reachable",
    kernel: CONFIG_GATED_FAMILY, isolates: Isolates::SeccompOrLsm,
    capability: None, autoload: true,
    reason: "qrtr_create runs after security_socket_create and checks no capability; EPERM \
             is seccomp or an LSM. EAFNOSUPPORT is qrtr absent (net-pf-42)");

family!(AF_SMC, af_smc, "socket.family.af_smc",
    (PF_SMC, libc::SOCK_STREAM, 0),
    "socket(AF_SMC, SOCK_STREAM, SMCPROTO_SMC): shared memory communications",
    kernel: CONFIG_GATED_FAMILY, isolates: Isolates::SeccompOrLsm,
    capability: None, autoload: true,
    reason: "smc_create runs after security_socket_create and checks no capability; EPERM \
             is seccomp or an LSM. EAFNOSUPPORT is smc absent (net-pf-43)");

family!(AF_MCTP, af_mctp, "socket.family.af_mctp",
    (PF_MCTP, libc::SOCK_DGRAM, 0),
    "socket(AF_MCTP, SOCK_DGRAM, 0): the Management Component Transport Protocol",
    kernel: CONFIG_GATED_FAMILY, isolates: Isolates::SeccompOrLsm,
    capability: None, autoload: true,
    reason: "mctp_pf_create runs after security_socket_create and checks no capability; \
             EPERM is seccomp or an LSM. EAFNOSUPPORT is mctp absent (net-pf-45)");

family!(AF_AX25, af_ax25, "socket.family.af_ax25",
    (libc::AF_AX25, libc::SOCK_DGRAM, 0),
    "socket(AF_AX25, SOCK_DGRAM, 0): the amateur-radio AX.25 stack is reachable",
    kernel: CONFIG_GATED_FAMILY, isolates: Isolates::SeccompOrLsm,
    capability: None, autoload: true,
    reason: "ax25_create answers EAFNOSUPPORT outside the initial network namespace, after \
             the family lookup has loaded ax25 (net-pf-3): inside a container the errno \
             is the same as absence and the module snapshot tells them apart. EPERM is \
             seccomp or an LSM; SOCK_RAW would need CAP_NET_RAW");

family!(AF_APPLETALK, af_appletalk, "socket.family.af_appletalk",
    (libc::AF_APPLETALK, libc::SOCK_DGRAM, 0),
    "socket(AF_APPLETALK, SOCK_DGRAM, 0): the AppleTalk stack is reachable",
    kernel: CONFIG_GATED_FAMILY, isolates: Isolates::SeccompOrLsm,
    capability: None, autoload: true,
    reason: "atalk_create answers EAFNOSUPPORT outside the initial network namespace, after \
             the family lookup has loaded appletalk (net-pf-5): inside a container the \
             errno is the same as absence and the module snapshot tells them apart. EPERM \
             is seccomp or an LSM; SOCK_RAW would need CAP_NET_RAW");

family!(AF_X25, af_x25, "socket.family.af_x25",
    (libc::AF_X25, libc::SOCK_SEQPACKET, 0),
    "socket(AF_X25, SOCK_SEQPACKET, 0): the X.25 stack is reachable",
    kernel: CONFIG_GATED_FAMILY, isolates: Isolates::SeccompOrLsm,
    capability: None, autoload: true,
    reason: "x25_create answers EAFNOSUPPORT outside the initial network namespace, after \
             the family lookup has loaded x25 (net-pf-9): inside a container the errno is \
             the same as absence and the module snapshot tells them apart. EPERM is \
             seccomp or an LSM");
