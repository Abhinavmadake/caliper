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

//! Socket address families and netlink protocol numbers (`corpus/README.md`,
//! committed set). The hook order these oracles rest on, from
//! `net/socket.c`: `__sys_socket_create` rejects unknown type flags with
//! `EINVAL`; `__sock_create` rejects a family outside `0..NPROTO` with
//! `EAFNOSUPPORT` and an out-of-range type with `EINVAL`, *then* calls
//! `security_socket_create`, *then* looks the family up (autoloading a
//! module for an in-range family with none registered) and lets the
//! family's own `create` run its capability checks. So an answer produced
//! before the hook isolates seccomp; one produced after it does not.
//!
//! Raw `SYS_socket` throughout: musl's `socket()` retries without
//! `SOCK_CLOEXEC` on `EINVAL`, which would put a second call between the
//! oracle and the record.

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

fn netlink_route() -> RawResult {
    socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE)
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

/// A netlink protocol every kernel builds: the family-level control for
/// the netlink probes that follow in the committed set.
pub const NETLINK_ROUTE: Probe = Probe {
    id: "netlink.protocol.route",
    family: "netlink",
    description: "socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE): rtnetlink is reachable",
    risk: ONE_CALL,
    arch: Applicability::All,
    kernel: KernelDependency::NONE,
    oracle: Oracle {
        guarantees: None,
        isolates: Isolates::SeccompOrLsm,
        reason: "netlink_create checks the protocol number after security_socket_create and \
                 after the family lookup, so EPERM is seccomp or an LSM; NETLINK_ROUTE is \
                 built into every supported kernel, so EPROTONOSUPPORT cannot be absence",
    },
    capability: None,
    effects: SideEffects::NONE,
    run: netlink_route,
};
