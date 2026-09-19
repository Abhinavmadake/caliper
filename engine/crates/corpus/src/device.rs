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

//! Device-node reachability (`corpus/README.md`, committed set).
//!
//! The probe image runs as uid 65534. Each probe uses `openat` with
//! `O_RDONLY | O_NONBLOCK | O_NOCTTY | O_CLOEXEC`, then returns without reading
//! or writing the descriptor. A successful descriptor is reclaimed when the
//! forked probe child exits. The selected world-readable nodes can reach the
//! device cgroup; DAC-gated nodes deliberately record that earlier mechanism.

use std::ffi::CStr;

use caliper_engine::{
    Applicability, Capability, Errno, Isolates, KernelDependency, Oracle, Probe, RawResult,
    SideEffects,
};

use crate::common::ONE_CALL;

const FLAGS: libc::c_int = libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC;

fn open_ro(path: &CStr) -> RawResult {
    let fd = unsafe { libc::syscall(libc::SYS_openat, libc::AT_FDCWD, path.as_ptr(), FLAGS, 0) };
    if fd < 0 {
        Err(Errno::last())
    } else {
        Ok(())
    }
}

macro_rules! device_probe {
    ($function:ident, $path:expr) => {
        fn $function() -> RawResult {
            open_ro($path)
        }
    };
}

device_probe!(open_fuse, c"/dev/fuse");
device_probe!(open_net_tun, c"/dev/net/tun");
device_probe!(open_kvm, c"/dev/kvm");
device_probe!(open_kmsg, c"/dev/kmsg");
device_probe!(open_mem, c"/dev/mem");
device_probe!(open_port, c"/dev/port");
device_probe!(open_null, c"/dev/null");
device_probe!(open_sda, c"/dev/sda");

macro_rules! define_probe {
    ($constant:ident, $function:ident, $id:literal, $description:literal, $capability:expr) => {
        pub const $constant: Probe = Probe {
            id: $id,
            family: "device",
            description: $description,
            risk: ONE_CALL,
            arch: Applicability::All,
            kernel: KernelDependency::NONE,
            oracle: Oracle {
                guarantees: None,
                isolates: Isolates::Undecidable,
                reason: "openat(O_RDONLY | O_NONBLOCK | O_NOCTTY | O_CLOEXEC) does not read or write: ENOENT means the runtime did not provision the node; EACCES is nodev, DAC, or an LSM; after DAC permits the read-open, EPERM is the device cgroup or the driver's own capability check",
            },
            capability: $capability,
            effects: SideEffects::NONE,
            run: $function,
        };
    };
}

define_probe!(
    OPEN_FUSE,
    open_fuse,
    "device.open.fuse",
    "/dev/fuse (10:229, typically 0666): read-only nonblocking open",
    None
);
define_probe!(
    OPEN_NET_TUN,
    open_net_tun,
    "device.open.net_tun",
    "/dev/net/tun (10:200, typically 0666): read-only nonblocking open",
    None
);
define_probe!(
    OPEN_KVM,
    open_kvm,
    "device.open.kvm",
    "/dev/kvm (10:232, typically 0660 root:kvm): DAC-gated read-only nonblocking open",
    None
);
define_probe!(
    OPEN_KMSG,
    open_kmsg,
    "device.open.kmsg",
    "/dev/kmsg (1:11, typically 0644): read-only nonblocking open",
    None
);
define_probe!(
    OPEN_MEM,
    open_mem,
    "device.open.mem",
    "/dev/mem (1:1, typically 0640 root:kmem): DAC-gated read-only nonblocking open",
    Some(Capability::SysRawio)
);
define_probe!(
    OPEN_PORT,
    open_port,
    "device.open.port",
    "/dev/port (1:4, typically 0640 root:kmem): DAC-gated read-only nonblocking open",
    Some(Capability::SysRawio)
);
define_probe!(
    OPEN_NULL,
    open_null,
    "device.open.null",
    "/dev/null (1:3, typically 0666): control read-only nonblocking open",
    None
);
define_probe!(
    OPEN_SDA,
    open_sda,
    "device.open.sda",
    "/dev/sda (8:0, typically 0660 root:disk): DAC-gated read-only nonblocking open",
    None
);
