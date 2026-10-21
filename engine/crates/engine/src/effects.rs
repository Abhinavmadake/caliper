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

//! Side-effect declaration (#9): what a probe creates and how it is
//! reclaimed (`spec/probe.md`), enforced by the engine rather than left to
//! convention (§12).
//!
//! Every probe carries a [`SideEffects`]. The compiler makes the field
//! mandatory, but a mandatory field is satisfied cheapest by
//! [`SideEffects::NONE`], and a lazy `NONE` is byte-identical to a
//! considered one — a declaration that looks audited and is not. So the
//! default is [`SideEffects::Undeclared`]: cheaper to write than a lie,
//! refused by the engine (the probe is not run, and reported), and refused
//! by the corpus crate's own test, which is the merge gate. An author who
//! clones a neighbouring probe and inherits its declaration wholesale is
//! the failure this cannot catch; `..Default::default()` at least makes
//! the honest shortcut the easy one.

use serde::{Serialize, Serializer};

/// The classes of kernel object that outlive a process, and so are the
/// only ones fork isolation does not reclaim (§6.2). Measured directly,
/// each from its own interface, never by whole-host comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResidualClass {
    /// Entries in the mount table (`/proc/self/mountinfo`).
    Mounts,
    /// Keys this process may view (`/proc/keys`): the session and user
    /// keyrings' contents and whatever else is visible — a superset, and
    /// the whole file is masked under RuntimeDefault.
    Keyrings,
    /// Directories under the cgroup subtree this process can see.
    Cgroups,
    /// System V shared memory, semaphores and message queues
    /// (`/proc/sysvipc/*`).
    SysvIpc,
    /// POSIX shared memory and message queues (`/dev/shm`, `/dev/mqueue`).
    PosixIpc,
    /// Distinct network namespaces held by processes this one can see.
    NetNamespaces,
}

impl ResidualClass {
    pub const ALL: [ResidualClass; 6] = [
        ResidualClass::Mounts,
        ResidualClass::Keyrings,
        ResidualClass::Cgroups,
        ResidualClass::SysvIpc,
        ResidualClass::PosixIpc,
        ResidualClass::NetNamespaces,
    ];

    pub fn index(self) -> usize {
        self as usize
    }

    /// The class as an object key. Values are kebab-case and keys are
    /// snake_case (`spec/fingerprint.md`, conventions) — the same name in
    /// the two positions is spelled two ways, on purpose.
    pub fn key(self) -> &'static str {
        match self {
            ResidualClass::Mounts => "mounts",
            ResidualClass::Keyrings => "keyrings",
            ResidualClass::Cgroups => "cgroups",
            ResidualClass::SysvIpc => "sysv_ipc",
            ResidualClass::PosixIpc => "posix_ipc",
            ResidualClass::NetNamespaces => "net_namespaces",
        }
    }
}

/// A probe's declaration.
///
/// Descriptor-shaped effects — sockets, rings, BPF objects, userfaultfd,
/// perf events — are not declared: the child's exit reclaims them, which is
/// what fork isolation is for. What is declared is the rest.
///
/// There is no rollback hook. A parent-side rollback runs under a
/// different view of the filters than the child, so it can succeed in
/// exactly the ways the probe could not, masking the asymmetry the corpus
/// exists to measure; and a rollback that ran before the snapshot would
/// hide the residual, while one that ran after is hygiene the finding
/// already did. The child owns what it creates and removes it before
/// returning. Where it cannot — killed first, or the filter permits create
/// and blocks remove — the object is measured, reported against this probe,
/// and the end-of-run janitor removes what it recognises as this run's
/// ([`posix_ipc_name`], [`sysv_ipc_key`]), loudly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SideEffects {
    /// Not yet considered. The engine refuses to run the probe.
    #[default]
    Undeclared,
    Declared {
        /// The residual classes this probe may touch. Empty means every
        /// effect is descriptor-shaped.
        residual: &'static [ResidualClass],
        /// The probe can make the kernel autoload a module: an unregistered
        /// socket family, netlink protocol or AF_ALG algorithm type. Neither
        /// reclaimable nor rolled back; the engine reports it from the
        /// before/after module snapshot, separately from residual state.
        module_autoload: bool,
    },
}

impl SideEffects {
    /// Considered, and found to be descriptor-shaped only.
    pub const NONE: SideEffects = SideEffects::Declared {
        residual: &[],
        module_autoload: false,
    };

    pub fn is_declared(&self) -> bool {
        !matches!(self, SideEffects::Undeclared)
    }

    pub fn declares(&self, class: ResidualClass) -> bool {
        match self {
            SideEffects::Undeclared => false,
            SideEffects::Declared { residual, .. } => residual.contains(&class),
        }
    }

    pub fn may_autoload_module(&self) -> bool {
        matches!(
            self,
            SideEffects::Declared {
                module_autoload: true,
                ..
            }
        )
    }
}

/// `Undeclared` serialises as `null`: the one meaning of absence across the
/// record — the producer did not know.
impl Serialize for SideEffects {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Declared<'a> {
            residual: &'a [ResidualClass],
            module_autoload: bool,
        }
        match self {
            SideEffects::Undeclared => s.serialize_none(),
            SideEffects::Declared {
                residual,
                module_autoload,
            } => s.serialize_some(&Declared {
                residual,
                module_autoload: *module_autoload,
            }),
        }
    }
}

/// Name prefix for any POSIX shared memory object or message queue a probe
/// creates. The full prefix carries the run (the engine's pid, which a
/// probe reads as its parent's): [`posix_ipc_name`].
pub const POSIX_IPC_PREFIX: &str = "caliper-";

/// System V IPC keys: each run owns the block of [`SYSV_IPC_KEYS`] keys
/// [`sysv_ipc_key`] picks by its pid, so the janitor of one run leaves a
/// concurrent run's objects alone (#99). Two runs collide only when their
/// pids are equal modulo 256. `IPC_PRIVATE` objects cannot be told from
/// anyone else's and are not janitored.
pub const SYSV_IPC_KEY_BASE: i32 = 0x4341_0000; // "CA\0\0"
pub const SYSV_IPC_KEYS: i32 = 256;

/// The name for POSIX object `name` in run `run`.
pub fn posix_ipc_name(run: u32, name: &str) -> String {
    format!("{POSIX_IPC_PREFIX}{run}-{name}")
}

/// Directory under which run `run`'s probes mount, named like its POSIX
/// objects so the janitor can recognise a leftover one (#96).
pub fn mount_dir(run: u32) -> String {
    format!("{MOUNT_DIR_PARENT}{}", posix_ipc_name(run, "mount"))
}

/// The writable directory the probe image carries for [`mount_dir`].
pub const MOUNT_DIR_PARENT: &str = "/tmp/";

/// Key `n` (below [`SYSV_IPC_KEYS`]) of run `run`'s block.
pub fn sysv_ipc_key(run: u32, n: i32) -> i32 {
    SYSV_IPC_KEY_BASE + (run % 256) as i32 * SYSV_IPC_KEYS + n
}

pub fn is_instrument_sysv_key(run: u32, key: i32) -> bool {
    let first = sysv_ipc_key(run, 0);
    (first..first + SYSV_IPC_KEYS).contains(&key)
}
