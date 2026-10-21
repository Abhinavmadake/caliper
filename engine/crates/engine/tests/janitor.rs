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

//! The janitor under the asymmetric filter (#9): create permitted, remove
//! blocked. That is the case the janitor exists for, and the case in which
//! a removal made from the parent would either fail silently (`ERRNO`) or
//! take the whole run with it (`KILL_PROCESS`). Each removal is a forked
//! child, so the failure is recorded and the run survives.
//!
//! Its own binary with `harness = false`: a seccomp filter is per thread
//! and cannot be removed, and the object has to be cleaned up at the end
//! by something that still can. So a single-threaded main leaks the
//! object, forks a child that applies the filters and runs the janitor
//! under them, and then — unfiltered — removes the object itself.

#![cfg(target_os = "linux")]

use std::collections::BTreeMap;

use caliper_engine::effects::{sysv_ipc_key, ResidualClass};
use caliper_engine::harness::Outcome;
use caliper_engine::residual::{janitor, Attempt, Removal};
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;
use seccompiler::{apply_filter, BpfProgram, SeccompAction, SeccompFilter, TargetArch};

#[cfg(target_arch = "aarch64")]
const ARCH: TargetArch = TargetArch::aarch64;
#[cfg(target_arch = "x86_64")]
const ARCH: TargetArch = TargetArch::x86_64;

/// The run is this test process; the forked child below acts for it.
static RUN: std::sync::OnceLock<u32> = std::sync::OnceLock::new();

fn run() -> u32 {
    *RUN.get_or_init(std::process::id)
}

/// One key of this run's block, not shared with `effects.rs`.
fn key() -> i32 {
    sysv_ipc_key(run(), 2)
}

fn on_shmctl(action: SeccompAction) -> BpfProgram {
    let mut rules = BTreeMap::new();
    rules.insert(libc::SYS_shmctl, vec![]);
    SeccompFilter::new(rules, SeccompAction::Allow, action, ARCH)
        .unwrap()
        .try_into()
        .unwrap()
}

/// The janitor's record for our segment.
fn ours(removals: &[Removal]) -> Removal {
    let tag = format!("key {:#x}", key());
    let mut mine = removals.iter().filter(|r| r.object.contains(&tag));
    let r = mine
        .next()
        .unwrap_or_else(|| panic!("segment not listed: {removals:?}"));
    assert!(mine.next().is_none(), "listed twice: {removals:?}");
    assert_eq!(r.class, ResidualClass::SysvIpc);
    r.clone()
}

fn main() {
    caliper_engine::init().unwrap();
    run();
    // SAFETY: plain syscall with a key of our own.
    let id = unsafe { libc::shmget(key(), 4096, libc::IPC_CREAT | 0o600) };
    assert!(id >= 0, "shmget: {}", std::io::Error::last_os_error());

    // SAFETY: single-threaded; the child calls the janitor and _exit.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        filtered();
    }
    let status = waitpid(Pid::from_raw(pid), None).unwrap();
    assert_eq!(status, WaitStatus::Exited(Pid::from_raw(pid), 0));

    // Unfiltered: the same removal succeeds, and says so.
    let r = ours(&janitor(run()));
    assert!(r.removed, "{r:?}");
    assert_eq!(r.attempt, Attempt::Child(Outcome::Returned { errno: 0 }));
    assert!(
        !janitor(run())
            .iter()
            .any(|r| r.object.contains(&format!("key {:#x}", key()))),
        "the janitor left the segment"
    );
}

/// Never returns.
fn filtered() -> ! {
    // The filter answers EPERM: the segment stays, the record says so.
    apply_filter(&on_shmctl(SeccompAction::Errno(libc::EPERM as u32))).unwrap();
    let r = ours(&janitor(run()));
    assert!(!r.removed, "{r:?}");
    assert_eq!(
        r.attempt,
        Attempt::Child(Outcome::Returned { errno: libc::EPERM })
    );

    // The filter kills: the child dies of SIGSYS, the record says so, and
    // this process is still here to write the record.
    apply_filter(&on_shmctl(SeccompAction::KillProcess)).unwrap();
    let r = ours(&janitor(run()));
    assert!(!r.removed, "{r:?}");
    assert_eq!(
        r.attempt,
        Attempt::Child(Outcome::Signaled {
            signal: Signal::SIGSYS as i32
        })
    );

    // SAFETY: the child's only exit; nothing to unwind or flush.
    unsafe { libc::_exit(0) }
}
