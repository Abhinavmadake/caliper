//! SIGSYS survival (#6): a probe that trips a `KILL_PROCESS` filter is
//! recorded `killed`, the parent survives, the run continues — and a
//! filter that answers with an errno instead is a different verdict.
//!
//! The filter is installed in the *test thread* with seccompiler and
//! inherited by the forked child, so the parent runs under the same filter
//! as the probe — the deployment §6.2 describes. Each test runs on its own
//! thread and seccomp filters are per-thread, so tests do not see each
//! other's. Linux only; `cargo test --target <arch>-unknown-linux-musl`.

#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::time::Duration;

use caliper_engine::harness::Outcome;
use caliper_engine::verdict::{classify, NotMeasured, Verdict};
use caliper_engine::{run_isolated, Probe, RawResult, RiskClass};
use nix::errno::Errno;
use seccompiler::{apply_filter, BpfProgram, SeccompAction, SeccompFilter, TargetArch};

#[cfg(target_arch = "aarch64")]
const ARCH: TargetArch = TargetArch::aarch64;
#[cfg(target_arch = "x86_64")]
const ARCH: TargetArch = TargetArch::x86_64;

/// The syscall under test. Nothing in the engine, musl start-up or the
/// test harness issues it, so a filter on it touches only the probe.
const TARGET: i64 = libc::SYS_getppid;

fn probe(id: &'static str, run: fn() -> RawResult) -> Probe {
    caliper_engine::init().unwrap();
    Probe {
        id,
        family: "test",
        description: id,
        risk: RiskClass::new(true, Duration::from_secs(5)),
        run,
    }
}

fn raw(r: libc::c_long) -> RawResult {
    if r < 0 {
        Err(Errno::last())
    } else {
        Ok(())
    }
}

fn target_syscall() -> RawResult {
    raw(unsafe { libc::syscall(TARGET) })
}

fn other_syscall() -> RawResult {
    raw(unsafe { libc::syscall(libc::SYS_getpid) })
}

/// A filter that allows everything except `TARGET`, which gets `action`.
fn filter_on_target(action: SeccompAction) -> BpfProgram {
    let mut rules = BTreeMap::new();
    rules.insert(TARGET, vec![]); // no conditions: every call matches
    SeccompFilter::new(rules, SeccompAction::Allow, action, ARCH)
        .unwrap()
        .try_into()
        .unwrap()
}

#[test]
fn kill_process_is_recorded_killed_and_the_run_continues() {
    apply_filter(&filter_on_target(SeccompAction::KillProcess)).unwrap();

    let out = run_isolated(&probe("tripwire", target_syscall)).unwrap();
    assert_eq!(
        out,
        Outcome::Signaled {
            signal: libc::SIGSYS
        }
    );
    let m = classify(out).unwrap();
    assert_eq!(m.verdict, Verdict::Killed);
    assert_eq!(m.errno, 0);

    // The parent is alive, under the same filter, and the next probe —
    // one the filter allows — measures normally.
    let next = run_isolated(&probe("after-kill", other_syscall)).unwrap();
    assert_eq!(classify(next).unwrap().verdict, Verdict::Permitted);

    // And so does a second trip of the same wire.
    let again = run_isolated(&probe("tripwire-again", target_syscall)).unwrap();
    assert_eq!(classify(again).unwrap().verdict, Verdict::Killed);
}

#[test]
fn kill_thread_is_also_killed() {
    // A single-threaded child dies the same way under KILL_THREAD.
    apply_filter(&filter_on_target(SeccompAction::KillThread)).unwrap();
    let out = run_isolated(&probe("tripwire", target_syscall)).unwrap();
    assert_eq!(classify(out).unwrap().verdict, Verdict::Killed);
}

#[test]
fn an_errno_action_is_denied_not_killed() {
    // RuntimeDefault's shape: the filter answers EPERM, the child returns.
    apply_filter(&filter_on_target(SeccompAction::Errno(libc::EPERM as u32))).unwrap();
    let out = run_isolated(&probe("filtered", target_syscall)).unwrap();
    assert_eq!(out, Outcome::Returned { errno: libc::EPERM });
    let m = classify(out).unwrap();
    assert_eq!(m.verdict, Verdict::Denied);
    assert_eq!(m.errno, libc::EPERM);
    assert_eq!(m.errno_name().as_deref(), Some("EPERM"));
}

#[test]
fn only_sigsys_is_killed() {
    fn crashes() -> RawResult {
        unsafe { std::ptr::write_volatile(std::ptr::null_mut::<u8>(), 1) };
        Ok(())
    }
    let out = run_isolated(&probe("segv", crashes)).unwrap();
    assert_eq!(
        classify(out),
        Err(NotMeasured::Crashed {
            signal: libc::SIGSEGV
        })
    );
}
