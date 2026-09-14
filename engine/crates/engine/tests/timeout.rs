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

//! Timeouts (#7): a probe that blocks past its risk class's deadline is
//! killed and recorded `timed-out` — not `denied`, not a hang. Linux only.

#![cfg(target_os = "linux")]

use std::time::{Duration, Instant};

use caliper_engine::harness::Outcome;
use caliper_engine::verdict::{classify, Verdict};
use caliper_engine::{
    run_isolated, Applicability, Isolates, KernelDependency, Oracle, Probe, RawResult, RiskClass,
    SideEffects,
};

/// An oracle for a probe whose call is expected to succeed.
const SUCCEEDS: Oracle = Oracle {
    guarantees: None,
    isolates: Isolates::Seccomp,
    reason: "test probe",
};

fn probe(id: &'static str, timeout: Duration, run: fn() -> RawResult) -> Probe {
    caliper_engine::init().unwrap();
    Probe {
        id,
        family: "test",
        description: id,
        risk: RiskClass::new(true, timeout),
        arch: Applicability::All,
        kernel: KernelDependency::NONE,
        oracle: Oracle {
            guarantees: None,
            isolates: Isolates::Seccomp,
            reason: "test probe",
        },
        capability: None,
        effects: SideEffects::NONE,
        run,
    }
}

/// Blocks forever: `pause(2)` returns only on a signal, and the parent's
/// SIGKILL never returns to the caller.
fn hangs() -> RawResult {
    unsafe { libc::pause() };
    Ok(())
}

/// Sleeps for a bounded time — long against a short deadline, short
/// against a long one. What the harness sees is the same as `hangs` up to
/// the deadline; hung and slow are not distinguished (spec/probe.md).
fn slow_200ms() -> RawResult {
    let ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 200_000_000,
    };
    unsafe { libc::nanosleep(&ts, std::ptr::null_mut()) };
    Ok(())
}

#[test]
fn a_hung_probe_is_killed_at_the_deadline_and_recorded_timed_out() {
    let deadline = Duration::from_millis(300);
    let started = Instant::now();
    let out = run_isolated(&probe("hangs", deadline, hangs)).unwrap();
    let took = started.elapsed();

    assert_eq!(out, Outcome::TimedOut);
    let m = classify(out, &SUCCEEDS, &KernelDependency::NONE, None).unwrap();
    assert_eq!(m.verdict, Verdict::TimedOut);
    assert_eq!(m.errno, 0);
    // Killed at the deadline, not stalled: generous upper bound for a
    // loaded CI runner, but nowhere near "indefinitely".
    assert!(took >= deadline, "returned before the deadline: {took:?}");
    assert!(
        took < deadline * 4,
        "stalled well past the deadline: {took:?}"
    );
}

#[test]
fn the_deadline_comes_from_the_risk_class() {
    // Same probe, two risk classes: over the deadline it is timed-out,
    // under it the sleep completes and the probe is permitted.
    let over = run_isolated(&probe("slow-tight", Duration::from_millis(50), slow_200ms)).unwrap();
    assert_eq!(over, Outcome::TimedOut);

    let under = run_isolated(&probe("slow-loose", Duration::from_secs(2), slow_200ms)).unwrap();
    assert_eq!(
        classify(under, &SUCCEEDS, &KernelDependency::NONE, None)
            .unwrap()
            .verdict,
        Verdict::Permitted
    );
}

#[test]
fn the_run_continues_after_a_timeout() {
    fn fine() -> RawResult {
        Ok(())
    }
    let _ = run_isolated(&probe("hangs", Duration::from_millis(50), hangs)).unwrap();
    let next = run_isolated(&probe("after", Duration::from_secs(1), fine)).unwrap();
    assert_eq!(
        classify(next, &SUCCEEDS, &KernelDependency::NONE, None)
            .unwrap()
            .verdict,
        Verdict::Permitted
    );
}
