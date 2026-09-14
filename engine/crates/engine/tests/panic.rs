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

//! A probe that panics is a fault, never a measurement.
//!
//! Its own binary with `harness = false`, deliberately: the child is a fork
//! of the test process, and a panicking child allocates and writes. Under
//! libtest's threaded runner another thread could hold musl's malloc lock
//! at the instant of the fork, and the child would block forever on it.
//! One thread, no lock, no flake. The real engine is single-threaded for
//! the same reason.
//!
//! Test builds unwind — Cargo forces that for test targets, `--release`
//! included — so `catch_unwind` stops it at the probe boundary, the child
//! exits with the reserved code, and the parent sees `Fault(Panicked)`.
//! The image profile is `panic = "abort"`: there the child dies of SIGABRT,
//! a crash reported by signal and not `killed`, which is SIGSYS only (#8).
//! That arm is kept below for completeness but is only observable through
//! `examples/harness-trace panic` built `--release`.

#![cfg(target_os = "linux")]

use std::time::Duration;

use caliper_engine::harness::{Fault, Outcome};
use caliper_engine::{
    run_isolated, Applicability, KernelDependency, Probe, RawResult, RiskClass, SideEffects,
};
use nix::sys::signal::Signal;

fn panics() -> RawResult {
    panic!("probe bug");
}

fn main() {
    // The default hook formats and prints; nothing in the assertion needs
    // it, and a silent child makes the strace of this test readable.
    std::panic::set_hook(Box::new(|_| {}));

    let probe = Probe {
        id: "panics",
        family: "test",
        description: "a probe with a bug in it",
        risk: RiskClass::new(true, Duration::from_secs(5)),
        arch: Applicability::All,
        kernel: KernelDependency::NONE,
        effects: SideEffects::NONE,
        run: panics,
    };
    let out = run_isolated(&probe).unwrap();

    #[cfg(panic = "unwind")]
    assert_eq!(out, Outcome::Fault(Fault::Panicked), "unwind build");
    #[cfg(panic = "abort")]
    assert!(out.signaled_by(Signal::SIGABRT), "abort build: {out:?}");

    // Silence unused-import lints in whichever configuration is not built.
    let _ = (Outcome::TimedOut, Fault::Panicked, Signal::SIGABRT);

    // The run continues.
    fn fine() -> RawResult {
        Ok(())
    }
    let next = run_isolated(&Probe {
        id: "fine",
        run: fine,
        ..probe
    })
    .unwrap();
    assert_eq!(next, Outcome::Returned { errno: 0 });
    println!("ok: panicking probe reported as {out:?}");
}
