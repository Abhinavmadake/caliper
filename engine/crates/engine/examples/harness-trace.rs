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

//! One probe through the harness, for strace. Shows what the parent issues
//! between `clone` and the child's syscall — which should be nothing — and
//! what the child issues, which should be the probe and `exit_group`:
//!
//!     strace -f target/<triple>/debug/examples/harness-trace
//!
//! With `panic` as the argument the probe panics instead. Built `--release`
//! this is the image's `panic = "abort"` profile, which `cargo test` never
//! uses (Cargo forces unwind for test targets), so this is where the
//! SIGABRT shape of a panicking probe is actually observable:
//!
//!     target/<triple>/release/examples/harness-trace panic

use std::time::Duration;

use caliper_engine::{
    run_isolated, Applicability, KernelDependency, Probe, RawResult, RiskClass, SideEffects,
};

fn getppid() -> RawResult {
    unsafe { libc::syscall(libc::SYS_getppid) };
    Ok(())
}

fn panics() -> RawResult {
    panic!("probe bug");
}

fn main() {
    caliper_engine::init().unwrap();
    let panic = std::env::args().nth(1).as_deref() == Some("panic");
    if panic {
        std::panic::set_hook(Box::new(|_| {}));
    }
    let probe = Probe {
        id: "trace",
        family: "test",
        description: "getppid in a child",
        risk: RiskClass::new(true, Duration::from_secs(1)),
        arch: Applicability::All,
        kernel: KernelDependency::NONE,
        effects: SideEffects::NONE,
        run: if panic { panics } else { getppid },
    };
    let out = run_isolated(&probe).unwrap();
    // One write, after the measurement.
    println!("{out:?}");
}
