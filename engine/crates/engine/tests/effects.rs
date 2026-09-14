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

//! Side effects (#9): an undeclared probe is refused, residual state is
//! counted directly around each probe and attributed to it, a declared
//! class that cannot be observed here is reported as unverifiable, the
//! per-probe accounting is audited against the run, and the janitor
//! removes what it recognises — loudly.
//!
//! The leaking probes create real objects: a System V shared-memory
//! segment keyed in the instrument's range, and a POSIX shared-memory
//! object under the instrument's prefix. Both outlive the child; both are
//! what the janitor is for. libtest runs tests in threads of one process,
//! and a leak from one test lands in another's snapshot window — which is
//! the ambient-writer problem the module comment on `measurement` describes,
//! reproduced in miniature. So the tests that touch objects take a lock.

#![cfg(target_os = "linux")]

use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use caliper_engine::cell::Cell;
use caliper_engine::effects::{ResidualClass, SYSV_IPC_KEY_BASE};
use caliper_engine::measurement::{measure, Measurement, Unmeasurable};
use caliper_engine::residual::{janitor, Snapshot};
use caliper_engine::{
    Applicability, Isolates, KernelDependency, Oracle, Probe, RawResult, RiskClass, SideEffects,
};
use nix::errno::Errno;

fn probe(id: &'static str, effects: SideEffects, run: fn() -> RawResult) -> Probe {
    caliper_engine::init().unwrap();
    Probe {
        id,
        family: "test",
        description: id,
        risk: RiskClass::new(true, Duration::from_secs(5)),
        arch: Applicability::All,
        kernel: KernelDependency::NONE,
        oracle: Oracle {
            guarantees: None,
            isolates: Isolates::Seccomp,
            reason: "test probe",
        },
        capability: None,
        effects,
        run,
    }
}

fn ok() -> RawResult {
    Ok(())
}

/// Leaves a System V segment behind, keyed as the instrument's.
fn leak_sysv_shm() -> RawResult {
    let r = unsafe { libc::shmget(SYSV_IPC_KEY_BASE + 1, 4096, libc::IPC_CREAT | 0o600) };
    if r < 0 {
        Err(Errno::last())
    } else {
        Ok(())
    }
}

/// Leaves a POSIX shared-memory object behind, named as the instrument's.
fn leak_posix_shm() -> RawResult {
    let name = c"/caliper-test-leak";
    let fd = unsafe { libc::shm_open(name.as_ptr(), libc::O_CREAT | libc::O_RDWR, 0o600) };
    if fd < 0 {
        Err(Errno::last())
    } else {
        Ok(())
    }
}

fn cell() -> Cell {
    Cell::detect().unwrap()
}

static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

const DECLARED_SYSV: SideEffects = SideEffects::Declared {
    residual: &[ResidualClass::SysvIpc],
    module_autoload: false,
};

#[test]
fn an_undeclared_probe_is_refused_not_run() {
    let _serial = serial();
    fn would_leak() -> RawResult {
        leak_sysv_shm()
    }
    let before = Snapshot::take();
    let p = probe("undeclared", SideEffects::default(), would_leak);
    assert_eq!(measure(&p, &cell()), Err(Unmeasurable::Undeclared));
    // Not run: nothing changed.
    assert_eq!(Snapshot::take(), before);

    // And the run records it as unmeasured, with the reason.
    let m = Measurement::run(&[p], "0.1.0", cell());
    assert!(m.results.is_empty());
    assert_eq!(m.unmeasured[0].why, Unmeasurable::Undeclared);
    let v = serde_json::to_value(&m).unwrap();
    assert_eq!(v["unmeasured"][0]["why"], "undeclared");
}

#[test]
fn undeclared_serialises_as_null_and_declared_as_the_declaration() {
    let p = probe("d", DECLARED_SYSV, ok);
    let v = serde_json::to_value(&p).unwrap();
    assert_eq!(v["effects"]["residual"][0], "sysv-ipc");
    assert_eq!(v["effects"]["module_autoload"], false);
    let p = probe("u", SideEffects::Undeclared, ok);
    let v = serde_json::to_value(&p).unwrap();
    assert!(v["effects"].is_null());
}

#[test]
fn a_leak_is_attributed_to_its_probe_and_checked_against_its_declaration() {
    let _serial = serial();
    let probes = [
        probe("clean", SideEffects::NONE, ok),
        probe("leaks.declared", DECLARED_SYSV, leak_sysv_shm),
        probe("clean.again", SideEffects::NONE, ok),
    ];
    let m = Measurement::run(&probes, "0.1.0", cell());
    assert_eq!(m.results.len(), 3);

    let sysv: Vec<_> = m
        .residual
        .leaks
        .iter()
        .filter(|l| l.class == ResidualClass::SysvIpc)
        .collect();
    assert_eq!(sysv.len(), 1, "{:?}", m.residual.leaks);
    assert_eq!(sysv[0].probe_id, "leaks.declared");
    assert_eq!(sysv[0].delta, 1);
    assert!(sysv[0].declared);

    // The run-level pair agrees with the per-probe accounting.
    assert!(m.residual.audit.is_empty(), "{:?}", m.residual.audit);
    // The janitor took the segment, after it was measured, and said so.
    assert_eq!(m.residual.janitor.len(), 1, "{:?}", m.residual.janitor);
    assert_eq!(m.residual.janitor[0].class, ResidualClass::SysvIpc);
    assert!(m.residual.janitor[0].object.contains("shm"));
    assert!(m.residual.janitor[0].removed, "{:?}", m.residual.janitor[0]);
    assert!(janitor().is_empty(), "the janitor left something");
}

#[test]
fn an_undeclared_leak_is_a_finding_against_the_probe() {
    let _serial = serial();
    let probes = [probe("leaks.undeclared", SideEffects::NONE, leak_posix_shm)];
    let m = Measurement::run(&probes, "0.1.0", cell());
    let posix: Vec<_> = m
        .residual
        .leaks
        .iter()
        .filter(|l| l.class == ResidualClass::PosixIpc)
        .collect();
    assert_eq!(posix.len(), 1, "{:?}", m.residual.leaks);
    assert_eq!(posix[0].probe_id, "leaks.undeclared");
    assert_eq!(posix[0].delta, 1);
    assert!(!posix[0].declared);
    assert_eq!(m.residual.janitor.len(), 1);
    assert_eq!(m.residual.janitor[0].object, "/dev/shm/caliper-test-leak");
    assert!(m.residual.janitor[0].removed, "{:?}", m.residual.janitor[0]);

    let v = serde_json::to_value(&m).unwrap();
    assert_eq!(v["residual"]["leaks"][0]["declared"], false);
    assert_eq!(v["residual"]["janitor"][0]["class"], "posix-ipc");
    assert_eq!(v["residual"]["janitor"][0]["removed"], true);
    assert_eq!(
        v["residual"]["janitor"][0]["attempt"]["child"]["returned"]["errno"],
        0
    );
}

#[test]
fn a_declared_class_that_cannot_be_observed_here_is_reported_as_unverifiable() {
    let _serial = serial();
    // The claim is about the record, not about this machine, so the class
    // is chosen from what the environment actually cannot see; if it sees
    // all six, the report is empty and that is asserted instead.
    let before = Snapshot::take();
    let blind: Vec<_> = ResidualClass::ALL
        .into_iter()
        .filter(|c| before.get(*c).count().is_none())
        .collect();
    let all: &'static [ResidualClass] = &ResidualClass::ALL;
    let probes = [probe(
        "declares.everything",
        SideEffects::Declared {
            residual: all,
            module_autoload: false,
        },
        ok,
    )];
    let m = Measurement::run(&probes, "0.1.0", cell());
    let reported: Vec<_> = m.residual.unverifiable.iter().map(|u| u.class).collect();
    assert_eq!(reported, blind);
    // And the observability map says the same, once, for the run.
    let v = serde_json::to_value(&m).unwrap();
    for c in ResidualClass::ALL {
        let key = serde_json::to_value(c).unwrap();
        let entry = &v["residual"]["observability"][key.as_str().unwrap()];
        if blind.contains(&c) {
            assert!(entry != "observed", "{c:?}: {entry}");
            assert!(v["residual"]["before"][key.as_str().unwrap()].is_null());
        } else {
            assert_eq!(entry, "observed", "{c:?}");
        }
    }
}

#[test]
fn modules_are_snapshotted_before_and_after_and_the_cell_carries_the_before() {
    let _serial = serial();
    let m = Measurement::run(&[probe("noop", SideEffects::NONE, ok)], "0.1.0", cell());
    match (&m.cell.kernel.modules, &m.module_delta) {
        (Some(before), Some(delta)) => {
            assert_eq!(&delta.before, before);
            assert!(delta.loaded_by_run.is_empty(), "{:?}", delta.loaded_by_run);
            let v = serde_json::to_value(&m).unwrap();
            assert_eq!(v["module_delta"]["loaded_by_run"], serde_json::json!([]));
            assert_eq!(v["cell"]["kernel"]["modules"], v["module_delta"]["before"]);
        }
        (None, None) => {
            // /proc/modules not readable here: unknown, and absent rather
            // than empty in both places.
            let v = serde_json::to_value(&m).unwrap();
            assert!(v["cell"]["kernel"].get("modules").is_none());
            assert!(v.get("module_delta").is_none());
        }
        other => panic!("modules known on one side only: {other:?}"),
    }
}
