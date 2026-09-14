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

//! Verdict classification (#8): `unimplemented` against `denied`, decided
//! by the probe's kernel dependency and the running kernel; `not-applicable`
//! decided before any fork; the raw errno preserved under every verdict;
//! and the emitted document carrying verdicts and nothing that reads as
//! attribution.
//!
//! Filters are applied to the test process (no `NO_NEW_PRIVS` reset), so
//! each test that installs one is written to tolerate the others' filters:
//! they all filter a syscall nothing else here issues.

#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::time::Duration;

use caliper_engine::cell::{Arch, Cell, Kernel, KernelVersion, Lsm};
use caliper_engine::harness::Outcome;
use caliper_engine::measurement::{measure, Measurement, FORMAT_VERSION};
use caliper_engine::verdict::{classify, Verdict};
use caliper_engine::{
    Applicability, Isolates, KernelDependency, Oracle, Probe, RawResult, RiskClass, SideEffects,
};
use nix::errno::Errno;
use seccompiler::{apply_filter, BpfProgram, SeccompAction, SeccompFilter, TargetArch};

/// An oracle for a probe whose call is expected to succeed.
const SUCCEEDS: Oracle = Oracle {
    guarantees: None,
    isolates: Isolates::Seccomp,
    reason: "test probe",
};

#[cfg(target_arch = "aarch64")]
const ARCH: TargetArch = TargetArch::aarch64;
#[cfg(target_arch = "x86_64")]
const ARCH: TargetArch = TargetArch::x86_64;

/// A syscall number no kernel implements: the kernel answers `ENOSYS` from
/// the syscall table, before any filter or hook could.
const NO_SUCH_SYSCALL: i64 = 999;
/// The syscall a filter is put on. Nothing in the engine, musl start-up or
/// the test harness issues it.
const TARGET: i64 = libc::SYS_getppid;

fn probe(id: &'static str, kernel: KernelDependency, run: fn() -> RawResult) -> Probe {
    caliper_engine::init().unwrap();
    Probe {
        id,
        family: "test",
        description: id,
        risk: RiskClass::new(true, Duration::from_secs(5)),
        arch: Applicability::All,
        kernel,
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

fn raw(r: libc::c_long) -> RawResult {
    if r < 0 {
        Err(Errno::last())
    } else {
        Ok(())
    }
}

fn missing_syscall() -> RawResult {
    raw(unsafe { libc::syscall(NO_SUCH_SYSCALL) })
}

fn target_syscall() -> RawResult {
    raw(unsafe { libc::syscall(TARGET) })
}

fn cell(version: Option<KernelVersion>) -> Cell {
    Cell {
        architecture: Arch::current(),
        kernel: Kernel {
            release: "test".into(),
            version,
            modules: None,
        },
        lsm: Lsm::None,
    }
}

const ENOSYS: i32 = libc::ENOSYS;
const RUNNING: Option<KernelVersion> = Some(KernelVersion::new(6, 8));

fn absent(since: Option<(u32, u32)>) -> KernelDependency {
    KernelDependency {
        since,
        absent_errno: Some(Errno::ENOSYS),
    }
}

// --- unimplemented vs denied, on the classification rule alone ----------

#[test]
fn absent_errno_from_a_kernel_that_may_lack_it_is_unimplemented() {
    let out = Outcome::Returned { errno: ENOSYS };
    // Presence is a config/module property: no version settles it.
    let m = classify(out, &SUCCEEDS, &absent(None), RUNNING).unwrap();
    assert_eq!((m.verdict, m.errno), (Verdict::Unimplemented, ENOSYS));
    // The entry point is newer than the running kernel.
    let m = classify(out, &SUCCEEDS, &absent(Some((6, 9))), RUNNING).unwrap();
    assert_eq!((m.verdict, m.errno), (Verdict::Unimplemented, ENOSYS));
}

#[test]
fn absent_errno_from_a_kernel_that_implements_it_is_denied() {
    // spec/probe.md: "ENOSYS from a syscall the cell's kernel implements is
    // a filter, not unimplemented".
    let out = Outcome::Returned { errno: ENOSYS };
    let m = classify(out, &SUCCEEDS, &absent(Some((6, 8))), RUNNING).unwrap();
    assert_eq!((m.verdict, m.errno), (Verdict::Denied, ENOSYS));
    let m = classify(out, &SUCCEEDS, &absent(Some((2, 6))), RUNNING).unwrap();
    assert_eq!((m.verdict, m.errno), (Verdict::Denied, ENOSYS));
}

#[test]
fn a_different_errno_is_denied_whatever_the_dependency_says() {
    let out = Outcome::Returned { errno: libc::EPERM };
    let m = classify(out, &SUCCEEDS, &absent(None), RUNNING).unwrap();
    assert_eq!((m.verdict, m.errno), (Verdict::Denied, libc::EPERM));
    let m = classify(out, &SUCCEEDS, &KernelDependency::NONE, RUNNING).unwrap();
    assert_eq!((m.verdict, m.errno), (Verdict::Denied, libc::EPERM));
}

#[test]
fn no_absent_errno_means_every_errno_is_a_denial() {
    let out = Outcome::Returned { errno: ENOSYS };
    let m = classify(out, &SUCCEEDS, &KernelDependency::NONE, RUNNING).unwrap();
    assert_eq!((m.verdict, m.errno), (Verdict::Denied, ENOSYS));
}

#[test]
fn an_unparsed_kernel_release_reads_absence_as_unimplemented() {
    // The reading that does not invent a policy finding.
    let out = Outcome::Returned { errno: ENOSYS };
    let m = classify(out, &SUCCEEDS, &absent(Some((2, 6))), None).unwrap();
    assert_eq!(m.verdict, Verdict::Unimplemented);
    let m = classify(out, &SUCCEEDS, &KernelDependency::NONE, None).unwrap();
    assert_eq!(m.verdict, Verdict::Denied);
}

// --- the same, end to end through a forked child -------------------------

#[test]
fn a_syscall_the_kernel_lacks_measures_unimplemented() {
    let c = cell(RUNNING);
    let m = measure(&probe("missing", absent(None), missing_syscall), &c).unwrap();
    assert_eq!((m.verdict, m.errno), (Verdict::Unimplemented, ENOSYS));
    // Declared as present since 2.6: the same ENOSYS is then a filter.
    let m = measure(&probe("missing", absent(Some((2, 6))), missing_syscall), &c).unwrap();
    assert_eq!((m.verdict, m.errno), (Verdict::Denied, ENOSYS));
}

#[test]
fn a_filter_answering_enosys_is_denied_not_unimplemented() {
    // A filter that speaks in the kernel's voice, on a syscall every
    // kernel has.
    let mut rules = BTreeMap::new();
    rules.insert(TARGET, vec![]);
    let filter: BpfProgram = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(ENOSYS as u32),
        ARCH,
    )
    .unwrap()
    .try_into()
    .unwrap();
    apply_filter(&filter).unwrap();

    let c = cell(RUNNING);
    let m = measure(&probe("filtered", absent(Some((2, 6))), target_syscall), &c).unwrap();
    assert_eq!((m.verdict, m.errno), (Verdict::Denied, ENOSYS));
}

// --- the oracle ----------------------------------------------------------

#[test]
fn the_oracles_guaranteed_errno_is_permitted_with_the_errno_kept() {
    let oracle = Oracle {
        guarantees: Some(Errno::EBADF),
        isolates: Isolates::Seccomp,
        reason: "descriptor resolution precedes every hook",
    };
    let hit = Outcome::Returned {
        errno: Errno::EBADF as i32,
    };
    let m = classify(hit, &oracle, &KernelDependency::NONE, RUNNING).unwrap();
    assert_eq!(
        (m.verdict, m.errno),
        (Verdict::Permitted, Errno::EBADF as i32)
    );

    // Anything else against the oracle is what it always was.
    let miss = Outcome::Returned {
        errno: Errno::EPERM as i32,
    };
    let m = classify(miss, &oracle, &KernelDependency::NONE, RUNNING).unwrap();
    assert_eq!((m.verdict, m.errno), (Verdict::Denied, Errno::EPERM as i32));
    let m = classify(miss, &oracle, &absent(Some((2, 6))), RUNNING).unwrap();
    assert_eq!(m.verdict, Verdict::Denied);
    let m = classify(hit, &SUCCEEDS, &KernelDependency::NONE, RUNNING).unwrap();
    assert_eq!(m.verdict, Verdict::Denied, "no oracle: EBADF is a denial");
}

#[test]
fn an_oracle_probe_measures_permitted_end_to_end() {
    fn close_bad_fd() -> RawResult {
        let r = unsafe { libc::syscall(libc::SYS_close, -1) };
        if r < 0 {
            Err(Errno::last())
        } else {
            Ok(())
        }
    }
    let mut p = probe("close.bad_fd", KernelDependency::NONE, close_bad_fd);
    p.oracle = Oracle {
        guarantees: Some(Errno::EBADF),
        isolates: Isolates::Seccomp,
        reason: "descriptor resolution precedes every hook",
    };
    let m = measure(&p, &cell(RUNNING)).unwrap();
    assert_eq!(
        (m.verdict, m.errno),
        (Verdict::Permitted, Errno::EBADF as i32)
    );
}

// --- not-applicable ------------------------------------------------------

#[test]
fn a_probe_for_the_other_architecture_is_not_applicable_and_not_run() {
    fn would_be_denied() -> RawResult {
        Err(Errno::EPERM)
    }
    const HERE: [Arch; 1] = [Arch::current()];
    const ELSEWHERE: [Arch; 1] = [Arch::current().other()];
    let mut p = probe("elsewhere", KernelDependency::NONE, would_be_denied);
    p.arch = Applicability::Only(&ELSEWHERE);
    let m = measure(&p, &cell(RUNNING)).unwrap();
    // errno 0: had the child run, EPERM would be here.
    assert_eq!((m.verdict, m.errno), (Verdict::NotApplicable, 0));

    p.arch = Applicability::Only(&HERE);
    let m = measure(&p, &cell(RUNNING)).unwrap();
    assert_eq!((m.verdict, m.errno), (Verdict::Denied, libc::EPERM));
}

// --- the emitted document -------------------------------------------------

#[test]
fn the_measurement_carries_verdicts_and_no_interpretation() {
    fn ok() -> RawResult {
        Ok(())
    }
    let probes = [
        probe("a.permitted", KernelDependency::NONE, ok),
        probe("b.unimplemented", absent(None), missing_syscall),
    ];
    let m = Measurement::run(&probes, "0.1.0", Cell::detect().unwrap());
    assert!(m.unmeasured.is_empty());

    let v: serde_json::Value = serde_json::to_value(&m).unwrap();
    assert_eq!(v["format_version"], FORMAT_VERSION);
    assert_eq!(v["corpus_revision"], "0.1.0");
    // The probe-side cell fields, spelled as the spec's example spells them.
    assert!(matches!(
        v["cell"]["architecture"].as_str(),
        Some("x86_64" | "aarch64")
    ));
    assert!(v["cell"]["kernel"]["release"]
        .as_str()
        .is_some_and(|r| !r.is_empty()));
    assert!(matches!(
        v["cell"]["lsm"].as_str(),
        Some("apparmor" | "selinux" | "none")
    ));
    // What the probe cannot know is absent, not false.
    assert!(v["cell"]["kernel"].get("sandbox_claimed").is_none());
    assert!(v["cell"].get("runtime").is_none());

    let results = v["results"].as_array().unwrap();
    assert_eq!(results.len(), 2);
    assert_eq!(results[0]["probe_id"], "a.permitted");
    assert_eq!(results[0]["verdict"], "permitted");
    assert_eq!(results[0]["errno"], 0);
    assert_eq!(results[1]["probe_id"], "b.unimplemented");
    assert_eq!(results[1]["verdict"], "unimplemented");
    assert_eq!(results[1]["errno"], ENOSYS);
    // No attribution, no reason, no digest: the engine stores no
    // interpretation (#8), and the control plane completes the fingerprint.
    for r in results {
        assert_eq!(r.as_object().unwrap().len(), 3, "{r}");
    }
    assert!(v.get("digest").is_none());
    assert_eq!(v["unmeasured"], serde_json::json!([]));
}

#[test]
fn a_probe_that_produced_no_verdict_is_reported_and_not_recorded() {
    fn crashes() -> RawResult {
        unsafe { std::ptr::write_volatile(std::ptr::null_mut::<u8>(), 1) };
        Ok(())
    }
    let probes = [probe("segv", KernelDependency::NONE, crashes)];
    let m = Measurement::run(&probes, "0.1.0", cell(RUNNING));
    assert!(m.results.is_empty());
    assert_eq!(m.unmeasured.len(), 1);
    assert_eq!(m.unmeasured[0].probe_id, "segv");
    // On the record, not only on stderr.
    let v = serde_json::to_value(&m).unwrap();
    assert_eq!(v["unmeasured"][0]["probe_id"], "segv");
}
