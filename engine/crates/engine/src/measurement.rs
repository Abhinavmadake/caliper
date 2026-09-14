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

//! A measurement run: every probe in the corpus, in order, and the
//! document the probe emits at the end (#8, #9). It is the probe-side half
//! of a fingerprint (`spec/fingerprint.md`): identity, the cell fields the
//! probe can see, one result per probe carrying the verdict and raw errno,
//! the module delta, and the residual-state report.
//!
//! No `attribution`, no control-plane cell fields, no `digest` — the
//! control plane completes the fingerprint and computes those, and the
//! engine "stores no interpretation" (§5). Field names follow the spec's
//! worked example where it has one (`results`, `module_delta`); the
//! residual report is the engine's own metric (§11.2) and is named here.
//!
//! Residual state is snapshotted around every probe, after `waitpid` has
//! reaped the child, so a leaked object is attributed to a probe id and
//! checked against that probe's declaration; and once around the whole
//! run, which audits the per-probe accounting: the per-probe deltas must
//! sum to the run delta, or a class is being changed by something between
//! probes. The window is not clean — an object the kernel reclaims
//! asynchronously can land in the next probe's diff, and anything else
//! writing to these classes in the container is counted too. The engine
//! cannot give a probe its own namespaces: that needs `CAP_SYS_ADMIN` or a
//! user namespace, which RuntimeDefault denies and which would change
//! what the kernel permits, so the workload's room is the only room.

use serde::Serialize;

use crate::cell::Cell;
use crate::effects::ResidualClass;
use crate::harness::run_isolated;
use crate::probe::Probe;
use crate::residual::{janitor, loaded_modules, ModuleDelta, ObservabilityMap, Removal, Snapshot};
use crate::verdict::{classify, Measured, NotMeasured, Verdict};

/// `spec/fingerprint.md`: incremented only by a breaking change to the
/// format; frozen from the end of week 9 (#28).
pub const FORMAT_VERSION: u32 = 1;

/// One probe's line in `results`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ProbeResult {
    pub probe_id: &'static str,
    #[serde(flatten)]
    pub measured: Measured,
}

/// A probe that produced no verdict. It is absent from `results` — the
/// one meaning of absence: not known — and named here so the absence is
/// explained on the record rather than discovered as corpus skew.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Unmeasured {
    pub probe_id: &'static str,
    pub why: Unmeasurable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Unmeasurable {
    /// The probe's side effects are `Undeclared`; it was not run (#9).
    Undeclared,
    /// The child ended in a way that is not a verdict.
    NotMeasured(NotMeasured),
    /// The harness itself failed — fork, pidfd or wait.
    Harness(#[serde(serialize_with = "errno_as_int")] nix::errno::Errno),
}

fn errno_as_int<S: serde::Serializer>(e: &nix::errno::Errno, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_i32(*e as i32)
}

/// A change in a residual class across one probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Leak {
    pub probe_id: &'static str,
    pub class: ResidualClass,
    /// Objects after minus objects before. Negative means the probe
    /// removed something it did not create.
    pub delta: i64,
    /// Whether the probe declared this class. An undeclared leak is a
    /// corpus defect as well as a residual.
    pub declared: bool,
}

/// A declaration this environment could not check: the probe declares a
/// class that is not observable here. A coverage statement, distinct from
/// a finding — without it "no leaks" would quietly include "could not
/// look".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Unverifiable {
    pub probe_id: &'static str,
    pub class: ResidualClass,
}

/// A class whose per-probe deltas do not sum to the run delta.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct AuditMismatch {
    pub class: ResidualClass,
    pub per_probe_sum: i64,
    pub run_delta: i64,
}

/// The residual-state report (§11.2: "zero unreclaimed objects").
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Residual {
    /// Per class, whether this environment exposes it at all.
    pub observability: ObservabilityMap,
    pub before: Snapshot,
    pub after: Snapshot,
    pub leaks: Vec<Leak>,
    pub unverifiable: Vec<Unverifiable>,
    pub audit: Vec<AuditMismatch>,
    /// Every removal the janitor attempted, succeeded or not.
    pub janitor: Vec<Removal>,
}

/// What the probe emits for `--run`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Measurement {
    pub format_version: u32,
    /// Which corpus produced the run: the corpus crate's version.
    pub corpus_revision: &'static str,
    pub cell: Cell,
    pub results: Vec<ProbeResult>,
    pub unmeasured: Vec<Unmeasured>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module_delta: Option<ModuleDelta>,
    pub residual: Residual,
}

/// Measure one probe against `cell`. Applicability is decided here, before
/// any fork: a probe whose entry point does not exist on this architecture
/// is `not-applicable` and is not run. So is the declaration: an
/// `Undeclared` probe is refused.
pub fn measure(probe: &Probe, cell: &Cell) -> Result<Measured, Unmeasurable> {
    decided_without_running(probe, cell).unwrap_or_else(|| run_and_classify(probe, cell))
}

/// The answer that needs no child, or `None`: the probe runs.
fn decided_without_running(probe: &Probe, cell: &Cell) -> Option<Result<Measured, Unmeasurable>> {
    if !probe.effects.is_declared() {
        return Some(Err(Unmeasurable::Undeclared));
    }
    if !probe.arch.includes(cell.architecture) {
        return Some(Ok(Measured {
            verdict: Verdict::NotApplicable,
            errno: 0,
        }));
    }
    None
}

fn run_and_classify(probe: &Probe, cell: &Cell) -> Result<Measured, Unmeasurable> {
    let outcome = run_isolated(probe).map_err(Unmeasurable::Harness)?;
    classify(outcome, &probe.oracle, &probe.kernel, cell.kernel.version)
        .map_err(Unmeasurable::NotMeasured)
}

impl Measurement {
    /// Run every probe, sequentially and in corpus order — the snapshots
    /// depend on probes not overlapping.
    pub fn run(probes: &[Probe], corpus_revision: &'static str, mut cell: Cell) -> Measurement {
        let modules_before = loaded_modules();
        cell.kernel.modules = modules_before.clone();
        let run_before = Snapshot::take();

        let mut results = Vec::with_capacity(probes.len());
        let mut unmeasured = Vec::new();
        let mut leaks = Vec::new();
        let mut unverifiable = Vec::new();
        let mut per_probe_sum = [0i64; ResidualClass::ALL.len()];

        for probe in probes {
            // A probe that is refused or not applicable never forks, so
            // nothing is snapshotted around it: whatever moved in that
            // window belongs to the run's audit, not to a probe that did
            // nothing.
            let outcome = match decided_without_running(probe, &cell) {
                Some(decided) => decided,
                None => {
                    for class in ResidualClass::ALL {
                        if probe.effects.declares(class) && run_before.get(class).count().is_none()
                        {
                            unverifiable.push(Unverifiable {
                                probe_id: probe.id,
                                class,
                            });
                        }
                    }
                    let before = Snapshot::take();
                    let outcome = run_and_classify(probe, &cell);
                    // Returns only after waitpid has reaped the child, so
                    // this is the kernel's state after teardown, not on
                    // exit.
                    let after = Snapshot::take();
                    for (class, delta) in ResidualClass::ALL.iter().zip(before.delta(&after)) {
                        if let Some(delta) = delta {
                            per_probe_sum[class.index()] += delta;
                            if delta != 0 {
                                leaks.push(Leak {
                                    probe_id: probe.id,
                                    class: *class,
                                    delta,
                                    declared: probe.effects.declares(*class),
                                });
                            }
                        }
                    }
                    outcome
                }
            };
            match outcome {
                Ok(measured) => results.push(ProbeResult {
                    probe_id: probe.id,
                    measured,
                }),
                Err(why) => unmeasured.push(Unmeasured {
                    probe_id: probe.id,
                    why,
                }),
            }
        }

        let run_after = Snapshot::take();
        let audit = ResidualClass::ALL
            .iter()
            .zip(run_before.delta(&run_after))
            .filter_map(|(class, run_delta)| {
                let run_delta = run_delta?;
                let per_probe = per_probe_sum[class.index()];
                (per_probe != run_delta).then_some(AuditMismatch {
                    class: *class,
                    per_probe_sum: per_probe,
                    run_delta,
                })
            })
            .collect();
        // After the final snapshot: what the janitor removes has been
        // measured and attributed already. Each removal is a forked child
        // (`crate::residual`), so a filter that kills it kills a child.
        let removed = janitor();
        let module_delta = match (modules_before, loaded_modules()) {
            (Some(before), Some(after)) => Some(ModuleDelta::new(before, after)),
            _ => None,
        };

        Measurement {
            format_version: FORMAT_VERSION,
            corpus_revision,
            cell,
            results,
            unmeasured,
            module_delta,
            residual: Residual {
                observability: run_before.observability(),
                before: run_before,
                after: run_after,
                leaks,
                unverifiable,
                audit,
                janitor: removed,
            },
        }
    }
}
