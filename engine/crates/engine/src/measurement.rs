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
//! document the probe emits at the end (#8). It is the probe-side half of a
//! fingerprint (`spec/fingerprint.md`): identity, the cell fields the probe
//! can see, and one result per probe carrying the verdict and raw errno.
//! No `attribution`, no control-plane cell fields, no `digest` — the
//! control plane completes the fingerprint and computes those, and the
//! engine "stores no interpretation" (§5). Field names follow the spec's
//! worked example so C's parser reads this as it reads the fixtures.
//!
//! `module_delta` is #9's and is not here yet.

use serde::Serialize;

use crate::cell::Cell;
use crate::harness::run_isolated;
use crate::probe::Probe;
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

/// What the probe emits for `--run`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Measurement {
    pub format_version: u32,
    /// Which corpus produced the run: the corpus crate's version.
    pub corpus_revision: &'static str,
    pub cell: Cell,
    pub results: Vec<ProbeResult>,
}

/// A probe that produced no verdict, reported alongside the measurement
/// and never inside it: an absent probe id is corpus skew downstream,
/// which is the right reading of "the instrument could not measure this".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unmeasured {
    pub probe_id: &'static str,
    pub why: Unmeasurable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unmeasurable {
    /// The child ended in a way that is not a verdict.
    NotMeasured(NotMeasured),
    /// The harness itself failed — fork, pidfd or wait.
    Harness(nix::errno::Errno),
}

/// Measure one probe against `cell`. Applicability is decided here, before
/// any fork: a probe whose entry point does not exist on this architecture
/// is `not-applicable` and is not run.
pub fn measure(probe: &Probe, cell: &Cell) -> Result<Measured, Unmeasurable> {
    if !probe.arch.includes(cell.architecture) {
        return Ok(Measured {
            verdict: Verdict::NotApplicable,
            errno: 0,
        });
    }
    let outcome = run_isolated(probe).map_err(Unmeasurable::Harness)?;
    classify(outcome, &probe.kernel, cell.kernel.version).map_err(Unmeasurable::NotMeasured)
}

impl Measurement {
    /// Run every probe, sequentially and in corpus order (#9's accounting
    /// depends on probes not overlapping). The unmeasured are returned
    /// separately so the caller can report them without recording them.
    pub fn run(
        probes: &[Probe],
        corpus_revision: &'static str,
        cell: Cell,
    ) -> (Measurement, Vec<Unmeasured>) {
        let mut results = Vec::with_capacity(probes.len());
        let mut unmeasured = Vec::new();
        for probe in probes {
            match measure(probe, &cell) {
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
        (
            Measurement {
                format_version: FORMAT_VERSION,
                corpus_revision,
                cell,
                results,
            },
            unmeasured,
        )
    }
}
