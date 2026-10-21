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

//! `caliper-probe` is the whole of the probe image: a static binary and
//! nothing else. No argument parser crate — `std::env::args` is enough for
//! four flags, and every dependency is a source of syscalls to account for.

use std::io::Write;
use std::process::ExitCode;

use caliper_engine::{Cell, Measurement, Unmeasurable};

const USAGE: &str = "\
usage: caliper-probe <mode>

  --run            measure: run every probe in the corpus and emit the
                   probe-side half of a fingerprint as JSON (#8), with the
                   module delta and residual-state report (#9). Probes that
                   produced no verdict are listed under `unmeasured` and
                   left out of the results, never recorded as one
  --reduced        measure: run the alert-safe reduced corpus, omitting probes
                   that may trigger alerts (e.g., AF_ALG module autoloading)
  --noop           start up, do nothing, exit. Establishes the engine's own
                   syscall footprint under strace (issue #4)
  --dump-corpus    emit the compiled-in corpus as JSON. An output, never an
                   input (spec/probe.md)
  --version        print the version and exit

exit status: 0 measured; 3 measured with defects (a probe other than a
deferred one unmeasured, or an undeclared object left behind), the document
still written; 1 could not measure; 2 usage
";

/// Measured, but the run has defects worth failing on (#99): the document
/// is complete and on stdout.
const EXIT_DEFECTS: u8 = 3;

fn main() -> ExitCode {
    if let Err(e) = caliper_engine::init() {
        eprintln!("caliper-probe: init: {e}");
        return ExitCode::FAILURE;
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["--run"] => run(false),
        ["--reduced"] => run(true),
        ["--noop"] => ExitCode::SUCCESS,
        ["--dump-corpus"] => dump_corpus(),
        ["--version"] => {
            println!("caliper-probe {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        _ => {
            let _ = std::io::stderr().write_all(USAGE.as_bytes());
            ExitCode::from(2)
        }
    }
}

fn run(reduced: bool) -> ExitCode {
    let cell = match Cell::detect() {
        Ok(cell) => cell,
        Err(e) => {
            eprintln!("caliper-probe: cell: {e}");
            return ExitCode::FAILURE;
        }
    };
    let all_probes = caliper_corpus::probes();
    let probes: Vec<_> = if reduced {
        all_probes
            .iter()
            .filter(|p| !p.effects.may_autoload_module())
            .cloned()
            .collect()
    } else {
        all_probes.to_vec()
    };

    let set: &'static str = if reduced { "reduced" } else { "full" };

    let m = Measurement::run(&probes, caliper_corpus::REVISION, set, cell);
    // Everything below is also in the document; stderr is for the person
    // watching the run, and for a corpus defect to be loud.
    for u in m
        .unmeasured
        .iter()
        .filter(|u| u.why != Unmeasurable::Deferred)
    {
        eprintln!("caliper-probe: {}: not measured: {:?}", u.probe_id, u.why);
    }
    for l in &m.residual.leaks {
        let tag = if l.declared { "declared" } else { "UNDECLARED" };
        eprintln!(
            "caliper-probe: {}: residual {:?} {:+} ({tag})",
            l.probe_id, l.class, l.delta
        );
    }
    for r in &m.residual.janitor {
        if r.removed {
            eprintln!("caliper-probe: janitor removed {:?} {}", r.class, r.object);
        } else {
            eprintln!(
                "caliper-probe: janitor COULD NOT remove {:?} {}: {:?}",
                r.class, r.object, r.attempt
            );
        }
    }
    let defects = m
        .unmeasured
        .iter()
        .any(|u| u.why != Unmeasurable::Deferred)
        // A negative delta is something gone, not something left behind.
        || m.residual.leaks.iter().any(|l| !l.declared && l.delta > 0);
    match (write_json(&m), defects) {
        (false, _) => ExitCode::FAILURE,
        (true, true) => ExitCode::from(EXIT_DEFECTS),
        (true, false) => ExitCode::SUCCESS,
    }
}

fn dump_corpus() -> ExitCode {
    emit(caliper_corpus::probes())
}

fn emit<T: serde::Serialize + ?Sized>(value: &T) -> ExitCode {
    if write_json(value) {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn write_json<T: serde::Serialize + ?Sized>(value: &T) -> bool {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    match serde_json::to_writer_pretty(&mut out, value) {
        Ok(()) => {
            let _ = out.write_all(b"\n");
            true
        }
        Err(e) => {
            eprintln!("caliper-probe: {e}");
            false
        }
    }
}
