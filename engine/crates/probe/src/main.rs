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

use caliper_engine::{Cell, Measurement};

const USAGE: &str = "\
usage: caliper-probe <mode>

  --run            measure: run every probe in the corpus and emit the
                   probe-side half of a fingerprint as JSON (#8). Probes
                   that produced no verdict are listed on stderr and left
                   out of the results, never recorded as one
  --noop           start up, do nothing, exit. Establishes the engine's own
                   syscall footprint under strace (issue #4)
  --dump-corpus    emit the compiled-in corpus as JSON. An output, never an
                   input (spec/probe.md)
  --version        print the version and exit
";

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
        ["--run"] => run(),
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

fn run() -> ExitCode {
    let cell = match Cell::detect() {
        Ok(cell) => cell,
        Err(e) => {
            eprintln!("caliper-probe: cell: {e}");
            return ExitCode::FAILURE;
        }
    };
    let (measurement, unmeasured) =
        Measurement::run(caliper_corpus::probes(), caliper_corpus::REVISION, cell);
    for u in &unmeasured {
        eprintln!("caliper-probe: {}: not measured: {:?}", u.probe_id, u.why);
    }
    emit(&measurement)
}

fn dump_corpus() -> ExitCode {
    emit(caliper_corpus::probes())
}

fn emit<T: serde::Serialize + ?Sized>(value: &T) -> ExitCode {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    match serde_json::to_writer_pretty(&mut out, value) {
        Ok(()) => {
            let _ = out.write_all(b"\n");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("caliper-probe: {e}");
            ExitCode::FAILURE
        }
    }
}
