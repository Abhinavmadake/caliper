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

// Package control is the CALIPER control plane.
//
// The engine and corpus produce a raw measurement; this half completes it into
// a fingerprint, diffs fingerprints across environment cells, classifies every
// divergence, evaluates a fingerprint against the declared manifest and the
// reference posture, and emits remediation. The two halves meet at the
// fingerprint format and nowhere else (proposal §5).
//
// This file is scaffolding only: it establishes the module so that the CI
// `control` job builds, vets and tests something, and so that C is not setting
// up a Go workspace from nothing. The package layout is C's to decide as the
// issues land — nothing here presumes it.
//
//   - Fingerprint handling and version negotiation   #24, #25
//   - Diff engine at probe granularity               #26
//   - Divergence classifier                          #27, and the project's
//     contribution rather than a correction
//   - Manifest parsing and the evaluator             #33, #34
//   - Reporting in JSON and human-readable form      #35
//   - Remediation generator (D)                      #36
//
// The format this package consumes is specified in spec/fingerprint.md, with a
// worked example in spec/examples/fingerprint.json. Read the serialisation
// conventions there before writing a parser: object keys are snake_case,
// enumerated values are kebab-case, and every control-plane field carries the
// source it came from.
package control
