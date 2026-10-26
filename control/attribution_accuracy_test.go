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

package control

import "testing"

func TestAttributionAccuracyScoresEveryDenialAgainstItsEnvironment(t *testing.T) {
	zero := uint64(0)
	corpus := []ProbeMetadata{
		{ID: "a", Family: "socket", Oracle: Oracle{Isolates: "seccomp"}},
		{ID: "b", Family: "socket", Oracle: Oracle{Isolates: "seccomp-or-lsm"}},
		{ID: "c", Family: "socket", Oracle: Oracle{Isolates: "seccomp-or-lsm"}},
		{ID: "d", Family: "clone", Oracle: Oracle{Isolates: "seccomp"}},
	}
	fp := func(seccompMode *uint64, results ...ProbeResult) Fingerprint {
		cell := Cell{LSM: "none"}
		if seccompMode != nil {
			cell.Seccomp = &SeccompState{Mode: seccompMode}
		}
		return Fingerprint{Cell: cell, Results: results}
	}
	truth := AttributionGroundTruth{Environments: []AttributionGroundTruthEnvironment{
		{Name: "seccomp", Mechanism: Seccomp},
		{Name: "lsm", Mechanism: LSM},
	}}
	// The control run denies d on its own, so d with that errno is left out
	// everywhere; c with another errno is not.
	control := fp(&zero, ProbeResult{ProbeID: "d", Verdict: "denied", Errno: 1},
		ProbeResult{ProbeID: "c", Verdict: "denied", Errno: 14})
	fingerprints := map[string]Fingerprint{
		"seccomp": fp(nil,
			ProbeResult{ProbeID: "a", Verdict: "denied", Errno: errnoENOSYS},
			ProbeResult{ProbeID: "b", Verdict: "denied", Errno: 1},
			ProbeResult{ProbeID: "c", Verdict: "permitted"},
			ProbeResult{ProbeID: "d", Verdict: "denied", Errno: 1}),
		// EACCES with no confining label stays undecidable.
		"lsm": fp(&zero, ProbeResult{ProbeID: "c", Verdict: "denied", Errno: 13}),
	}
	m, err := EvaluateAttributionAccuracy(truth, control, fingerprints, corpus)
	if err != nil {
		t.Fatal(err)
	}
	if m.Denials != 3 || m.ExcludedByControl != 1 {
		t.Fatalf("denials/excluded = %d/%d, want 3/1", m.Denials, m.ExcludedByControl)
	}
	if m.CorrectAttributions != 2 || m.AttributedDenials != 2 || m.Undecidable != 1 {
		t.Fatalf("correct/attributed/undecidable = %d/%d/%d, want 2/2/1", m.CorrectAttributions, m.AttributedDenials, m.Undecidable)
	}
	if m.WithoutElimination != (WithoutElimination{CorrectAttributions: 1, Undecidable: 2}) {
		t.Fatalf("without cell elimination = %+v, want 1 correct and 2 undecidable", m.WithoutElimination)
	}
	if !m.ENOSYSFilterIncluded || !m.LSMOnlyIncluded {
		t.Fatalf("ENOSYS/LSM-only included = %t/%t, want both", m.ENOSYSFilterIncluded, m.LSMOnlyIncluded)
	}
	if !m.AccuracyCriterionMet || m.UndecidableCriterionMet {
		t.Fatalf("criteria = %t/%t, want accuracy met and undecidable not", m.AccuracyCriterionMet, m.UndecidableCriterionMet)
	}

	truth.Environments[0].Mechanism = "filter"
	if _, err := EvaluateAttributionAccuracy(truth, control, fingerprints, corpus); err == nil {
		t.Fatal("accepted an unknown mechanism")
	}
}
