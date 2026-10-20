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

func TestMeasureRemediationClosureCountsAnyNonPermittedReprobeAsClosed(t *testing.T) {
	for _, test := range []struct {
		name     string
		original Verdict
		reprobe  Verdict
		closed   bool
		status   RemediationClosure
	}{
		{name: "denied remains denied", original: "denied", reprobe: "denied", closed: true, status: ClosureClosed},
		{name: "denied becomes killed", original: "denied", reprobe: "killed", closed: true, status: ClosureClosed},
		{name: "killed becomes errno denial", original: "killed", reprobe: "denied", closed: true, status: ClosureClosed},
		{name: "operation remains permitted", original: "denied", reprobe: "permitted", status: ClosureOpen},
		{name: "unimplemented does not prove closure", original: "denied", reprobe: "unimplemented", status: ClosureUnknown},
	} {
		t.Run(test.name, func(t *testing.T) {
			metric := measureClosureForTest(t, test.original, test.reprobe, testCell("x86_64", "6.8.0", "c20,c30", []string{"module_a"}))
			if metric.Seccomp.Eligible != 1 {
				t.Fatalf("eligible = %d, want 1", metric.Seccomp.Eligible)
			}
			wantClosed := 0
			if test.closed {
				wantClosed = 1
			}
			if metric.Seccomp.Closed != wantClosed {
				t.Errorf("closed = %d, want %d", metric.Seccomp.Closed, wantClosed)
			}
			if got := metric.Observations[0].Closure; got != test.status {
				t.Errorf("closure = %q, want %q", got, test.status)
			}
		})
	}
}

func TestMeasureRemediationClosureMatchesStableCellIdentity(t *testing.T) {
	base := testCell("x86_64", "6.8.0", "c20,c30", []string{"module_a"})
	changedVolatileFields := testCell("x86_64", "6.8.0", "c40,c50", []string{"module_b"})
	metric := measureClosureForTest(t, "denied", "denied", changedVolatileFields)
	if metric.Seccomp.Closed != 1 {
		t.Fatalf("closed = %d, want 1 with changed MCS label and module snapshot", metric.Seccomp.Closed)
	}

	classification, left, right := closureInputs(base, "denied")
	wrongCell := testCell("aarch64", "7.0.0", "c20,c30", []string{"module_a"})
	_, err := MeasureRemediationClosure(classification, left, right, Fingerprint{
		FormatVersion: SupportedFormatVersion,
		Results:       []ProbeResult{{ProbeID: "probe", Verdict: "denied"}},
		Cell:          wrongCell,
	}, true)
	if err == nil {
		t.Fatal("expected a different architecture/kernel identity to be rejected")
	}
}

func TestMeasureRemediationClosureKeepsMissingReprobeInDenominator(t *testing.T) {
	classification, left, right := closureInputs(testCell("x86_64", "6.8.0", "c10,c20", []string{"module_a"}), "denied")
	metric, err := MeasureRemediationClosure(classification, left, right, Fingerprint{
		FormatVersion: SupportedFormatVersion,
		Results:       []ProbeResult{},
		Cell:          right.Cell,
	}, true)
	if err != nil {
		t.Fatalf("MeasureRemediationClosure() error = %v", err)
	}
	if metric.Seccomp.Eligible != 1 || metric.Seccomp.Closed != 0 || metric.Seccomp.Rate == nil || *metric.Seccomp.Rate != 0 {
		t.Errorf("seccomp counts = %#v, want one eligible unclosed probe", metric.Seccomp)
	}
	if got := metric.Observations[0].Closure; got != ClosureUnknown {
		t.Errorf("closure = %q, want %q for a missing re-probe", got, ClosureUnknown)
	}
}

func measureClosureForTest(t *testing.T, original, reprobe Verdict, reprobeCell Cell) RemediationMetric {
	t.Helper()
	classification, left, right := closureInputs(testCell("x86_64", "6.8.0", "c10,c20", []string{"module_a"}), original)
	metric, err := MeasureRemediationClosure(classification, left, right, Fingerprint{
		FormatVersion: SupportedFormatVersion,
		Results:       []ProbeResult{{ProbeID: "probe", Verdict: reprobe}},
		Cell:          reprobeCell,
	}, true)
	if err != nil {
		t.Fatalf("MeasureRemediationClosure() error = %v", err)
	}
	return metric
}

func closureInputs(target Cell, deniedVerdict Verdict) (ClassificationResult, Fingerprint, Fingerprint) {
	mechanism := Seccomp
	denied := ProbeResult{
		ProbeID: "probe", Verdict: deniedVerdict,
		Attribution: &Attribution{Mechanism: &mechanism, Confidence: High},
	}
	left := Fingerprint{
		FormatVersion: SupportedFormatVersion,
		Results:       []ProbeResult{denied},
		Cell:          target,
	}
	rightCell := target
	rightCell.LSMLabel = stringPointer("container_t:s0:c1,c2")
	rightCell.Kernel.Modules = stringSlicePointer([]string{"module_a"})
	right := Fingerprint{
		FormatVersion: SupportedFormatVersion,
		Results:       []ProbeResult{{ProbeID: "probe", Verdict: "permitted"}},
		Cell:          rightCell,
	}
	classification := ClassificationResult{Divergences: []ClassifiedDivergence{{
		Divergence: Divergence{ProbeID: "probe", Left: denied, Right: right.Results[0]},
		Class:      PolicyExplained,
	}}}
	return classification, left, right
}

func testCell(architecture, kernelRelease, mcsLabel string, modules []string) Cell {
	return Cell{
		Architecture:   architecture,
		Kernel:         Kernel{Release: kernelRelease, Modules: stringSlicePointer(modules)},
		LSM:            "selinux",
		LSMLabel:       stringPointer("system_u:system_r:container_t:s0:" + mcsLabel),
		LSMEnforcing:   boolPointer(true),
		Distribution:   &SourcedValue{Value: "Linux", Source: "node"},
		Runtime:        &SourcedValue{Value: "containerd", Source: "node"},
		RuntimeVersion: &SourcedValue{Value: "2.2.0", Source: "node"},
		RuntimeClass:   &SourcedValue{Value: "runc", Source: "pod"},
	}
}

func boolPointer(value bool) *bool { return &value }

func stringSlicePointer(value []string) *[]string { return &value }
