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

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompleteFingerprintEnrichesProbeMeasurement(t *testing.T) {
	const raw = `{
		"format_version": 1,
		"corpus_revision": "0.1.0",
		"cell": {
			"architecture": "x86_64",
			"kernel": {"release": "6.8.0", "version": {"major": 6, "minor": 8}, "modules": null},
			"lsm": "apparmor",
			"capabilities": {"effective": "0000000000000000"}
		},
		"results": [{"probe_id": "socket.test", "verdict": "permitted", "errno": 0}],
		"unmeasured": [],
		"module_delta": {"before": ["nf_tables"], "after": ["nf_tables"]},
		"residual": {"leaks": [], "audit": []}
	}`

	var probe ProbeMeasurement
	if err := json.Unmarshal([]byte(raw), &probe); err != nil {
		t.Fatalf("decode probe measurement: %v", err)
	}
	completed := CompleteFingerprint(probe, CellMetadata{
		Distribution:      &SourcedValue{Value: "Ubuntu 24.04", Source: "node-object"},
		Runtime:           &SourcedValue{Value: "containerd", Source: "node-object"},
		RuntimeVersion:    &SourcedValue{Value: "2.2.0", Source: "node-object"},
		RuntimeClass:      &SourcedValue{Value: "runc", Source: "pod-spec"},
		NodeKernelVersion: "6.8.0-node",
	})

	if completed.Cell.Architecture != "x86_64" || completed.Cell.LSM != "apparmor" {
		t.Errorf("probe cell facts = %#v", completed.Cell)
	}
	if completed.Cell.Distribution.Value != "Ubuntu 24.04" || completed.Cell.Runtime.Value != "containerd" || completed.Cell.RuntimeVersion.Value != "2.2.0" {
		t.Errorf("control-plane facts = %#v", completed.Cell)
	}
	if completed.Cell.RuntimeClass.Source != "pod-spec" || completed.Cell.Kernel.SandboxClaimed == nil || !*completed.Cell.Kernel.SandboxClaimed {
		t.Errorf("Node kernel comparison = %#v", completed.Cell)
	}
	if len(completed.Results) != 1 || completed.Results[0].ProbeID != "socket.test" {
		t.Errorf("results = %#v", completed.Results)
	}

	data, err := json.Marshal(completed)
	if err != nil {
		t.Fatalf("encode completed fingerprint: %v", err)
	}
	var output map[string]any
	if err := json.Unmarshal(data, &output); err != nil {
		t.Fatalf("decode completed fingerprint: %v", err)
	}
	cell := output["cell"].(map[string]any)
	kernel := cell["kernel"].(map[string]any)
	if cell["capabilities"] == nil || kernel["version"].(map[string]any)["major"] != float64(6) {
		t.Errorf("probe cell fields were dropped: %s", data)
	}
	if output["module_delta"] == nil || output["residual"] == nil {
		t.Errorf("engine fields were dropped: %s", data)
	}
}

func TestCompleteCellDerivesSandboxClaimFromNodeKernel(t *testing.T) {
	probe := ProbeCell{Kernel: Kernel{Release: "6.8.0-sandbox"}}

	claimed := CompleteCell(probe, CellMetadata{NodeKernelVersion: "6.8.0-node"})
	if claimed.Kernel.SandboxClaimed == nil || !*claimed.Kernel.SandboxClaimed {
		t.Errorf("sandbox_claimed = %v, want true for differing kernel releases", claimed.Kernel.SandboxClaimed)
	}

	notClaimed := CompleteCell(probe, CellMetadata{NodeKernelVersion: "6.8.0-sandbox"})
	if notClaimed.Kernel.SandboxClaimed == nil || *notClaimed.Kernel.SandboxClaimed {
		t.Errorf("sandbox_claimed = %v, want false for matching kernel releases", notClaimed.Kernel.SandboxClaimed)
	}

	unknown := CompleteCell(probe, CellMetadata{})
	if unknown.Kernel.SandboxClaimed != nil {
		t.Errorf("sandbox_claimed = %v, want unset without Node kernelVersion", *unknown.Kernel.SandboxClaimed)
	}
}

func TestCompleteFingerprintOmitsUnavailableMetadata(t *testing.T) {
	completed := CompleteFingerprint(ProbeMeasurement{
		Cell: ProbeCell{Architecture: "x86_64", Kernel: Kernel{Release: "6.8.0"}},
	}, CellMetadata{})
	data, err := json.Marshal(completed)
	if err != nil {
		t.Fatalf("encode completed fingerprint: %v", err)
	}
	var output map[string]any
	if err := json.Unmarshal(data, &output); err != nil {
		t.Fatalf("decode completed fingerprint: %v", err)
	}
	cell := output["cell"].(map[string]any)
	for _, key := range []string{"distribution", "runtime", "runtime_version", "runtime_class"} {
		if _, exists := cell[key]; exists {
			t.Errorf("cell unexpectedly contains unavailable %q: %s", key, data)
		}
	}
	kernel := cell["kernel"].(map[string]any)
	if _, exists := kernel["sandbox_claimed"]; exists {
		t.Errorf("kernel unexpectedly contains sandbox_claimed without Node kernelVersion: %s", data)
	}
}

func TestDiffRecordedFixtures(t *testing.T) {
	baseline := loadFixture(t, "x86_64-apparmor.json")

	t.Run("runtime version divergence preserves both errno values", func(t *testing.T) {
		olderRuntime := loadFixture(t, "x86_64-apparmor-1.7.12.json")
		diff := mustDiff(t, baseline, olderRuntime)

		if len(diff.Divergences) != 1 {
			t.Fatalf("divergences = %d, want 1", len(diff.Divergences))
		}
		got := diff.Divergences[0]
		if got.ProbeID != "io_uring.opcode.sendmsg_zc" {
			t.Errorf("probe_id = %q", got.ProbeID)
		}
		if got.Left.Verdict != "denied" || got.Left.Errno != 1 {
			t.Errorf("left = %#v, want denied with errno 1", got.Left)
		}
		if got.Right.Verdict != "permitted" || got.Right.Errno != 0 {
			t.Errorf("right = %#v, want permitted with errno 0", got.Right)
		}
	})

	t.Run("policy fixture compares individual probes, not families", func(t *testing.T) {
		hardened := loadFixture(t, "x86_64-apparmor-hardened.json")
		diff := mustDiff(t, baseline, hardened)

		if len(diff.Divergences) != 120 {
			t.Fatalf("divergences = %d, want 120", len(diff.Divergences))
		}
		byID := make(map[string]Divergence, len(diff.Divergences))
		for _, d := range diff.Divergences {
			byID[d.ProbeID] = d
		}
		got, ok := byID["mount.reach"]
		if !ok {
			t.Fatal("mount.reach did not diverge")
		}
		if got.Left.Verdict != "denied" || got.Left.Errno != 1 || got.Right.Verdict != "killed" {
			t.Errorf("mount.reach = %#v, want denied errno 1 against killed", got)
		}
		if _, ok := byID["mount.type.proc"]; ok {
			t.Error("mount.type.proc diverged, but its verdict is the same on both sides")
		}
	})
}

func TestDiffSeparatesCorpusSkew(t *testing.T) {
	left := testFingerprint([]ProbeResult{
		{ProbeID: "shared", Verdict: "denied", Errno: 1},
		{ProbeID: "only-left", Verdict: "permitted"},
	})
	right := testFingerprint([]ProbeResult{
		{ProbeID: "shared", Verdict: "permitted"},
		{ProbeID: "only-right", Verdict: "denied", Errno: 13},
	})

	diff := mustDiff(t, left, right)
	if len(diff.Divergences) != 1 || diff.Divergences[0].ProbeID != "shared" {
		t.Errorf("divergences = %#v, want only shared", diff.Divergences)
	}
	if len(diff.CorpusSkew.OnlyLeft) != 1 || diff.CorpusSkew.OnlyLeft[0].ProbeID != "only-left" {
		t.Errorf("only_left = %#v", diff.CorpusSkew.OnlyLeft)
	}
	if len(diff.CorpusSkew.OnlyRight) != 1 || diff.CorpusSkew.OnlyRight[0].ProbeID != "only-right" {
		t.Errorf("only_right = %#v", diff.CorpusSkew.OnlyRight)
	}
}

func TestDiffDoesNotTreatErrnoOnlyChangeAsDivergence(t *testing.T) {
	diff := mustDiff(t,
		testFingerprint([]ProbeResult{{ProbeID: "socket.family.af_alg", Verdict: "denied", Errno: 1}}),
		testFingerprint([]ProbeResult{{ProbeID: "socket.family.af_alg", Verdict: "denied", Errno: 13}}),
	)
	if len(diff.Divergences) != 0 {
		t.Errorf("divergences = %#v, want none", diff.Divergences)
	}
}

func TestDiffRejectsDuplicateProbeIDs(t *testing.T) {
	_, err := Diff(
		testFingerprint([]ProbeResult{{ProbeID: "socket.family.af_alg"}, {ProbeID: "socket.family.af_alg"}}),
		testFingerprint(nil),
	)
	if err == nil || !strings.Contains(err.Error(), "duplicate probe_id") {
		t.Fatalf("Diff error = %v, want duplicate probe_id", err)
	}
}

func TestDiffSeparatesUnmeasuredProbesFromCorpusSkew(t *testing.T) {
	left := testFingerprint([]ProbeResult{{ProbeID: "measured", Verdict: "permitted"}})
	left.Unmeasured = []Unmeasured{{ProbeID: "crashed", Why: json.RawMessage(`{"not-measured":{"crashed":{"signal":11}}}`)}}
	right := testFingerprint([]ProbeResult{
		{ProbeID: "measured", Verdict: "denied", Errno: 1},
		{ProbeID: "crashed", Verdict: "permitted"},
	})

	diff := mustDiff(t, left, right)
	if len(diff.CorpusSkew.OnlyLeft) != 0 || len(diff.CorpusSkew.OnlyRight) != 0 {
		t.Errorf("corpus skew = %#v, want none", diff.CorpusSkew)
	}
	if len(diff.Unmeasured) != 1 {
		t.Fatalf("unmeasured = %#v, want one entry", diff.Unmeasured)
	}
	got := diff.Unmeasured[0]
	if got.ProbeID != "crashed" || got.Left == nil || got.RightResult == nil {
		t.Errorf("unmeasured = %#v, want crashed with left reason and right result", got)
	}
	if len(diff.Divergences) != 1 || diff.Divergences[0].ProbeID != "measured" {
		t.Errorf("divergences = %#v, want only measured", diff.Divergences)
	}
}

func TestDiffRejectsUnsupportedFormatVersion(t *testing.T) {
	left := testFingerprint(nil)
	left.FormatVersion = SupportedFormatVersion + 1
	_, err := Diff(left, testFingerprint(nil))
	if err == nil || !strings.Contains(err.Error(), "unsupported format_version") {
		t.Fatalf("Diff error = %v, want unsupported format_version", err)
	}
}

func TestDiffRejectsMeasuredUnmeasuredOverlap(t *testing.T) {
	left := testFingerprint([]ProbeResult{{ProbeID: "socket.family.af_alg", Verdict: "denied", Errno: 1}})
	left.Unmeasured = []Unmeasured{{ProbeID: "socket.family.af_alg"}}
	_, err := Diff(left, testFingerprint(nil))
	if err == nil || !strings.Contains(err.Error(), "both results and unmeasured") {
		t.Fatalf("Diff error = %v, want measured/unmeasured overlap", err)
	}
}

func loadFixture(t *testing.T, name string) Fingerprint {
	t.Helper()
	path := filepath.Join("..", "fixtures", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	var fingerprint Fingerprint
	if err := json.Unmarshal(data, &fingerprint); err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return fingerprint
}

func testFingerprint(results []ProbeResult) Fingerprint {
	return Fingerprint{FormatVersion: SupportedFormatVersion, Results: results}
}

func mustDiff(t *testing.T, left, right Fingerprint) DiffResult {
	t.Helper()
	diff, err := Diff(left, right)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	return diff
}
