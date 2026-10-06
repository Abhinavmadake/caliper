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
		selinux := loadFixture(t, "x86_64-selinux.json")
		diff := mustDiff(t, baseline, selinux)

		if len(diff.Divergences) != 1 {
			t.Fatalf("divergences = %d, want 1", len(diff.Divergences))
		}
		got := diff.Divergences[0]
		if got.ProbeID != "mount.fstype.bpf" {
			t.Errorf("probe_id = %q, want mount.fstype.bpf", got.ProbeID)
		}
		if got.Left.Errno != 0 || got.Right.Errno != 13 {
			t.Errorf("errno pair = (%d, %d), want (0, 13)", got.Left.Errno, got.Right.Errno)
		}
	})
}

func TestDiffSeparatesCorpusSkew(t *testing.T) {
	left := Fingerprint{Results: []ProbeResult{
		{ProbeID: "shared", Verdict: "denied", Errno: 1},
		{ProbeID: "only-left", Verdict: "permitted"},
	}}
	right := Fingerprint{Results: []ProbeResult{
		{ProbeID: "shared", Verdict: "permitted"},
		{ProbeID: "only-right", Verdict: "denied", Errno: 13},
	}}

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
		Fingerprint{Results: []ProbeResult{{ProbeID: "socket.family.af_alg", Verdict: "denied", Errno: 1}}},
		Fingerprint{Results: []ProbeResult{{ProbeID: "socket.family.af_alg", Verdict: "denied", Errno: 13}}},
	)
	if len(diff.Divergences) != 0 {
		t.Errorf("divergences = %#v, want none", diff.Divergences)
	}
}

func TestDiffRejectsDuplicateProbeIDs(t *testing.T) {
	_, err := Diff(
		Fingerprint{Results: []ProbeResult{{ProbeID: "socket.family.af_alg"}, {ProbeID: "socket.family.af_alg"}}},
		Fingerprint{},
	)
	if err == nil || !strings.Contains(err.Error(), "duplicate probe_id") {
		t.Fatalf("Diff error = %v, want duplicate probe_id", err)
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

func mustDiff(t *testing.T, left, right Fingerprint) DiffResult {
	t.Helper()
	diff, err := Diff(left, right)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	return diff
}
