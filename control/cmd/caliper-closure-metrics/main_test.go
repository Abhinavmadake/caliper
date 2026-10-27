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

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func fingerprint(mode int, results string) string {
	return fmt.Sprintf(`{"format_version": 1, "corpus_revision": "0.3.3", "corpus_set": "full",
		"cell": {"architecture": "x86_64", "kernel": {"release": "7.0.0"}, "lsm": "none", "seccomp": {"mode": %d}},
		"results": %s, "unmeasured": []}`, mode, results)
}

const findings = `{"posture_revision": "v1", "tier": "untrusted-multi-tenant", "expectation_violations": [
	{"kind": "expectation-violation", "posture_revision": "v1", "tier": "untrusted-multi-tenant", "family": "socket", "probe_id": "socket.family.af_alg", "verdict": "permitted"},
	{"kind": "expectation-violation", "posture_revision": "v1", "tier": "untrusted-multi-tenant", "family": "netlink", "probe_id": "netlink.protocol.xfrm", "verdict": "permitted"},
	{"kind": "expectation-violation", "posture_revision": "v1", "tier": "untrusted-multi-tenant", "family": "path", "probe_id": "path.masked.proc_kcore", "verdict": "permitted"}],
	"claim_violations": [], "undeclared_exposures": []}`

const remediation = `{"posture_revision": "v1", "tier": "untrusted-multi-tenant",
	"closures": [{"probe_id": "socket.family.af_alg"}, {"probe_id": "netlink.protocol.xfrm"}],
	"not_closable": [{"probe_id": "path.masked.proc_kcore", "reason": "pointer"}]}`

func writeCell(t *testing.T, dir, name string, mode int, reprobe string) {
	t.Helper()
	files := map[string]string{
		name + ".json":                    fingerprint(mode, `[]`),
		name + "-remediated.json":         fingerprint(mode, reprobe),
		"pipeline/baseline.findings.json": findings,
		"pipeline/remediation.json":       remediation,
	}
	for file, content := range files {
		path := filepath.Join(dir, name, file)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestClosureRateSeparatesSeccompFromOther(t *testing.T) {
	dir := t.TempDir()
	writeCell(t, dir, "cell2", 2, `[{"probe_id": "socket.family.af_alg", "verdict": "denied", "errno": 1},
		{"probe_id": "netlink.protocol.xfrm", "verdict": "denied", "errno": 1},
		{"probe_id": "path.masked.proc_kcore", "verdict": "permitted", "errno": 0}]`)
	writeCell(t, dir, "cell6", 0, `[{"probe_id": "socket.family.af_alg", "verdict": "permitted", "errno": 0},
		{"probe_id": "netlink.protocol.xfrm", "verdict": "permitted", "errno": 0},
		{"probe_id": "path.masked.proc_kcore", "verdict": "permitted", "errno": 0}]`)
	m, err := computeMetrics(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !m.SeccompCriterionMet || m.Seccomp.Findings != 2 || m.Seccomp.Closed != 2 || *m.Seccomp.ClosureRate != 1 {
		t.Fatalf("seccomp = %+v, met %t", m.Seccomp, m.SeccompCriterionMet)
	}
	if m.Other.Findings != 4 || m.Other.Closed != 0 {
		t.Fatalf("other = %+v, want 4 findings, none closed", m.Other)
	}
	if got := m.Cells[1].Findings[0]; got.Mechanism != "other" || got.Reason != unenforcedReason {
		t.Fatalf("cell6 af_alg = %+v, want other because seccomp is not applied", got)
	}

	writeCell(t, dir, "cell2", 2, `[{"probe_id": "socket.family.af_alg", "verdict": "permitted", "errno": 0},
		{"probe_id": "netlink.protocol.xfrm", "verdict": "denied", "errno": 1},
		{"probe_id": "path.masked.proc_kcore", "verdict": "permitted", "errno": 0}]`)
	if m, err = computeMetrics(dir); err != nil {
		t.Fatal(err)
	}
	if m.SeccompCriterionMet || m.Seccomp.Closed != 1 {
		t.Fatalf("open seccomp closure: seccomp = %+v, met %t", m.Seccomp, m.SeccompCriterionMet)
	}

	writeCell(t, dir, "cell2", 2, `[{"probe_id": "socket.family.af_alg", "verdict": "denied", "errno": 1}]`)
	if _, err := computeMetrics(dir); err == nil {
		t.Fatal("accepted a finding that was not re-probed")
	}
}

func TestCommittedClosureMetricsMatchRegeneratedFixtures(t *testing.T) {
	metrics, err := computeMetrics("../../../fixtures/pipeline")
	if err != nil {
		t.Fatalf("regenerate closure metrics: %v", err)
	}
	if !metrics.SeccompCriterionMet {
		t.Fatalf("seccomp = %+v, want every closure verified", metrics.Seccomp)
	}
	got, err := json.MarshalIndent(metrics, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	want, err := os.ReadFile("../../../fixtures/metrics/closure-metrics.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("committed closure metrics do not match regenerated pipeline fixtures")
	}
}
