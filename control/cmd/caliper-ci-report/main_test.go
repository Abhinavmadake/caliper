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
	"os"
	"strings"
	"testing"

	"github.com/Abhinavmadake/caliper/control"
)

func TestEvaluateAndRenderRecordedFixture(t *testing.T) {
	data, err := os.ReadFile("../../../fixtures/x86_64-apparmor.json")
	if err != nil {
		t.Fatal(err)
	}
	fp, err := control.DecodeFingerprint(data)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := evaluate(fp, inputs{
		posture:  "../../../posture/v1/posture.yaml",
		corpus:   "../../../corpus/index.json",
		manifest: "../../../deploy/k8s/job.yaml",
		tier:     "restricted",
	})
	if err != nil {
		t.Fatal(err)
	}
	if ev.report.Attribution.Denials == 0 {
		t.Fatal("no denials attributed")
	}
	body := renderReport("test-context", ev)
	for _, want := range []string{
		reportMarker,
		"**Posture:** `v1`, tier `restricted`, workload `Job/caliper-probe`",
		"### Expectation violations (",
		"### Claim violations (",
		"### Undeclared exposures (",
		"- **socket** (",
		"Undecidable: ",
		"| `socket.family.af_alg` | `permitted` |",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("report lacks %q", want)
		}
	}
	if os.Getenv("CALIPER_SHOW_REPORT") != "" {
		t.Log(body)
	}
}

func TestAFALGRuntimeDefaultRestrictedDemonstration(t *testing.T) {
	data, err := os.ReadFile("../../../fixtures/x86_64-apparmor.json")
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := control.DecodeFingerprint(data)
	if err != nil {
		t.Fatal(err)
	}
	evaluation, err := evaluate(fingerprint, inputs{
		posture:  "../../../posture/v1/posture.yaml",
		corpus:   "../../../corpus/index.json",
		manifest: "../../../deploy/k8s/af-alg-demonstration.yaml",
		tier:     "untrusted-multi-tenant",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := evaluation.workload.PodSecurityStandard; got == nil || got.Enforce == nil || got.Enforce.Level != "restricted" {
		t.Fatalf("workload PSS = %#v, want Restricted", got)
	}
	if len(evaluation.workload.Pod.Containers) != 1 {
		t.Fatalf("containers = %d, want 1", len(evaluation.workload.Pod.Containers))
	}
	if seccomp := evaluation.workload.Pod.EffectiveSeccomp(evaluation.workload.Pod.Containers[0]); seccomp == nil || seccomp.Type != "RuntimeDefault" || !seccomp.RuntimeDefined {
		t.Fatalf("effective seccomp = %#v, want RuntimeDefault", seccomp)
	}

	var finding *control.Finding
	for i := range evaluation.report.Findings.ExpectationViolations {
		candidate := &evaluation.report.Findings.ExpectationViolations[i]
		if candidate.ProbeID == "socket.family.af_alg" {
			finding = candidate
			break
		}
	}
	if finding == nil || finding.Kind != control.ExpectationViolation || finding.Verdict != "permitted" {
		t.Fatalf("AF_ALG finding = %#v, want permitted expectation violation", finding)
	}
	for _, category := range [][]control.Finding{
		evaluation.report.Findings.ClaimViolations,
		evaluation.report.Findings.UndeclaredExposures,
	} {
		for _, candidate := range category {
			if candidate.ProbeID == "socket.family.af_alg" {
				t.Fatalf("AF_ALG was misclassified outside expectation violations: %#v", candidate)
			}
		}
	}
	if len(finding.Citations) == 0 || finding.Citations[0].ID != "CVE-2026-31431" {
		t.Fatalf("AF_ALG evidence = %#v, want CVE-2026-31431", finding.Citations)
	}
	if body := renderReport("test-context", evaluation); !strings.Contains(body, "[CVE-2026-31431](https://nvd.nist.gov/vuln/detail/CVE-2026-31431)") {
		t.Fatalf("rendered report omitted AF_ALG evidence: %s", body)
	}
}

func TestReadMeasurementSkipsLeadingDiagnostics(t *testing.T) {
	data, err := os.ReadFile("../../../fixtures/x86_64-apparmor.json")
	if err != nil {
		t.Fatal(err)
	}
	data = bytes.Replace(data, []byte(`"corpus_set": "full"`), []byte(`"corpus_set": "reduced"`), 1)
	path := t.TempDir() + "/log"
	logged := append([]byte("caliper-probe: x: not measured: Undeclared\n"), data...)
	if err := os.WriteFile(path, logged, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readMeasurement(path); err != nil {
		t.Fatal(err)
	}
}
