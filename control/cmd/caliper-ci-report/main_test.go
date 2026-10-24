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
	"io"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/Abhinavmadake/caliper/control"
	batchv1 "k8s.io/api/batch/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
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

func TestRenderReportManyCountsDistinctExpectationCells(t *testing.T) {
	expectationFinding := control.Finding{Kind: control.ExpectationViolation, ProbeID: "expectation.probe", Family: "network"}
	claimFinding := control.Finding{Kind: control.ClaimViolation, ProbeID: "claim.probe", Family: "filesystem"}
	withExpectation := evaluation{report: control.Report{Findings: control.FindingReport{
		ExpectationViolations: []control.Finding{expectationFinding},
	}}}
	claimOnly := evaluation{report: control.Report{Findings: control.FindingReport{
		ClaimViolations: []control.Finding{claimFinding},
	}}}

	tests := []struct {
		name        string
		clusters    []string
		evaluations []evaluation
		wantCount   string
		wantStatus  string
		wantClaim   string
	}{
		{
			name:        "criterion needs three distinct contexts with expectation findings",
			clusters:    []string{"cluster-a", "cluster-b", "cluster-c"},
			evaluations: []evaluation{withExpectation, withExpectation, claimOnly},
			wantCount:   "**Cells with expectation violations:** 2",
			wantStatus:  "**Three-cell criterion:** not met",
			wantClaim:   "### Claim violations (1)",
		},
		{
			name:        "repeated context does not count as another cell",
			clusters:    []string{"cluster-a", "cluster-b", "cluster-c", "cluster-c"},
			evaluations: []evaluation{withExpectation, withExpectation, withExpectation, withExpectation},
			wantCount:   "**Cells with expectation violations:** 3",
			wantStatus:  "**Three-cell criterion:** met",
			wantClaim:   "### Claim violations (0)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := renderReportMany(tt.clusters, tt.evaluations)
			for _, want := range []string{
				tt.wantCount,
				tt.wantStatus,
				"| Cell | Expectation violations | Claim violations | Undeclared exposures |",
				"### Expectation violations (1)",
				tt.wantClaim,
				"| `cluster-a` | 1 | 0 | 0 |",
			} {
				if !strings.Contains(body, want) {
					t.Errorf("multi-cell report lacks %q", want)
				}
			}
		})
	}
}

func TestAFALGRuntimeDefaultRestrictedDemonstration(t *testing.T) {
	data, err := os.ReadFile("../../../fixtures/cells/cell2.json")
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
	demonstrationSpec := jobSpec(t, "../../../deploy/k8s/af-alg-demonstration.yaml")
	standardSpec := jobSpec(t, "../../../deploy/k8s/job.yaml")
	if !reflect.DeepEqual(demonstrationSpec, standardSpec) {
		t.Fatalf("demonstration Job spec drifted from deploy/k8s/job.yaml:\n demo=%#v\n base=%#v", demonstrationSpec, standardSpec)
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

func jobSpec(t *testing.T, path string) batchv1.JobSpec {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	decoder := utilyaml.NewYAMLOrJSONDecoder(file, 4096)
	for {
		object := map[string]interface{}{}
		err := decoder.Decode(&object)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if object["kind"] != "Job" {
			continue
		}
		var job batchv1.Job
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(object, &job); err != nil {
			t.Fatal(err)
		}
		return job.Spec
	}
	t.Fatalf("%s contains no Job", path)
	return batchv1.JobSpec{}
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
