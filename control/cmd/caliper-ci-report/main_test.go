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
	"path/filepath"
	"reflect"
	"slices"
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

func TestBuildCellMetricsCountsDistinctExpectationCells(t *testing.T) {
	expectationFinding := control.Finding{Kind: control.ExpectationViolation, ProbeID: "expectation.probe", Family: "network"}
	claimFinding := control.Finding{Kind: control.ClaimViolation, ProbeID: "claim.probe", Family: "filesystem"}
	withExpectation := func(architecture string) evaluation {
		return evaluation{
			fingerprint: control.Fingerprint{Cell: control.Cell{Architecture: architecture}},
			report: control.Report{Findings: control.FindingReport{
				ExpectationViolations: []control.Finding{expectationFinding},
			}},
		}
	}
	claimOnly := evaluation{
		fingerprint: control.Fingerprint{Cell: control.Cell{Architecture: "cell-c"}},
		report: control.Report{Findings: control.FindingReport{
			ClaimViolations: []control.Finding{claimFinding},
		}},
	}

	metrics, err := buildCellMetrics(
		[]evaluation{withExpectation("cell-a"), withExpectation("cell-b"), claimOnly, withExpectation("cell-b")},
		[]string{"cell1.json", "cell2.json", "cell3.json", "cell4.json"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if metrics.FingerprintsEvaluated != 4 || metrics.DistinctCells != 3 {
		t.Errorf("evaluated/distinct cells = %d/%d, want 4/3", metrics.FingerprintsEvaluated, metrics.DistinctCells)
	}
	if metrics.ExpectationViolationCells != 2 || metrics.ThreeCellCriterionMet {
		t.Errorf("expectation-violation cells/criterion = %d/%t, want 2/false", metrics.ExpectationViolationCells, metrics.ThreeCellCriterionMet)
	}
	if metrics.CategoryTotals.ExpectationViolations != 3 || metrics.CategoryTotals.ClaimViolations != 1 {
		t.Errorf("category totals = %#v, want expectation=3 and claim=1", metrics.CategoryTotals)
	}
	if metrics.Cells[2].CategoryCounts.ClaimViolations != 1 || metrics.Cells[2].CategoryCounts.ExpectationViolations != 0 {
		t.Errorf("per-cell category counts = %#v, want claim=1 and expectation=0", metrics.Cells[2].CategoryCounts)
	}
	if !reflect.DeepEqual(metrics.Cells[2].ClaimViolationsByFamily, map[string][]string{"filesystem": {"claim.probe"}}) {
		t.Errorf("claim violations by family = %#v, want filesystem claim.probe", metrics.Cells[2].ClaimViolationsByFamily)
	}
	if !reflect.DeepEqual(metrics.Cells[0].ExpectationViolationsByFamily, map[string][]string{"network": {"expectation.probe"}}) {
		t.Errorf("expectation violations by family = %#v, want network expectation.probe", metrics.Cells[0].ExpectationViolationsByFamily)
	}
	met, err := buildCellMetrics(
		[]evaluation{withExpectation("cell-a"), withExpectation("cell-b"), withExpectation("cell-c")},
		[]string{"cell1.json", "cell2.json", "cell3.json"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !met.ThreeCellCriterionMet || met.ExpectationViolationCells != 3 {
		t.Errorf("three-cell criterion = %t with %d cells, want true with 3", met.ThreeCellCriterionMet, met.ExpectationViolationCells)
	}
}

func TestCellIdentityIgnoresKernelModules(t *testing.T) {
	modulesA := []string{"overlay", "veth"}
	modulesB := []string{"overlay", "veth", "nf_tables"}
	cellA := control.Cell{Architecture: "amd64", Kernel: control.Kernel{Release: "6.12.1", Modules: &modulesA}}
	cellB := control.Cell{Architecture: "amd64", Kernel: control.Kernel{Release: "6.12.1", Modules: &modulesB}}
	gotA, err := cellIdentityChecked(cellA)
	if err != nil {
		t.Fatal(err)
	}
	gotB, err := cellIdentityChecked(cellB)
	if err != nil {
		t.Fatal(err)
	}
	if gotA != gotB {
		t.Fatalf("cell identity changed with kernel modules: %s != %s", gotA, gotB)
	}
	cellB.Kernel.Release = "6.12.2"
	gotB, err = cellIdentityChecked(cellB)
	if err != nil {
		t.Fatal(err)
	}
	if gotA == gotB {
		t.Fatal("cell identity ignored kernel release")
	}
}

func TestCommittedFindingMetricsMatchRegeneratedFixtures(t *testing.T) {
	generated := filepath.Join(t.TempDir(), "finding-metrics.json")
	in := inputs{
		posture:  "../../../posture/v1/posture.yaml",
		corpus:   "../../../corpus/index.json",
		manifest: "../../../deploy/k8s/job.yaml",
		tier:     "restricted",
	}
	if err := runCellMetrics("../../../fixtures/cells", generated, in); err != nil {
		t.Fatalf("regenerate cell metrics: %v", err)
	}
	got, err := os.ReadFile(generated)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("../../../fixtures/metrics/finding-metrics.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("committed finding metrics do not match regenerated cell fixtures")
	}
}

func TestAFALGRuntimeDefaultRestrictedDemonstration(t *testing.T) {
	// Cell 4's containerd 1.7.12 RuntimeDefault predates any AF_ALG deny.
	for _, cell := range []struct{ fixture, runtimeVersion string }{
		{"cell2.json", "2.2.1"},
		{"cell4.json", "1.7.12"},
	} {
		t.Run(cell.fixture, func(t *testing.T) {
			testAFALGDemonstration(t, cell.fixture, cell.runtimeVersion)
		})
	}
}

func testAFALGDemonstration(t *testing.T, fixture, runtimeVersion string) {
	data, err := os.ReadFile(filepath.Join("../../../fixtures/cells", fixture))
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := control.DecodeFingerprint(data)
	if err != nil {
		t.Fatal(err)
	}
	if got := fingerprint.Cell.RuntimeVersion; got == nil || got.Value != runtimeVersion {
		t.Fatalf("runtime_version = %#v, want %s", got, runtimeVersion)
	}
	// Copy Fail needs algif_aead; the pre-probe snapshot records it absent.
	if modules := fingerprint.Cell.Kernel.Modules; modules == nil || slices.Contains(*modules, "algif_aead") {
		t.Fatalf("pre-probe modules = %v, want a snapshot without algif_aead", modules)
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
	wantModules := []control.ModuleState{{Name: "af_alg", LoadedBefore: new(bool), LoadedByRun: true}}
	if !reflect.DeepEqual(finding.Modules, wantModules) {
		t.Fatalf("AF_ALG modules = %#v, want af_alg loaded by the run", finding.Modules)
	}
	if body := renderReport("test-context", evaluation); !strings.Contains(body, "[CVE-2026-31431](https://nvd.nist.gov/vuln/detail/CVE-2026-31431), [CVE-2017-2636](https://nvd.nist.gov/vuln/detail/CVE-2017-2636); af_alg: not loaded before run, loaded by run |") {
		t.Fatalf("rendered report omitted AF_ALG evidence: %s", body)
	}
}

// The same admitted workload on GKE, whose containerd 2.2.7 RuntimeDefault
// carries the AF_ALG deny added in 2.2.4: nothing is reported.
func TestAFALGDeniedOnPatchedRuntimeDefault(t *testing.T) {
	data, err := os.ReadFile("../../../fixtures/gke-cos-containerd-2.2.7.json")
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
	var result *control.ProbeResult
	for i := range evaluation.fingerprint.Results {
		if evaluation.fingerprint.Results[i].ProbeID == "socket.family.af_alg" {
			result = &evaluation.fingerprint.Results[i]
		}
	}
	if result == nil || result.Verdict != "denied" || result.Errno != 1 {
		t.Fatalf("AF_ALG result = %#v, want denied with EPERM", result)
	}
	findings := evaluation.report.Findings
	for _, category := range [][]control.Finding{findings.ExpectationViolations, findings.ClaimViolations, findings.UndeclaredExposures} {
		for _, finding := range category {
			if finding.ProbeID == "socket.family.af_alg" {
				t.Fatalf("denied AF_ALG produced a finding: %#v", finding)
			}
		}
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
