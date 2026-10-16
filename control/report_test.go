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
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestBuildReportAndWriteJSON(t *testing.T) {
	seccomp := Seccomp
	findings := FindingReport{
		PostureRevision: "v1",
		Tier:            "untrusted-multi-tenant",
		ExpectationViolations: []Finding{{
			Kind: ExpectationViolation, PostureRevision: "v1", Tier: "untrusted-multi-tenant",
			Family: "socket", ProbeID: "socket.family.af_alg", Verdict: "permitted",
		}},
		ClaimViolations:     []Finding{},
		UndeclaredExposures: []Finding{},
	}
	classification := ClassificationResult{
		Diff: DiffResult{
			CorpusRevisions: CorpusRevisions{Left: "r1", Right: "r2"},
			CorpusSets:      CorpusSets{Left: "full", Right: "reduced"},
			CorpusSkew:      CorpusSkew{OnlyLeft: []ProbeResult{{ProbeID: "probe.left"}}},
			Unmeasured:      []UnmeasuredProbe{{ProbeID: "probe.unknown"}},
		},
		Divergences: []ClassifiedDivergence{
			{Divergence: Divergence{ProbeID: "probe.arch", Left: ProbeResult{Verdict: "permitted"}, Right: ProbeResult{Verdict: "not-applicable"}}, Class: ArchitectureExplained},
			{Divergence: Divergence{ProbeID: "probe.policy", Left: ProbeResult{Verdict: "denied"}, Right: ProbeResult{Verdict: "permitted"}}, Class: PolicyExplained},
		},
		Counts: DivergenceCounts{Architecture: 1, Policy: 1},
	}
	first := Fingerprint{
		Cell: Cell{Architecture: "amd64", Kernel: Kernel{Release: "6.1.0"}},
		Results: []ProbeResult{
			{ProbeID: "probe.high", Verdict: "denied", Attribution: &Attribution{Confidence: High, Mechanism: &seccomp}},
			{ProbeID: "probe.low", Verdict: "denied", Attribution: &Attribution{Confidence: Low, Undecidable: true}},
			{ProbeID: "probe.killed", Verdict: "killed", Attribution: &Attribution{Confidence: High, Mechanism: &seccomp}},
		},
	}
	second := Fingerprint{Results: []ProbeResult{{ProbeID: "probe.no-attr", Verdict: "denied"}}}

	report, err := BuildReport(findings, classification, first, second)
	if err != nil {
		t.Fatalf("BuildReport() error = %v", err)
	}
	if report.Attribution.Denials != 4 || report.Attribution.Undecidable != 2 {
		t.Fatalf("attribution totals = %d/%d, want 2/4 including the killed result", report.Attribution.Undecidable, report.Attribution.Denials)
	}
	if report.Attribution.UndecidableFraction == nil || *report.Attribution.UndecidableFraction != 0.5 {
		t.Fatalf("undecidable fraction = %v, want 0.5", report.Attribution.UndecidableFraction)
	}

	var output bytes.Buffer
	if err := WriteJSONReport(&output, report); err != nil {
		t.Fatalf("WriteJSONReport() error = %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatalf("report is not valid JSON: %v", err)
	}
	if decoded["notice"] != AuthorizationNotice {
		t.Errorf("JSON report notice = %v", decoded["notice"])
	}
	attribution := decoded["attribution"].(map[string]any)
	if attribution["denials"] != float64(4) {
		t.Errorf("JSON attribution denominator = %v, want 4 denials including the kill", attribution["denials"])
	}
	if attribution["undecidable_fraction"] != *report.Attribution.UndecidableFraction {
		t.Errorf("JSON undecidable fraction = %v", attribution["undecidable_fraction"])
	}
	attributionResults := attribution["results"].([]any)
	firstObservation := attributionResults[0].(map[string]any)
	if _, ok := firstObservation["cell_label"].(string); !ok {
		t.Errorf("JSON attribution result omitted cell_label: %#v", firstObservation)
	}
	cellDetails := firstObservation["cell"].(map[string]any)
	if cellDetails["architecture"] != "amd64" {
		t.Errorf("JSON attribution result cell details = %#v", cellDetails)
	}
	if _, ok := decoded["findings"]; !ok {
		t.Error("JSON report omitted findings")
	}
	if _, ok := decoded["classification"]; !ok {
		t.Error("JSON report omitted classified divergences")
	}
}

func TestWriteTextReportSeparatesClassesAndIncludesUndecidableFraction(t *testing.T) {
	mechanism := Seccomp
	report, err := BuildReport(
		FindingReport{
			PostureRevision: "v1",
			Tier:            "restricted",
			ExpectationViolations: []Finding{{
				ProbeID: "socket.family.af_alg", Family: "socket", Reason: "posture expectation",
			}},
			ClaimViolations: []Finding{{
				ProbeID: "capability.sys_module", Family: "capability", Reason: "manifest claim",
			}},
			UndeclaredExposures: []Finding{{
				ProbeID: "custom.probe", Family: "custom", Reason: "undeclared exposure",
			}},
		},
		ClassificationResult{
			Divergences: []ClassifiedDivergence{
				{Divergence: Divergence{ProbeID: "probe.arch", Left: ProbeResult{Verdict: "permitted"}, Right: ProbeResult{Verdict: "not-applicable"}}, Class: ArchitectureExplained},
				{Divergence: Divergence{ProbeID: "probe.policy", Left: ProbeResult{Verdict: "denied"}, Right: ProbeResult{Verdict: "permitted"}}, Class: PolicyExplained},
			},
			Counts: DivergenceCounts{Architecture: 1, Policy: 1},
		},
		Fingerprint{Cell: Cell{Architecture: "amd64"}, Results: []ProbeResult{{
			ProbeID: "probe.one", Verdict: "denied", Attribution: &Attribution{Confidence: Low, Undecidable: true, Mechanism: &mechanism},
		}}},
		Fingerprint{Cell: Cell{Architecture: "arm64"}, Results: []ProbeResult{{
			ProbeID: "probe.two", Verdict: "killed", Attribution: &Attribution{Confidence: High, Mechanism: &mechanism},
		}}},
	)
	if err != nil {
		t.Fatalf("BuildReport() error = %v", err)
	}
	var output bytes.Buffer
	if err := WriteTextReport(&output, report); err != nil {
		t.Fatalf("WriteTextReport() error = %v", err)
	}
	text := output.String()
	for _, want := range []string{
		AuthorizationNotice,
		"Expectation violations (1)", "socket.family.af_alg [socket]: posture expectation",
		"Claim violations (1)", "capability.sys_module [capability]: manifest claim",
		"Undeclared exposures (1)", "custom.probe [custom]: undeclared exposure",
		"Architecture-explained (1)", "probe.arch: permitted -> not-applicable",
		"Policy-explained (1)", "probe.policy: denied -> permitted",
		"Undecidable: 1/2 denials (including kills; 50.0%)",
		"high 1, medium 0, low 1, unknown 0",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("text report omitted %q:\n%s", want, text)
		}
	}
}

func TestWriteTextReportHandlesNoMeasuredResults(t *testing.T) {
	report, err := BuildReport(FindingReport{}, ClassificationResult{})
	if err != nil {
		t.Fatalf("BuildReport() error = %v", err)
	}
	var output bytes.Buffer
	if err := WriteTextReport(&output, report); err != nil {
		t.Fatalf("WriteTextReport() error = %v", err)
	}
	if !strings.Contains(output.String(), "Undecidable: n/a (0/0 denials)") {
		t.Fatalf("empty attribution denominator not explained:\n%s", output.String())
	}
}

func TestBuildReportKeepsAttributionDisabledMeasurementsReachable(t *testing.T) {
	fingerprint := Fingerprint{FormatVersion: SupportedFormatVersion, Results: []ProbeResult{
		{ProbeID: "denied-without-attribution", Verdict: "denied", Errno: 1},
		{ProbeID: "permitted-without-attribution", Verdict: "permitted"},
	}}

	report, err := BuildReport(FindingReport{}, ClassificationResult{}, fingerprint)
	if err != nil {
		t.Fatalf("BuildReport: %v", err)
	}
	if report.Attribution.Denials != 1 || report.Attribution.Undecidable != 1 || report.Attribution.ConfidenceCounts.Unknown != 1 {
		t.Errorf("attribution-disabled totals = %+v", report.Attribution)
	}
	if report.Attribution.UndecidableFraction == nil || *report.Attribution.UndecidableFraction != 1 {
		t.Errorf("undecidable fraction = %v, want 1", report.Attribution.UndecidableFraction)
	}
	if fingerprint.Results[0].Attribution != nil || fingerprint.Results[1].Attribution != nil {
		t.Error("BuildReport added attribution to an attribution-disabled measurement")
	}

	posture := ReferencePosture{
		Revision: "test", Status: "draft",
		Tiers: []PostureTier{{Name: "test", NamedAfter: "restricted"}},
		Assertions: []PostureAssertion{{
			Tier: "test", Family: "test", ProbeIDs: []string{"permitted-without-attribution"},
			Expect: "unreachable", Rationale: "reachability must remain evaluable without attribution",
			Citations: []PostureCitation{{ID: "test", URL: "https://example.test/evidence"}},
		}},
	}
	findings, err := EvaluateFindings(fingerprint, ManifestWorkload{}, "test", posture, []ProbeMetadata{{
		ID: "permitted-without-attribution", Family: "test",
	}})
	if err != nil {
		t.Fatalf("EvaluateFindings with attribution disabled: %v", err)
	}
	if len(findings.ExpectationViolations) != 1 || findings.ExpectationViolations[0].ProbeID != "permitted-without-attribution" {
		t.Errorf("unattributed permitted result did not remain reachable to evaluation: %+v", findings)
	}
}

func TestBuildReportLabelsSameCellFingerprintsByPositionAndDigest(t *testing.T) {
	cell := Cell{
		Architecture: "x86_64",
		Kernel:       Kernel{Release: "6.8.0-142-generic"},
		RuntimeClass: &SourcedValue{Value: "runc", Source: "pod"},
	}
	first := Fingerprint{
		FormatVersion: SupportedFormatVersion,
		Cell:          cell,
		Results:       []ProbeResult{{ProbeID: "default.probe", Verdict: "denied", Attribution: &Attribution{Confidence: High}}},
	}
	second := Fingerprint{
		FormatVersion: SupportedFormatVersion,
		Cell:          cell,
		Results:       []ProbeResult{{ProbeID: "hardened.probe", Verdict: "killed", Attribution: &Attribution{Confidence: High}}},
	}
	firstDigest, err := ComputeFingerprintDigest(first)
	if err != nil {
		t.Fatalf("ComputeFingerprintDigest(first) error = %v", err)
	}
	secondDigest, err := ComputeFingerprintDigest(second)
	if err != nil {
		t.Fatalf("ComputeFingerprintDigest(second) error = %v", err)
	}

	report, err := BuildReport(FindingReport{}, ClassificationResult{}, first, second)
	if err != nil {
		t.Fatalf("BuildReport() error = %v", err)
	}
	if len(report.Attribution.Results) != 2 {
		t.Fatalf("got %d attribution records, want 2", len(report.Attribution.Results))
	}
	wantLabels := []string{
		"cell-1-" + strings.TrimPrefix(firstDigest, "sha256:")[:12],
		"cell-2-" + strings.TrimPrefix(secondDigest, "sha256:")[:12],
	}
	for i, observation := range report.Attribution.Results {
		if observation.CellLabel != wantLabels[i] {
			t.Errorf("cell label[%d] = %q, want %q", i, observation.CellLabel, wantLabels[i])
		}
		if !reflect.DeepEqual(observation.Cell, cell) {
			t.Errorf("cell details[%d] = %#v, want %#v", i, observation.Cell, cell)
		}
	}
	if report.Attribution.Results[0].CellLabel == report.Attribution.Results[1].CellLabel {
		t.Fatal("same-cell fingerprints received the same report label")
	}
}
