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
		},
	}
	second := Fingerprint{Results: []ProbeResult{{ProbeID: "probe.no-attr", Verdict: "denied"}}}

	report := BuildReport(findings, classification, first, second)
	if report.Attribution.Denials != 3 || report.Attribution.Undecidable != 2 {
		t.Fatalf("attribution totals = %d/%d, want 2/3", report.Attribution.Undecidable, report.Attribution.Denials)
	}
	if report.Attribution.UndecidableFraction == nil || *report.Attribution.UndecidableFraction < 0.666 || *report.Attribution.UndecidableFraction > 0.667 {
		t.Fatalf("undecidable fraction = %v, want about 0.667", report.Attribution.UndecidableFraction)
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
	if attribution["denials"] != float64(3) {
		t.Errorf("JSON attribution denominator = %v, want 3 denials", attribution["denials"])
	}
	if attribution["undecidable_fraction"] != *report.Attribution.UndecidableFraction {
		t.Errorf("JSON undecidable fraction = %v", attribution["undecidable_fraction"])
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
	report := BuildReport(
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
			ProbeID: "probe.two", Verdict: "denied", Attribution: &Attribution{Confidence: High},
		}}},
	)
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
		"Undecidable: 1/2 denials (50.0%)",
		"high 1, medium 0, low 1, unknown 0",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("text report omitted %q:\n%s", want, text)
		}
	}
}

func TestWriteTextReportHandlesNoMeasuredResults(t *testing.T) {
	report := BuildReport(FindingReport{}, ClassificationResult{})
	var output bytes.Buffer
	if err := WriteTextReport(&output, report); err != nil {
		t.Fatalf("WriteTextReport() error = %v", err)
	}
	if !strings.Contains(output.String(), "Undecidable: n/a (0/0 denials)") {
		t.Fatalf("empty attribution denominator not explained:\n%s", output.String())
	}
}
