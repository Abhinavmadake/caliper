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
	"os"
	"path/filepath"
	"testing"
)

func loadReferencePosture(t *testing.T) ReferencePosture {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "posture", "v1", "posture.yaml"))
	if err != nil {
		t.Fatalf("read reference posture: %v", err)
	}
	posture, err := ParsePosture(data)
	if err != nil {
		t.Fatalf("parse reference posture: %v", err)
	}
	return posture
}

func TestEvaluateFindingsSeparatesExpectationClaimAndUndeclared(t *testing.T) {
	posture := loadReferencePosture(t)
	falseValue := false
	workload := ManifestWorkload{
		PodSecurityStandard: &PodSecurityLevels{
			Enforce: &PodSecurityLevel{Level: "restricted"},
		},
		Pod: PodSecuritySpec{
			Seccomp: &SeccompProfile{Type: "RuntimeDefault", RuntimeDefined: true},
			Containers: []ContainerSecurity{{
				Name:       "app",
				Privileged: &falseValue,
				Capabilities: &CapabilitySet{
					Drop: []string{"ALL"},
				},
			}},
		},
	}
	fingerprint := Fingerprint{
		FormatVersion: SupportedFormatVersion,
		Results: []ProbeResult{
			{ProbeID: "socket.family.af_alg", Verdict: "permitted"},
			{ProbeID: "capability.sys_module", Verdict: "permitted"},
			{ProbeID: "custom.entry", Verdict: "permitted"},
		},
	}
	corpus := []ProbeMetadata{
		{ID: "socket.family.af_alg", Family: "socket", Oracle: Oracle{Isolates: "seccomp"}},
		{ID: "capability.sys_module", Family: "capability", Capability: "CAP_SYS_MODULE", Oracle: Oracle{Isolates: "undecidable"}},
		{ID: "custom.entry", Family: "custom"},
	}

	report, err := EvaluateFindings(fingerprint, workload, "untrusted-multi-tenant", posture, corpus)
	if err != nil {
		t.Fatalf("EvaluateFindings() error = %v", err)
	}
	if len(report.ExpectationViolations) != 2 || len(report.ClaimViolations) != 1 || len(report.UndeclaredExposures) != 1 {
		t.Fatalf("finding categories = expectation %d, claim %d, undeclared %d", len(report.ExpectationViolations), len(report.ClaimViolations), len(report.UndeclaredExposures))
	}
	var afalgFinding *Finding
	for i := range report.ExpectationViolations {
		if report.ExpectationViolations[i].ProbeID == "socket.family.af_alg" {
			afalgFinding = &report.ExpectationViolations[i]
			break
		}
	}
	if afalgFinding == nil || afalgFinding.Kind != ExpectationViolation || afalgFinding.PostureRevision != "v1" {
		t.Errorf("AF_ALG finding = %#v, want posture expectation violation", afalgFinding)
	}
	var capabilityExpectation bool
	for _, finding := range report.ExpectationViolations {
		if finding.ProbeID == "capability.sys_module" {
			capabilityExpectation = true
		}
	}
	if !capabilityExpectation {
		t.Error("capability.sys_module should remain in the expectation list as well as the claim list")
	}
	if got := report.UndeclaredExposures[0]; got.ProbeID != "custom.entry" || got.Kind != UndeclaredExposure {
		t.Errorf("undeclared finding = %#v", got)
	}
	if got := report.ClaimViolations[0]; got.ProbeID != "capability.sys_module" || got.Kind != ClaimViolation {
		t.Errorf("overlapping claim finding = %#v", got)
	}

	// At the privileged tier no reference assertion applies. The explicit
	// drop-ALL declaration is then the only reason the capability is a finding.
	fingerprint.Results = []ProbeResult{{ProbeID: "capability.sys_module", Verdict: "permitted"}}
	report, err = EvaluateFindings(fingerprint, workload, "privileged", posture, corpus)
	if err != nil {
		t.Fatalf("EvaluateFindings() at privileged tier error = %v", err)
	}
	if len(report.ExpectationViolations) != 0 || len(report.ClaimViolations) != 1 || len(report.UndeclaredExposures) != 0 {
		t.Fatalf("claim categories = expectation %d, claim %d, undeclared %d", len(report.ExpectationViolations), len(report.ClaimViolations), len(report.UndeclaredExposures))
	}
	if got := report.ClaimViolations[0]; got.Kind != ClaimViolation || got.ProbeID != "capability.sys_module" {
		t.Errorf("claim finding = %#v", got)
	}

}

func TestEvaluateFindingsRequiresOracleToIsolateCapabilityClaim(t *testing.T) {
	posture := loadReferencePosture(t)
	workload := ManifestWorkload{Pod: PodSecuritySpec{Containers: []ContainerSecurity{{
		Name: "app", Capabilities: &CapabilitySet{Drop: []string{"ALL"}},
	}}}}
	fingerprint := Fingerprint{
		FormatVersion: SupportedFormatVersion,
		Results:       []ProbeResult{{ProbeID: "mount.reach", Verdict: "permitted"}},
	}
	corpus := []ProbeMetadata{{
		ID:         "mount.reach",
		Family:     "mount",
		Capability: "CAP_SYS_ADMIN",
		Oracle:     Oracle{Isolates: "seccomp"},
	}}

	report, err := EvaluateFindings(fingerprint, workload, "privileged", posture, corpus)
	if err != nil {
		t.Fatalf("EvaluateFindings() error = %v", err)
	}
	if len(report.ClaimViolations) != 0 {
		t.Fatalf("got claim violation for non-isolating oracle: %#v", report.ClaimViolations)
	}
	if len(report.UndeclaredExposures) != 1 || report.UndeclaredExposures[0].ProbeID != "mount.reach" {
		t.Fatalf("mount.reach should remain undeclared, got %#v", report.UndeclaredExposures)
	}
}

func TestEvaluateFindingsRequiresCorpusMetadataForMeasuredResults(t *testing.T) {
	fingerprint := Fingerprint{
		FormatVersion: SupportedFormatVersion,
		Results:       []ProbeResult{{ProbeID: "missing", Verdict: "permitted"}},
	}
	posture := ReferencePosture{
		Revision: "test",
		Status:   "released",
		Tiers:    []PostureTier{{Name: "restricted", NamedAfter: "restricted"}},
	}
	_, err := EvaluateFindings(fingerprint, ManifestWorkload{}, "restricted", posture, nil)
	if err == nil {
		t.Fatal("expected missing corpus metadata to be rejected")
	}
}
