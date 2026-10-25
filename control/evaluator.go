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
	"fmt"
	"sort"
	"strings"
)

// FindingReport deliberately keeps the three categories in distinct fields.
// Undeclared exposures are actionable feedback for corpus and posture work.
type FindingReport struct {
	PostureRevision       string    `json:"posture_revision"`
	Tier                  string    `json:"tier"`
	ExpectationViolations []Finding `json:"expectation_violations"`
	ClaimViolations       []Finding `json:"claim_violations"`
	UndeclaredExposures   []Finding `json:"undeclared_exposures"`
}

// EvaluateFindings categorises permitted probe results against the selected
// reference tier and one workload's manifest declarations. The tier is an
// explicit input because PSS labels and the reference posture describe
// different things. In particular, Restricted PSS plus RuntimeDefault does
// not promise that AF_ALG is blocked.
func EvaluateFindings(fingerprint Fingerprint, workload ManifestWorkload, tier string, posture ReferencePosture, corpus []ProbeMetadata) (FindingReport, error) {
	if err := fingerprint.ValidateFormatVersion(); err != nil {
		return FindingReport{}, err
	}
	if err := posture.Validate(); err != nil {
		return FindingReport{}, err
	}
	evaluatedTier, exists := posture.tierIndex(tier)
	if !exists {
		return FindingReport{}, fmt.Errorf("unknown evaluation tier %q", tier)
	}
	metadata, err := metadataByID(corpus)
	if err != nil {
		return FindingReport{}, err
	}
	if _, err := resultsByID(fingerprint.Results); err != nil {
		return FindingReport{}, err
	}
	loadedByRun, err := modulesLoadedByRun(fingerprint)
	if err != nil {
		return FindingReport{}, err
	}

	report := FindingReport{
		PostureRevision:       posture.Revision,
		Tier:                  tier,
		ExpectationViolations: []Finding{},
		ClaimViolations:       []Finding{},
		UndeclaredExposures:   []Finding{},
	}
	for _, result := range fingerprint.Results {
		if result.Verdict != "permitted" {
			continue
		}
		probe, found := metadata[result.ProbeID]
		if !found {
			return FindingReport{}, fmt.Errorf("no corpus metadata for result %q", result.ProbeID)
		}
		assertion := matchingPostureAssertion(posture, evaluatedTier, probe)
		finding := Finding{
			PostureRevision: posture.Revision,
			Tier:            tier,
			Family:          probe.Family,
			ProbeID:         result.ProbeID,
			Verdict:         result.Verdict,
		}
		if assertion != nil {
			expectationFinding := finding
			expectationFinding.Kind = ExpectationViolation
			expectationFinding.Reason = assertion.Rationale
			expectationFinding.Citations = append([]PostureCitation(nil), assertion.Citations...)
			expectationFinding.Modules = moduleStates(fingerprint, loadedByRun, probe.Kernel)
			if err := expectationFinding.Validate(); err != nil {
				return FindingReport{}, fmt.Errorf("invalid expectation finding for %q: %w", result.ProbeID, err)
			}
			report.ExpectationViolations = append(report.ExpectationViolations, expectationFinding)
		}
		claimViolation := probe.Oracle.Isolates == "undecidable" && manifestClaimsCapability(workload, probe.Capability)
		if claimViolation {
			claimFinding := finding
			claimFinding.Kind = ClaimViolation
			claimFinding.Reason = "manifest declares this capability unavailable, but its probe was permitted"
			if err := claimFinding.Validate(); err != nil {
				return FindingReport{}, fmt.Errorf("invalid claim finding for %q: %w", result.ProbeID, err)
			}
			report.ClaimViolations = append(report.ClaimViolations, claimFinding)
		}
		if assertion == nil && !claimViolation {
			finding.Kind = UndeclaredExposure
			finding.Reason = "probe was permitted and neither the selected posture tier nor the manifest declares it unreachable"
			if err := finding.Validate(); err != nil {
				return FindingReport{}, fmt.Errorf("invalid undeclared exposure finding for %q: %w", result.ProbeID, err)
			}
			report.UndeclaredExposures = append(report.UndeclaredExposures, finding)
		}
	}
	sortFindings(report.ExpectationViolations)
	sortFindings(report.ClaimViolations)
	sortFindings(report.UndeclaredExposures)
	return report, nil
}

func moduleStates(fingerprint Fingerprint, loadedByRun []string, dependency KernelDependency) []ModuleState {
	var states []ModuleState
	for _, module := range []string{dependency.Module, dependency.ProtocolModule} {
		if module == "" {
			continue
		}
		state := ModuleState{Name: module, LoadedByRun: containsModule(loadedByRun, module)}
		if fingerprint.Cell.Kernel.Modules != nil {
			before := containsModule(*fingerprint.Cell.Kernel.Modules, module)
			state.LoadedBefore = &before
		}
		states = append(states, state)
	}
	return states
}

func modulesLoadedByRun(fingerprint Fingerprint) ([]string, error) {
	if len(fingerprint.ModuleDelta) == 0 {
		return nil, nil
	}
	var delta struct {
		LoadedByRun []string `json:"loaded_by_run"`
	}
	if err := json.Unmarshal(fingerprint.ModuleDelta, &delta); err != nil {
		return nil, fmt.Errorf("decode module_delta: %w", err)
	}
	return delta.LoadedByRun, nil
}

func sortFindings(findings []Finding) {
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].ProbeID < findings[j].ProbeID
	})
}

func matchingPostureAssertion(posture ReferencePosture, evaluatedTier int, probe ProbeMetadata) *PostureAssertion {
	for i := range posture.Assertions {
		assertion := &posture.Assertions[i]
		assertionTier, _ := posture.tierIndex(assertion.Tier)
		if assertionTier > evaluatedTier || assertion.Family != probe.Family {
			continue
		}
		if len(assertion.ProbeIDs) == 0 {
			return assertion
		}
		for _, id := range assertion.ProbeIDs {
			if id == probe.ID {
				return assertion
			}
		}
	}
	return nil
}

// manifestClaimsCapability recognises only explicit dropped-capability
// declarations and the capability requirement implied by PSS Restricted.
// Seccomp RuntimeDefault and Localhost profiles are intentionally not treated
// as syscall-level claims: their rules cannot be inferred from the manifest.
func manifestClaimsCapability(workload ManifestWorkload, capability string) bool {
	wanted := normalizeCapability(capability)
	if wanted == "" || wanted == "NET_BIND_SERVICE" || len(workload.Pod.Containers) == 0 {
		return false
	}
	restricted := workload.PodSecurityStandard != nil &&
		workload.PodSecurityStandard.Enforce != nil &&
		strings.EqualFold(workload.PodSecurityStandard.Enforce.Level, "restricted")
	for _, container := range workload.Pod.Containers {
		if container.Privileged != nil && *container.Privileged {
			return false
		}
		capabilities := container.EffectiveCapabilities()
		if capabilities == nil {
			if !restricted {
				return false
			}
			continue
		}
		if capabilities.All {
			return false
		}
		for _, added := range capabilities.Add {
			if normalizeCapability(added) == wanted {
				return false
			}
		}
		if !restricted && !capabilityDropped(*capabilities, wanted) {
			return false
		}
	}
	return true
}

func capabilityDropped(capabilities CapabilitySet, wanted string) bool {
	for _, dropped := range capabilities.Drop {
		if strings.EqualFold(strings.TrimSpace(dropped), "ALL") || normalizeCapability(dropped) == wanted {
			return true
		}
	}
	return false
}

func normalizeCapability(capability string) string {
	capability = strings.ToUpper(strings.TrimSpace(capability))
	return strings.TrimPrefix(capability, "CAP_")
}
