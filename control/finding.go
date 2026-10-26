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

import "fmt"

// FindingKind classifies a measured exposure without conflating the manifest
// contract with the independent reference posture.
type FindingKind string

const (
	ExpectationViolation FindingKind = "expectation-violation"
	ClaimViolation       FindingKind = "claim-violation"
	UndeclaredExposure   FindingKind = "undeclared-exposure"
)

// Finding carries the posture provenance and probe evidence for one reachable
// kernel entry point.
type Finding struct {
	Kind            FindingKind `json:"kind"`
	PostureRevision string      `json:"posture_revision"`
	Tier            string      `json:"tier"`
	Family          string      `json:"family"`
	ProbeID         string      `json:"probe_id"`
	Verdict         Verdict     `json:"verdict"`
	Reason          string      `json:"reason,omitempty"`
	// Citations preserve the posture evidence behind an expectation finding.
	// Claim and undeclared-exposure findings have no posture assertion, so this
	// is empty for them.
	Citations []PostureCitation `json:"citations,omitempty"`
	// Modules is the state of the probe's kernel-dependency modules on an
	// expectation finding, since exploitability can hinge on them.
	Modules []ModuleState `json:"modules,omitempty"`
}

// ModuleState reads one module against the run's snapshots. LoadedBefore is
// nil when the fingerprint has no pre-probe snapshot.
type ModuleState struct {
	Name         string `json:"name"`
	LoadedBefore *bool  `json:"loaded_before"`
	LoadedByRun  bool   `json:"loaded_by_run"`
}

// Validate prevents a finding from being emitted without naming the exact
// immutable posture revision used for its evaluation.
func (f Finding) Validate() error {
	if f.PostureRevision == "" {
		return fmt.Errorf("finding posture_revision is required")
	}
	switch f.Kind {
	case ExpectationViolation, ClaimViolation, UndeclaredExposure:
	default:
		return fmt.Errorf("finding kind %q is invalid", f.Kind)
	}
	if f.Tier == "" || f.Family == "" || f.ProbeID == "" {
		return fmt.Errorf("finding tier, family, and probe_id are required")
	}
	if f.Verdict != "permitted" {
		return fmt.Errorf("finding verdict must be permitted, got %q", f.Verdict)
	}
	return nil
}
