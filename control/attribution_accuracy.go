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

// AttributionGroundTruth names measured environments in which one mechanism
// is the only control in force (#44), and a control run with none, whose
// denials are the kernel's own and are left out of every environment.
type AttributionGroundTruth struct {
	Control      string                              `json:"control"`
	Environments []AttributionGroundTruthEnvironment `json:"environments"`
}

type AttributionGroundTruthEnvironment struct {
	Name        string    `json:"name"`
	Mechanism   Mechanism `json:"mechanism"`
	Fingerprint string    `json:"fingerprint"`
}

// AttributionAccuracy is the §11.2 metric: accuracy over the denials the
// attributor decided, and the undecidable fraction over every denial.
type AttributionAccuracy struct {
	Environments            []EnvironmentAccuracy     `json:"environments"`
	Denials                 int                       `json:"denials"`
	ExcludedByControl       int                       `json:"excluded_by_control"`
	AttributedDenials       int                       `json:"attributed_denials"`
	CorrectAttributions     int                       `json:"correct_attributions"`
	Undecidable             int                       `json:"undecidable"`
	Accuracy                *float64                  `json:"accuracy"`
	UndecidableFraction     *float64                  `json:"undecidable_fraction"`
	AccuracyCriterionMet    bool                      `json:"accuracy_criterion_met"`
	UndecidableCriterionMet bool                      `json:"undecidable_criterion_met"`
	WithoutElimination      WithoutElimination        `json:"without_cell_elimination"`
	ENOSYSFilterIncluded    bool                      `json:"enosys_filter_included"`
	LSMOnlyIncluded         bool                      `json:"lsm_only_included"`
	Cases                   []AttributionAccuracyCase `json:"cases"`
}

// WithoutElimination is the same scoring with the oracle and correlations
// alone: what the cell's seccomp mode, LSM state and capabilities decide.
type WithoutElimination struct {
	CorrectAttributions int `json:"correct_attributions"`
	Undecidable         int `json:"undecidable"`
}

type EnvironmentAccuracy struct {
	Name                string    `json:"name"`
	Mechanism           Mechanism `json:"mechanism"`
	Denials             int       `json:"denials"`
	CorrectAttributions int       `json:"correct_attributions"`
	Incorrect           int       `json:"incorrect"`
	Undecidable         int       `json:"undecidable"`
}

type AttributionAccuracyCase struct {
	Environment string     `json:"environment"`
	ProbeID     string     `json:"probe_id"`
	Errno       int        `json:"errno"`
	Attributed  *Mechanism `json:"attributed,omitempty"`
	Correct     bool       `json:"correct"`
}

// EvaluateAttributionAccuracy attributes every denial in each environment's
// fingerprint and scores it against the environment's mechanism.
func EvaluateAttributionAccuracy(truth AttributionGroundTruth, control Fingerprint, fingerprints map[string]Fingerprint, corpus []ProbeMetadata) (AttributionAccuracy, error) {
	if len(truth.Environments) == 0 {
		return AttributionAccuracy{}, fmt.Errorf("ground truth has no environments")
	}
	kernelDenials := map[string]bool{}
	for _, r := range control.Results {
		if isDenial(r) {
			kernelDenials[r.ProbeID] = true
		}
	}

	var m AttributionAccuracy
	for _, env := range truth.Environments {
		if !validMechanism(env.Mechanism) {
			return AttributionAccuracy{}, fmt.Errorf("environment %q has unknown mechanism %q", env.Name, env.Mechanism)
		}
		fp, ok := fingerprints[env.Name]
		if !ok {
			return AttributionAccuracy{}, fmt.Errorf("no fingerprint for environment %q", env.Name)
		}
		attributed, err := Attribute(fp, corpus)
		if err != nil {
			return AttributionAccuracy{}, fmt.Errorf("attribute %q: %w", env.Name, err)
		}
		oracleOnly, err := attributeFingerprint(fp, corpus, false)
		if err != nil {
			return AttributionAccuracy{}, fmt.Errorf("attribute %q: %w", env.Name, err)
		}
		e := EnvironmentAccuracy{Name: env.Name, Mechanism: env.Mechanism}
		for i, r := range attributed.Results {
			if !isDenial(r) {
				continue
			}
			if kernelDenials[r.ProbeID] {
				m.ExcludedByControl++
				continue
			}
			switch o := oracleOnly.Results[i].Attribution; {
			case o.Undecidable:
				m.WithoutElimination.Undecidable++
			case o.Mechanism != nil && *o.Mechanism == env.Mechanism:
				m.WithoutElimination.CorrectAttributions++
			}
			c := AttributionAccuracyCase{Environment: env.Name, ProbeID: r.ProbeID, Errno: r.Errno, Attributed: r.Attribution.Mechanism}
			e.Denials++
			switch {
			case r.Attribution.Undecidable:
				e.Undecidable++
			case c.Attributed != nil && *c.Attributed == env.Mechanism:
				c.Correct = true
				e.CorrectAttributions++
			default:
				e.Incorrect++
			}
			if env.Mechanism == Seccomp && r.Verdict == "denied" && r.Errno == errnoENOSYS {
				m.ENOSYSFilterIncluded = true
			}
			m.Cases = append(m.Cases, c)
		}
		if env.Mechanism == LSM && e.Denials > 0 {
			m.LSMOnlyIncluded = true
		}
		m.Denials += e.Denials
		m.CorrectAttributions += e.CorrectAttributions
		m.AttributedDenials += e.CorrectAttributions + e.Incorrect
		m.Undecidable += e.Undecidable
		m.Environments = append(m.Environments, e)
	}
	if m.AttributedDenials > 0 {
		accuracy := float64(m.CorrectAttributions) / float64(m.AttributedDenials)
		m.Accuracy = &accuracy
		m.AccuracyCriterionMet = accuracy >= 0.90
	}
	if m.Denials > 0 {
		fraction := float64(m.Undecidable) / float64(m.Denials)
		m.UndecidableFraction = &fraction
		m.UndecidableCriterionMet = fraction <= 0.10
	}
	return m, nil
}

func isDenial(r ProbeResult) bool {
	return r.Verdict == "denied" || r.Verdict == "killed"
}

func validMechanism(mechanism Mechanism) bool {
	switch mechanism {
	case Seccomp, LSM, CapabilityMissing, Mount, KernelLimit:
		return true
	}
	return false
}
