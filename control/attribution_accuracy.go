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
	"fmt"
	"os"
	"path/filepath"
)

// AttributionGroundTruth is a deliberately constructed suite: every case has
// one known denial cause, rather than trying to infer truth from a production
// container where several mechanisms can overlap.
type AttributionGroundTruth struct {
	Environments []AttributionGroundTruthEnvironment `json:"environments"`
}
type AttributionGroundTruthEnvironment struct {
	Name        string `json:"name"`
	KnownCause  string `json:"known_cause"`
	Fingerprint string `json:"fingerprint"`
}

type AttributionGroundTruthCase struct {
	Environment       string     `json:"environment"`
	ProbeID           string     `json:"probe_id"`
	KnownCause        string     `json:"known_cause"`
	ObservedMechanism *Mechanism `json:"observed_mechanism,omitempty"`
	Undecidable       bool       `json:"undecidable"`
	Correct           bool       `json:"correct"`
}

// AttributionAccuracy records the evaluation required by proposal §11.2.
// Accuracy is over decided attributions; undecidable fraction is over every
// denial, so an implementation cannot hide uncertainty by omitting it.
type AttributionAccuracy struct {
	GroundTruthEnvironments int                       `json:"ground_truth_environments"`
	Denials                 int                       `json:"denials"`
	AttributedDenials       int                       `json:"attributed_denials"`
	CorrectAttributions     int                       `json:"correct_attributions"`
	IncorrectAttributions   int                       `json:"incorrect_attributions"`
	Undecidable             int                       `json:"undecidable"`
	Accuracy                *float64                  `json:"accuracy,omitempty"`
	UndecidableFraction     *float64                  `json:"undecidable_fraction,omitempty"`
	AccuracyCriterionMet    bool                      `json:"accuracy_criterion_met"`
	UndecidableCriterionMet bool                      `json:"undecidable_criterion_met"`
	ENOSYSFilterIncluded    bool                      `json:"enosys_filter_included"`
	LSMOnlyIncluded         bool                      `json:"lsm_only_included"`
	Cases                   []AttributionAccuracyCase `json:"cases"`
}

type AttributionAccuracyCase struct {
	Name              string     `json:"name"`
	KnownCause        string     `json:"known_cause"`
	ExpectedMechanism Mechanism  `json:"expected_mechanism"`
	ObservedMechanism *Mechanism `json:"observed_mechanism,omitempty"`
	Undecidable       bool       `json:"undecidable"`
	Correct           bool       `json:"correct"`
}

// EvaluateAttributionAccuracy runs the attributor once for every constructed
// environment and applies issue #44's 90% accuracy and 10% uncertainty gates.
func EvaluateAttributionAccuracy(groundTruth AttributionGroundTruth, extras ...interface{}) (AttributionAccuracy, error) {
	var fingerprints map[string]Fingerprint
	var corpus []ProbeMetadata
	if len(extras) == 2 {
		var ok bool
		fingerprints, ok = extras[0].(map[string]Fingerprint)
		if !ok {
			return AttributionAccuracy{}, fmt.Errorf("invalid fingerprints")
		}
		corpus, ok = extras[1].([]ProbeMetadata)
		if !ok {
			return AttributionAccuracy{}, fmt.Errorf("invalid corpus")
		}
	} else if len(extras) == 0 {
		fingerprints = make(map[string]Fingerprint)
		base := filepath.Join("..", "fixtures", "ground-truth")
		for _, env := range groundTruth.Environments {
			data, err := os.ReadFile(filepath.Join(base, env.Fingerprint))
			if err != nil {
				return AttributionAccuracy{}, err
			}
			fp, err := DecodeFingerprint(data)
			if err != nil {
				return AttributionAccuracy{}, err
			}
			fingerprints[env.Name] = fp
		}
		data, err := os.ReadFile(filepath.Join("..", "corpus", "index.json"))
		if err != nil {
			return AttributionAccuracy{}, err
		}
		corpus, err = LoadAttributionCorpus(data)
		if err != nil {
			return AttributionAccuracy{}, err
		}
	} else {
		return AttributionAccuracy{}, fmt.Errorf("expected fingerprints and corpus")
	}
	if len(groundTruth.Environments) == 0 {
		return AttributionAccuracy{}, fmt.Errorf("attribution ground truth has no environments")
	}
	metrics := AttributionAccuracy{GroundTruthEnvironments: len(groundTruth.Environments), Cases: make([]AttributionAccuracyCase, 0)}
	for _, env := range groundTruth.Environments {
		fp, ok := fingerprints[env.Name]
		if !ok {
			return AttributionAccuracy{}, fmt.Errorf("missing fingerprint for %q", env.Name)
		}
		attributed, err := Attribute(fp, corpus)
		if err != nil {
			return AttributionAccuracy{}, fmt.Errorf("attribute %q: %w", env.Name, err)
		}
		for _, result := range attributed.Results {
			if result.Verdict != "denied" && result.Verdict != "killed" {
				continue
			}
			test := AttributionAccuracyCase{Name: env.Name + ":" + result.ProbeID, KnownCause: env.KnownCause}
			metrics.Denials++
			actual := Attribution{}
			if result.Attribution != nil {
				actual = *result.Attribution
			}
			test.Undecidable = actual.Undecidable
			test.ObservedMechanism = actual.Mechanism
			if actual.Mechanism != nil {
				metrics.AttributedDenials++
				test.Correct = string(*actual.Mechanism) == env.KnownCause
				if test.Correct {
					metrics.CorrectAttributions++
				} else {
					metrics.IncorrectAttributions++
				}
			}
			if actual.Undecidable {
				metrics.Undecidable++
			}
			if env.KnownCause == "seccomp" && result.Errno == errnoENOSYS {
				metrics.ENOSYSFilterIncluded = true
			}
			if env.KnownCause == "lsm" {
				metrics.LSMOnlyIncluded = true
			}
			metrics.Cases = append(metrics.Cases, test)
		}
	}
	if metrics.AttributedDenials > 0 {
		accuracy := float64(metrics.CorrectAttributions) / float64(metrics.AttributedDenials)
		metrics.Accuracy = &accuracy
		metrics.AccuracyCriterionMet = accuracy >= .90
	}
	if metrics.Denials > 0 {
		fraction := float64(metrics.Undecidable) / float64(metrics.Denials)
		metrics.UndecidableFraction = &fraction
		metrics.UndecidableCriterionMet = fraction <= .10
	}
	return metrics, nil
	/*
	   	for _, test := range groundTruth.Cases {
	   		if test.Name == "" || test.KnownCause == "" {
	   			return AttributionAccuracy{}, fmt.Errorf("ground-truth case requires name and known_cause")
	   		}
	   		if _, exists := seen[test.Name]; exists {
	   			return AttributionAccuracy{}, fmt.Errorf("duplicate ground-truth case %q", test.Name)
	   		}
	   		seen[test.Name] = struct{}{}
	   		if !validMechanism(test.ExpectedMechanism) {
	   			return AttributionAccuracy{}, fmt.Errorf("ground-truth case %q has invalid expected mechanism %q", test.Name, test.ExpectedMechanism)
	   		}
	   		if test.Result.Verdict != "denied" && test.Result.Verdict != "killed" {
	   			return AttributionAccuracy{}, fmt.Errorf("ground-truth case %q is not a denial", test.Name)
	   		}
	   		if test.Result.ProbeID == "" {
	   			test.Result.ProbeID = test.Probe.ID
	   		}
	   		if test.Probe.ID == "" || test.Result.ProbeID != test.Probe.ID {
	   			return AttributionAccuracy{}, fmt.Errorf("ground-truth case %q has mismatched probe id", test.Name)
	   		}

	   		attributed, err := Attribute(Fingerprint{Cell: test.Cell, Results: []ProbeResult{test.Result}}, []ProbeMetadata{test.Probe})
	   		if err != nil {
	   			return AttributionAccuracy{}, fmt.Errorf("attribute %q: %w", test.Name, err)
	   		}
	   		actual := attributed.Results[0].Attribution
	   		entry := AttributionAccuracyCase{Name: test.Name, KnownCause: test.KnownCause, ExpectedMechanism: test.ExpectedMechanism, Undecidable: actual.Undecidable}
	   		metrics.Denials++
	   		if actual.Mechanism != nil {
	   			entry.ObservedMechanism = actual.Mechanism
	   			metrics.AttributedDenials++
	   			entry.Correct = *actual.Mechanism == test.ExpectedMechanism
	   			if entry.Correct {
	   				metrics.CorrectAttributions++
	   			} else {
	   				metrics.IncorrectAttributions++
	   			}
	   		}
	   		if actual.Undecidable {
	   			metrics.Undecidable++
	   		}
	   		if test.KnownCause == "seccomp-enosys" && test.Result.Errno == errnoENOSYS && test.ExpectedMechanism == Seccomp {
	   			metrics.ENOSYSFilterIncluded = true
	   		}
	   		if test.KnownCause == "lsm-only" && test.ExpectedMechanism == LSM {
	   			metrics.LSMOnlyIncluded = true
	   		}
	   		metrics.Cases = append(metrics.Cases, entry)
	   	}

	   	if metrics.AttributedDenials > 0 {
	   		accuracy := float64(metrics.CorrectAttributions) / float64(metrics.AttributedDenials)
	   		metrics.Accuracy = &accuracy
	   		metrics.AccuracyCriterionMet = accuracy >= 0.90
	   	}

	   fraction := float64(metrics.Undecidable) / float64(metrics.Denials)
	   metrics.UndecidableFraction = &fraction
	   metrics.UndecidableCriterionMet = fraction <= 0.10
	   return metrics, nil
	*/
}

func validMechanism(mechanism Mechanism) bool {
	switch mechanism {
	case Seccomp, LSM, CapabilityMissing, Mount, KernelLimit:
		return true
	default:
		return false
	}
}
