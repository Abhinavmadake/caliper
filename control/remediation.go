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
	"reflect"
)

// RemediationClosure is the measured outcome of applying remediation to one
// policy-explained divergence. Unknown means the original observations do not
// establish a denied/permitted pair with a known attribution mechanism.
type RemediationClosure string

const (
	ClosureClosed  RemediationClosure = "closed"
	ClosureOpen    RemediationClosure = "open"
	ClosureUnknown RemediationClosure = "unknown"
)

// RemediationObservation links the original divergence to its post-remediation
// measurement. Expected is the denied-side verdict; Observed is the re-probe.
type RemediationObservation struct {
	ProbeID   string             `json:"probe_id"`
	Mechanism *Mechanism         `json:"mechanism,omitempty"`
	Expected  Verdict            `json:"expected,omitempty"`
	Observed  *Verdict           `json:"observed,omitempty"`
	Closure   RemediationClosure `json:"closure"`
	Reason    string             `json:"reason,omitempty"`
}

// RemediationMetric separates seccomp's thresholded success criterion from
// other mechanisms, which are reported without a threshold (§11.2).
type RemediationMetric struct {
	SelfManagedNode bool                        `json:"self_managed_node"`
	Seccomp         ClosureCounts               `json:"seccomp"`
	OtherMechanisms map[Mechanism]ClosureCounts `json:"other_mechanisms"`
	Unattributed    int                         `json:"unattributed"`
	Observations    []RemediationObservation    `json:"observations"`
}

// ClosureCounts reports a rate only when at least one closure could be
// measured. No pass/fail threshold is implied by this data structure.
type ClosureCounts struct {
	Eligible         int      `json:"eligible"`
	Closed           int      `json:"closed"`
	Rate             *float64 `json:"rate"`
	SuccessThreshold *float64 `json:"success_threshold,omitempty"`
}

// MeasureRemediationClosure evaluates re-probing results against the original
// classified divergences. The probe must have been rerun on the same
// self-managed cell that was open before remediation. Seccomp-attributed
// divergences are counted as closed only when the measured verdict changes to
// the original denied-side verdict; policy text alone never counts as closure.
func MeasureRemediationClosure(classification ClassificationResult, left, right, reprobe Fingerprint, selfManagedNode bool) (RemediationMetric, error) {
	if !selfManagedNode {
		return RemediationMetric{}, fmt.Errorf("remediation closure verification requires a self-managed node (proposal §12)")
	}
	if err := reprobe.ValidateFormatVersion(); err != nil {
		return RemediationMetric{}, fmt.Errorf("re-probe fingerprint: %w", err)
	}
	if err := left.ValidateFormatVersion(); err != nil {
		return RemediationMetric{}, fmt.Errorf("left fingerprint: %w", err)
	}
	if err := right.ValidateFormatVersion(); err != nil {
		return RemediationMetric{}, fmt.Errorf("right fingerprint: %w", err)
	}
	metric := RemediationMetric{
		SelfManagedNode: true,
		OtherMechanisms: map[Mechanism]ClosureCounts{},
		Observations:    []RemediationObservation{},
	}
	results, err := resultsByID(reprobe.Results)
	if err != nil {
		return RemediationMetric{}, fmt.Errorf("re-probe fingerprint: %w", err)
	}

	for _, item := range classification.Divergences {
		if item.Class != PolicyExplained {
			continue
		}
		observation, openIsLeft, mechanism, attributable := remediationTarget(item.Divergence)
		if !attributable {
			metric.Unattributed++
			metric.Observations = append(metric.Observations, observation)
			continue
		}
		target := right.Cell
		if openIsLeft {
			target = left.Cell
		}
		if !reflect.DeepEqual(target, reprobe.Cell) {
			return RemediationMetric{}, fmt.Errorf("re-probe cell does not match the previously open cell for probe %q", item.ProbeID)
		}
		observed, measured := results[item.ProbeID]
		if !measured {
			observation.Closure = ClosureUnknown
			observation.Reason = "probe is absent from the re-probe fingerprint"
			// A missing post-remediation measurement cannot count as success. Keep
			// it in the denominator so the seccomp metric cannot be inflated by
			// omitting probes that were difficult to verify.
			metric.addClosure(mechanism, true, false)
			metric.Observations = append(metric.Observations, observation)
			continue
		}
		verdict := observed.Verdict
		observation.Observed = &verdict
		if observed.Verdict == observation.Expected {
			observation.Closure = ClosureClosed
			metric.addClosure(mechanism, true, true)
		} else {
			observation.Closure = ClosureOpen
			observation.Reason = "re-probed verdict still differs from the original denied-side verdict"
			metric.addClosure(mechanism, true, false)
		}
		metric.Observations = append(metric.Observations, observation)
	}
	threshold := 1.0
	metric.Seccomp.SuccessThreshold = &threshold
	metric.Seccomp.Rate = closureRate(metric.Seccomp)
	for mechanism, counts := range metric.OtherMechanisms {
		counts.Rate = closureRate(counts)
		metric.OtherMechanisms[mechanism] = counts
	}
	return metric, nil
}

func remediationTarget(divergence Divergence) (RemediationObservation, bool, Mechanism, bool) {
	observation := RemediationObservation{ProbeID: divergence.ProbeID, Closure: ClosureUnknown}
	var denied ProbeResult
	openIsLeft := false
	switch {
	case (divergence.Left.Verdict == "denied" || divergence.Left.Verdict == "killed") && divergence.Right.Verdict == "permitted":
		denied = divergence.Left
	case (divergence.Right.Verdict == "denied" || divergence.Right.Verdict == "killed") && divergence.Left.Verdict == "permitted":
		denied = divergence.Right
		openIsLeft = true
	default:
		observation.Reason = "divergence is not a measured denied-versus-permitted pair"
		return observation, false, "", false
	}
	if denied.Attribution == nil || denied.Attribution.Mechanism == nil || denied.Attribution.Undecidable {
		observation.Reason = "denied-side attribution does not identify a mechanism"
		return observation, false, "", false
	}
	mechanism := *denied.Attribution.Mechanism
	observation.Mechanism = &mechanism
	observation.Expected = denied.Verdict
	return observation, openIsLeft, mechanism, true
}

func (metric *RemediationMetric) addClosure(mechanism Mechanism, eligible, closed bool) {
	counts := &metric.Seccomp
	if mechanism != Seccomp {
		other := metric.OtherMechanisms[mechanism]
		if eligible {
			other.Eligible++
		}
		if eligible && closed {
			other.Closed++
		}
		metric.OtherMechanisms[mechanism] = other
		return
	}
	if eligible {
		counts.Eligible++
	}
	if eligible && closed {
		counts.Closed++
	}
}

func closureRate(counts ClosureCounts) *float64 {
	if counts.Eligible == 0 {
		return nil
	}
	rate := float64(counts.Closed) / float64(counts.Eligible)
	return &rate
}
