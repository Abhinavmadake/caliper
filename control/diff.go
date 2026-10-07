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
)

// SupportedFormatVersion is the sole fingerprint format version understood by
// this control plane. spec/fingerprint.md requires consumers to reject an
// unknown version rather than make a best-effort interpretation.
const SupportedFormatVersion = 1

// Fingerprint is the portion of a confinement fingerprint that the diff engine
// needs. Other fingerprint fields are deliberately preserved by consumers that
// need them; a diff compares only per-probe verdicts.
type Fingerprint struct {
	FormatVersion  int           `json:"format_version"`
	CorpusRevision string        `json:"corpus_revision"`
	Cell           Cell          `json:"cell"`
	Results        []ProbeResult `json:"results"`
	Unmeasured     []Unmeasured  `json:"unmeasured"`
}

// Cell contains the environment facts used to explain a divergence. The
// control plane records more identity fields than these; the classifier reads
// only architecture, the kernel and RuntimeClass.
type Cell struct {
	Architecture string       `json:"architecture"`
	Kernel       Kernel       `json:"kernel"`
	RuntimeClass SourcedValue `json:"runtime_class"`
}

// Kernel is the probe-visible kernel identity. Modules is nil when the probe
// could not read /proc/modules; nil is unknown and is not the same as empty.
type Kernel struct {
	Release string    `json:"release"`
	Modules *[]string `json:"modules"`
}

// SourcedValue is a control-plane value and the source that supplied it.
type SourcedValue struct {
	Value  string `json:"value"`
	Source string `json:"source"`
}

// ProbeResult is a raw observation from one probe. Errno is retained even
// though a verdict difference, rather than an errno difference, defines a
// divergence for the project's metric.
type ProbeResult struct {
	ProbeID string  `json:"probe_id"`
	Verdict Verdict `json:"verdict"`
	Errno   int     `json:"errno"`
}

// Unmeasured is a probe for which the engine produced no verdict, such as a
// deferred probe or one whose child crashed. It is intentionally absent from
// results, so the diff must read this field before calling a missing probe
// corpus skew.
type Unmeasured struct {
	ProbeID string          `json:"probe_id"`
	Why     json.RawMessage `json:"why"`
}

// Verdict is a value from the fixed fingerprint verdict enumeration.
type Verdict string

// Divergence is one probe whose verdict differs between two fingerprints.
// Classification belongs to issue #27; this type intentionally contains no
// explanation or policy judgement.
type Divergence struct {
	ProbeID string      `json:"probe_id"`
	Left    ProbeResult `json:"left"`
	Right   ProbeResult `json:"right"`
}

// CorpusSkew records probes that cannot be compared because they appear in
// only one fingerprint. They are not divergences and must never be classified.
type CorpusSkew struct {
	OnlyLeft  []ProbeResult `json:"only_left"`
	OnlyRight []ProbeResult `json:"only_right"`
}

// UnmeasuredProbe is a probe that cannot be compared because at least one
// measurement did not produce a verdict. It is distinct from corpus skew and
// from a verdict divergence, neither of which it can validly represent.
type UnmeasuredProbe struct {
	ProbeID     string       `json:"probe_id"`
	LeftResult  *ProbeResult `json:"left_result,omitempty"`
	RightResult *ProbeResult `json:"right_result,omitempty"`
	Left        *Unmeasured  `json:"left,omitempty"`
	Right       *Unmeasured  `json:"right,omitempty"`
}

// DiffResult separates comparable verdict changes from corpus skew.
type DiffResult struct {
	Divergences []Divergence      `json:"divergences"`
	CorpusSkew  CorpusSkew        `json:"corpus_skew"`
	Unmeasured  []UnmeasuredProbe `json:"unmeasured"`
}

// Diff compares the intersection of two fingerprints at probe granularity.
// Results are ordered by probe ID so reports and tests are reproducible.
func Diff(left, right Fingerprint) (DiffResult, error) {
	if left.FormatVersion != SupportedFormatVersion {
		return DiffResult{}, fmt.Errorf("left fingerprint: unsupported format_version %d", left.FormatVersion)
	}
	if right.FormatVersion != SupportedFormatVersion {
		return DiffResult{}, fmt.Errorf("right fingerprint: unsupported format_version %d", right.FormatVersion)
	}

	leftByID, err := resultsByID(left.Results)
	if err != nil {
		return DiffResult{}, fmt.Errorf("left fingerprint: %w", err)
	}
	rightByID, err := resultsByID(right.Results)
	if err != nil {
		return DiffResult{}, fmt.Errorf("right fingerprint: %w", err)
	}
	leftUnmeasured, err := unmeasuredByID(left.Unmeasured)
	if err != nil {
		return DiffResult{}, fmt.Errorf("left fingerprint: %w", err)
	}
	rightUnmeasured, err := unmeasuredByID(right.Unmeasured)
	if err != nil {
		return DiffResult{}, fmt.Errorf("right fingerprint: %w", err)
	}
	if err := noMeasuredUnmeasuredOverlap(leftByID, leftUnmeasured); err != nil {
		return DiffResult{}, fmt.Errorf("left fingerprint: %w", err)
	}
	if err := noMeasuredUnmeasuredOverlap(rightByID, rightUnmeasured); err != nil {
		return DiffResult{}, fmt.Errorf("right fingerprint: %w", err)
	}

	ids := make(map[string]struct{}, len(leftByID)+len(rightByID)+len(leftUnmeasured)+len(rightUnmeasured))
	for id := range leftByID {
		ids[id] = struct{}{}
	}
	for id := range rightByID {
		ids[id] = struct{}{}
	}
	for id := range leftUnmeasured {
		ids[id] = struct{}{}
	}
	for id := range rightUnmeasured {
		ids[id] = struct{}{}
	}

	sortedIDs := make([]string, 0, len(ids))
	for id := range ids {
		sortedIDs = append(sortedIDs, id)
	}
	sort.Strings(sortedIDs)

	result := DiffResult{}
	for _, id := range sortedIDs {
		leftResult, inLeft := leftByID[id]
		rightResult, inRight := rightByID[id]
		leftUnmeasuredResult, leftIsUnmeasured := leftUnmeasured[id]
		rightUnmeasuredResult, rightIsUnmeasured := rightUnmeasured[id]
		if leftIsUnmeasured || rightIsUnmeasured {
			entry := UnmeasuredProbe{ProbeID: id}
			if inLeft {
				entry.LeftResult = &leftResult
			}
			if inRight {
				entry.RightResult = &rightResult
			}
			if leftIsUnmeasured {
				entry.Left = &leftUnmeasuredResult
			}
			if rightIsUnmeasured {
				entry.Right = &rightUnmeasuredResult
			}
			result.Unmeasured = append(result.Unmeasured, entry)
			continue
		}
		switch {
		case !inLeft:
			result.CorpusSkew.OnlyRight = append(result.CorpusSkew.OnlyRight, rightResult)
		case !inRight:
			result.CorpusSkew.OnlyLeft = append(result.CorpusSkew.OnlyLeft, leftResult)
		case leftResult.Verdict != rightResult.Verdict:
			result.Divergences = append(result.Divergences, Divergence{
				ProbeID: id,
				Left:    leftResult,
				Right:   rightResult,
			})
		}
	}

	return result, nil
}

func unmeasuredByID(unmeasured []Unmeasured) (map[string]Unmeasured, error) {
	byID := make(map[string]Unmeasured, len(unmeasured))
	for _, entry := range unmeasured {
		if entry.ProbeID == "" {
			return nil, fmt.Errorf("unmeasured probe has an empty probe_id")
		}
		if _, exists := byID[entry.ProbeID]; exists {
			return nil, fmt.Errorf("duplicate unmeasured probe_id %q", entry.ProbeID)
		}
		byID[entry.ProbeID] = entry
	}
	return byID, nil
}

func noMeasuredUnmeasuredOverlap(results map[string]ProbeResult, unmeasured map[string]Unmeasured) error {
	for id := range unmeasured {
		if _, exists := results[id]; exists {
			return fmt.Errorf("probe_id %q appears in both results and unmeasured", id)
		}
	}
	return nil
}

func resultsByID(results []ProbeResult) (map[string]ProbeResult, error) {
	byID := make(map[string]ProbeResult, len(results))
	for _, result := range results {
		if result.ProbeID == "" {
			return nil, fmt.Errorf("probe result has an empty probe_id")
		}
		if _, exists := byID[result.ProbeID]; exists {
			return nil, fmt.Errorf("duplicate probe_id %q", result.ProbeID)
		}
		byID[result.ProbeID] = result
	}
	return byID, nil
}
