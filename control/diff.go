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
	"sort"
)

// Fingerprint is the portion of a confinement fingerprint that the diff engine
// needs. Other fingerprint fields are deliberately preserved by consumers that
// need them; a diff compares only per-probe verdicts.
type Fingerprint struct {
	FormatVersion  int           `json:"format_version"`
	CorpusRevision string        `json:"corpus_revision"`
	Results        []ProbeResult `json:"results"`
}

// ProbeResult is a raw observation from one probe. Errno is retained even
// though a verdict difference, rather than an errno difference, defines a
// divergence for the project's metric.
type ProbeResult struct {
	ProbeID string  `json:"probe_id"`
	Verdict Verdict `json:"verdict"`
	Errno   int     `json:"errno"`
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

// DiffResult separates comparable verdict changes from corpus skew.
type DiffResult struct {
	Divergences []Divergence `json:"divergences"`
	CorpusSkew  CorpusSkew   `json:"corpus_skew"`
}

// Diff compares the intersection of two fingerprints at probe granularity.
// Results are ordered by probe ID so reports and tests are reproducible.
func Diff(left, right Fingerprint) (DiffResult, error) {
	leftByID, err := resultsByID(left.Results)
	if err != nil {
		return DiffResult{}, fmt.Errorf("left fingerprint: %w", err)
	}
	rightByID, err := resultsByID(right.Results)
	if err != nil {
		return DiffResult{}, fmt.Errorf("right fingerprint: %w", err)
	}

	ids := make(map[string]struct{}, len(leftByID)+len(rightByID))
	for id := range leftByID {
		ids[id] = struct{}{}
	}
	for id := range rightByID {
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
