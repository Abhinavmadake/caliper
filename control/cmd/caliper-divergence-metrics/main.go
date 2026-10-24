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

// caliper-divergence-metrics computes the proposal's divergence metric from
// the six committed cell fingerprints.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Abhinavmadake/caliper/control"
)

func main() {
	fixtures := flag.String("fixtures", "../fixtures/cells", "directory containing cell1.json through cell6.json")
	corpusPath := flag.String("corpus", "../corpus/index.json", "probe corpus index JSON")
	output := flag.String("out", "", "write metrics JSON to this path instead of stdout")
	flag.Parse()
	if flag.NArg() != 0 {
		fail(fmt.Errorf("unexpected argument %q", flag.Arg(0)))
	}
	metrics, err := computeMetrics(*fixtures, *corpusPath)
	if err != nil {
		fail(err)
	}
	data, err := json.MarshalIndent(metrics, "", "  ")
	if err != nil {
		fail(fmt.Errorf("encode divergence metrics: %w", err))
	}
	data = append(data, '\n')
	if *output == "" {
		if _, err := os.Stdout.Write(data); err != nil {
			fail(err)
		}
		return
	}
	if err := os.WriteFile(*output, data, 0o644); err != nil {
		fail(fmt.Errorf("write divergence metrics: %w", err))
	}
}

type divergenceMetrics struct {
	FingerprintsEvaluated      int                      `json:"fingerprints_evaluated"`
	CellPairsCompared          int                      `json:"cell_pairs_compared"`
	PairsWithPolicyDivergence  int                      `json:"pairs_with_policy_divergence"`
	FourPairPolicyCriterionMet bool                     `json:"four_pair_policy_criterion_met"`
	Totals                     control.DivergenceCounts `json:"totals"`
	Pairs                      []divergencePairMetrics  `json:"pairs"`
}

type divergencePairMetrics struct {
	LeftFingerprint  string                   `json:"left_fingerprint"`
	RightFingerprint string                   `json:"right_fingerprint"`
	Counts           control.DivergenceCounts `json:"counts"`
}

func computeMetrics(fixturesDir, corpusPath string) (divergenceMetrics, error) {
	paths := make([]string, 0, 6)
	fingerprints := make([]control.Fingerprint, 0, 6)
	for i := 1; i <= 6; i++ {
		path := filepath.Join(fixturesDir, fmt.Sprintf("cell%d.json", i))
		data, err := os.ReadFile(path)
		if err != nil {
			return divergenceMetrics{}, fmt.Errorf("read cell fingerprint %s: %w", path, err)
		}
		fingerprint, err := control.DecodeFingerprint(data)
		if err != nil {
			return divergenceMetrics{}, fmt.Errorf("decode cell fingerprint %s: %w", path, err)
		}
		paths = append(paths, filepath.Base(path))
		fingerprints = append(fingerprints, fingerprint)
	}
	corpusData, err := os.ReadFile(corpusPath)
	if err != nil {
		return divergenceMetrics{}, fmt.Errorf("read corpus: %w", err)
	}
	var corpus []control.ProbeMetadata
	if err := json.Unmarshal(corpusData, &corpus); err != nil {
		return divergenceMetrics{}, fmt.Errorf("parse corpus: %w", err)
	}

	metrics := divergenceMetrics{
		FingerprintsEvaluated: len(fingerprints),
		Pairs:                 make([]divergencePairMetrics, 0, len(fingerprints)*(len(fingerprints)-1)/2),
	}
	for left := 0; left < len(fingerprints); left++ {
		for right := left + 1; right < len(fingerprints); right++ {
			classified, err := control.Classify(fingerprints[left], fingerprints[right], corpus)
			if err != nil {
				return divergenceMetrics{}, fmt.Errorf("classify %s against %s: %w", paths[left], paths[right], err)
			}
			counts := classified.Counts
			metrics.Pairs = append(metrics.Pairs, divergencePairMetrics{
				LeftFingerprint:  paths[left],
				RightFingerprint: paths[right],
				Counts:           counts,
			})
			addCounts(&metrics.Totals, counts)
			if counts.Policy > 0 {
				metrics.PairsWithPolicyDivergence++
			}
		}
	}
	metrics.CellPairsCompared = len(metrics.Pairs)
	metrics.FourPairPolicyCriterionMet = metrics.PairsWithPolicyDivergence >= 4
	if metrics.FingerprintsEvaluated != 6 || metrics.CellPairsCompared != 15 {
		return divergenceMetrics{}, errors.New("divergence metric must compare all six fingerprints and their 15 pairs")
	}
	return metrics, nil
}

func addCounts(total *control.DivergenceCounts, counts control.DivergenceCounts) {
	total.Architecture += counts.Architecture
	total.KernelVersion += counts.KernelVersion
	total.RuntimeClass += counts.RuntimeClass
	total.Policy += counts.Policy
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "caliper-divergence-metrics:", err)
	os.Exit(1)
}
