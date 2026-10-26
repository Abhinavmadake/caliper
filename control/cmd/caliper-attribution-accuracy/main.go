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

// caliper-attribution-accuracy scores attribution against constructed,
// single-cause denial environments for issue #44.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Abhinavmadake/caliper/control"
)

func main() {
	groundTruth := flag.String("ground-truth", "../fixtures/ground-truth/attribution.json", "constructed attribution ground-truth JSON")
	output := flag.String("out", "", "write metrics JSON to this path instead of stdout")
	flag.Parse()
	if flag.NArg() != 0 {
		fail(fmt.Errorf("unexpected argument %q", flag.Arg(0)))
	}
	metrics, err := compute(*groundTruth)
	if err != nil {
		fail(err)
	}
	data, err := json.MarshalIndent(metrics, "", "  ")
	if err != nil {
		fail(fmt.Errorf("encode attribution accuracy: %w", err))
	}
	data = append(data, '\n')
	if *output == "" {
		_, err = os.Stdout.Write(data)
	} else {
		err = os.WriteFile(*output, data, 0o644)
	}
	if err != nil {
		fail(err)
	}
}

func compute(path string) (control.AttributionAccuracy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return control.AttributionAccuracy{}, fmt.Errorf("read ground truth: %w", err)
	}
	var groundTruth control.AttributionGroundTruth
	if err := json.Unmarshal(data, &groundTruth); err != nil {
		return control.AttributionAccuracy{}, fmt.Errorf("parse ground truth: %w", err)
	}
	base := filepath.Dir(path)
	fingerprints := make(map[string]control.Fingerprint)
	for _, env := range groundTruth.Environments { data, err := os.ReadFile(filepath.Join(base, env.Fingerprint)); if err != nil { return control.AttributionAccuracy{}, fmt.Errorf("read %s: %w", env.Fingerprint, err) }; fp, err := control.DecodeFingerprint(data); if err != nil { return control.AttributionAccuracy{}, err }; fingerprints[env.Name] = fp }
	corpusData, err := os.ReadFile(filepath.Join(base, "..", "..", "corpus", "index.json")); if err != nil { return control.AttributionAccuracy{}, err }
	corpus, err := control.LoadAttributionCorpus(corpusData); if err != nil { return control.AttributionAccuracy{}, err }
	return control.EvaluateAttributionAccuracy(groundTruth, fingerprints, corpus)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "caliper-attribution-accuracy:", err)
	os.Exit(1)
}
