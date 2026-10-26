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

// caliper-attribution-accuracy scores attribution against the measured
// single-cause environments of issue #44.
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
	groundTruth := flag.String("ground-truth", "../fixtures/ground-truth/attribution.json", "ground-truth environments JSON; fingerprints are read beside it")
	corpusPath := flag.String("corpus", "../corpus/index.json", "probe corpus index JSON")
	output := flag.String("out", "", "write metrics JSON to this path instead of stdout")
	flag.Parse()
	if flag.NArg() != 0 {
		fail(fmt.Errorf("unexpected argument %q", flag.Arg(0)))
	}
	metrics, err := compute(*groundTruth, *corpusPath)
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

func compute(truthPath, corpusPath string) (control.AttributionAccuracy, error) {
	data, err := os.ReadFile(truthPath)
	if err != nil {
		return control.AttributionAccuracy{}, fmt.Errorf("read ground truth: %w", err)
	}
	var truth control.AttributionGroundTruth
	if err := json.Unmarshal(data, &truth); err != nil {
		return control.AttributionAccuracy{}, fmt.Errorf("parse ground truth: %w", err)
	}
	dir := filepath.Dir(truthPath)
	controlRun, err := readFingerprint(filepath.Join(dir, truth.Control))
	if err != nil {
		return control.AttributionAccuracy{}, err
	}
	fingerprints := make(map[string]control.Fingerprint, len(truth.Environments))
	for _, env := range truth.Environments {
		if fingerprints[env.Name], err = readFingerprint(filepath.Join(dir, env.Fingerprint)); err != nil {
			return control.AttributionAccuracy{}, err
		}
	}
	corpusData, err := os.ReadFile(corpusPath)
	if err != nil {
		return control.AttributionAccuracy{}, fmt.Errorf("read corpus: %w", err)
	}
	var corpus []control.ProbeMetadata
	if err := json.Unmarshal(corpusData, &corpus); err != nil {
		return control.AttributionAccuracy{}, fmt.Errorf("parse corpus: %w", err)
	}
	return control.EvaluateAttributionAccuracy(truth, controlRun, fingerprints, corpus)
}

func readFingerprint(path string) (control.Fingerprint, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return control.Fingerprint{}, fmt.Errorf("read fingerprint: %w", err)
	}
	fp, err := control.DecodeFingerprint(data)
	if err != nil {
		return control.Fingerprint{}, fmt.Errorf("decode %s: %w", path, err)
	}
	return fp, nil
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "caliper-attribution-accuracy:", err)
	os.Exit(1)
}
