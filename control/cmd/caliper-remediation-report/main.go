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

// caliper-remediation-report measures remediation closure from two original
// fingerprints and a post-remediation re-probe fingerprint.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/Abhinavmadake/caliper/control"
)

func main() {
	leftPath := flag.String("left", "", "first original fingerprint JSON")
	rightPath := flag.String("right", "", "second original fingerprint JSON")
	reprobePath := flag.String("reprobe", "", "post-remediation fingerprint JSON from the previously open cell")
	corpusPath := flag.String("corpus", "../corpus/index.json", "probe corpus index JSON")
	selfManaged := flag.Bool("self-managed-node", false, "confirm the re-probe ran on a self-managed node")
	format := flag.String("format", "text", "output format: text or json")
	flag.Parse()
	if err := run(*leftPath, *rightPath, *reprobePath, *corpusPath, *selfManaged, *format); err != nil {
		fmt.Fprintln(os.Stderr, "caliper-remediation-report:", err)
		os.Exit(1)
	}
}

func run(leftPath, rightPath, reprobePath, corpusPath string, selfManaged bool, format string) error {
	if leftPath == "" || rightPath == "" || reprobePath == "" {
		return errors.New("left, right and reprobe fingerprints are required")
	}
	if !selfManaged {
		return errors.New("-self-managed-node is required for closure verification (proposal §12)")
	}
	if format != "text" && format != "json" {
		return fmt.Errorf("unsupported format %q: want text or json", format)
	}
	var corpus []control.ProbeMetadata
	data, err := os.ReadFile(corpusPath)
	if err != nil {
		return fmt.Errorf("read corpus: %w", err)
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		return fmt.Errorf("decode corpus: %w", err)
	}
	left, err := readFingerprint(leftPath)
	if err != nil {
		return fmt.Errorf("read left fingerprint: %w", err)
	}
	right, err := readFingerprint(rightPath)
	if err != nil {
		return fmt.Errorf("read right fingerprint: %w", err)
	}
	reprobe, err := readFingerprint(reprobePath)
	if err != nil {
		return fmt.Errorf("read re-probe fingerprint: %w", err)
	}
	left, err = control.Attribute(left, corpus)
	if err != nil {
		return fmt.Errorf("attribute left fingerprint: %w", err)
	}
	right, err = control.Attribute(right, corpus)
	if err != nil {
		return fmt.Errorf("attribute right fingerprint: %w", err)
	}
	classification, err := control.Classify(left, right, corpus)
	if err != nil {
		return fmt.Errorf("classify divergences: %w", err)
	}
	metric, err := control.MeasureRemediationClosure(classification, left, right, reprobe, true)
	if err != nil {
		return err
	}
	report := control.Report{Notice: control.AuthorizationNotice, Classification: classification, Remediation: &metric}
	if format == "json" {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(report)
	}
	return control.WriteTextReport(os.Stdout, report)
}

func readFingerprint(path string) (control.Fingerprint, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return control.Fingerprint{}, err
	}
	return control.DecodeFingerprint(data)
}
