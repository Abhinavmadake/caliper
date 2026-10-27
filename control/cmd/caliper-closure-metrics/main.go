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

// caliper-closure-metrics computes the remediation closure rate (#45) from
// the per-cell pipeline runs in fixtures/pipeline.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/Abhinavmadake/caliper/control"
)

const unenforcedReason = "seccomp mode is 0 in the sandbox, so the profile is not applied"

func main() {
	fixtures := flag.String("fixtures", "../fixtures/pipeline", "directory of per-cell pipeline runs")
	output := flag.String("out", "", "write metrics JSON to this path instead of stdout")
	flag.Parse()
	if flag.NArg() != 0 {
		fail(fmt.Errorf("unexpected argument %q", flag.Arg(0)))
	}
	metrics, err := computeMetrics(*fixtures)
	if err != nil {
		fail(err)
	}
	data, err := json.MarshalIndent(metrics, "", "  ")
	if err != nil {
		fail(fmt.Errorf("encode closure metrics: %w", err))
	}
	data = append(data, '\n')
	if *output == "" {
		if _, err := os.Stdout.Write(data); err != nil {
			fail(err)
		}
		return
	}
	if err := os.WriteFile(*output, data, 0o644); err != nil {
		fail(fmt.Errorf("write closure metrics: %w", err))
	}
}

type closureMetrics struct {
	PostureRevision string        `json:"posture_revision"`
	Tier            string        `json:"tier"`
	Cells           []cellMetrics `json:"cells"`
	Seccomp         counts        `json:"seccomp"`
	// Findings seccomp cannot close on that cell, reported without a
	// threshold (§11.2).
	Other               counts `json:"other"`
	SeccompCriterionMet bool   `json:"seccomp_criterion_met"`
}

type counts struct {
	Findings    int      `json:"findings"`
	Closed      int      `json:"closed"`
	ClosureRate *float64 `json:"closure_rate"`
}

type cellMetrics struct {
	Cell            string    `json:"cell"`
	SeccompEnforced bool      `json:"seccomp_enforced"`
	Seccomp         counts    `json:"seccomp"`
	Other           counts    `json:"other"`
	Findings        []closure `json:"findings"`
}

type closure struct {
	ProbeID   string `json:"probe_id"`
	Family    string `json:"family"`
	Mechanism string `json:"mechanism"`
	Reason    string `json:"reason,omitempty"`
	// The verdict in the fresh measurement under the generated profile.
	Reprobe control.Verdict `json:"reprobe_verdict"`
	Closed  bool            `json:"closed"`
}

func (c *counts) add(closed bool) {
	c.Findings++
	if closed {
		c.Closed++
	}
	rate := float64(c.Closed) / float64(c.Findings)
	c.ClosureRate = &rate
}

func computeMetrics(fixturesDir string) (closureMetrics, error) {
	dirs, err := filepath.Glob(filepath.Join(fixturesDir, "cell*"))
	if err != nil {
		return closureMetrics{}, err
	}
	sort.Strings(dirs)
	var metrics closureMetrics
	for _, dir := range dirs {
		cell, findings, err := cellFrom(dir)
		if err != nil {
			return closureMetrics{}, err
		}
		if metrics.Tier == "" {
			metrics.PostureRevision, metrics.Tier = findings.PostureRevision, findings.Tier
		} else if findings.PostureRevision != metrics.PostureRevision || findings.Tier != metrics.Tier {
			return closureMetrics{}, fmt.Errorf("%s is posture %s %s, others %s %s", cell.Cell,
				findings.PostureRevision, findings.Tier, metrics.PostureRevision, metrics.Tier)
		}
		for _, f := range cell.Findings {
			if f.Mechanism == "seccomp" {
				metrics.Seccomp.add(f.Closed)
			} else {
				metrics.Other.add(f.Closed)
			}
		}
		metrics.Cells = append(metrics.Cells, cell)
	}
	if len(metrics.Cells) == 0 {
		return closureMetrics{}, errors.New("no cell pipeline runs found")
	}
	metrics.SeccompCriterionMet = metrics.Seccomp.Findings > 0 && metrics.Seccomp.Closed == metrics.Seccomp.Findings
	return metrics, nil
}

func cellFrom(dir string) (cellMetrics, control.FindingReport, error) {
	name := filepath.Base(dir)
	var findings control.FindingReport
	var remediation control.Remediation
	if err := readJSON(filepath.Join(dir, "pipeline", "baseline.findings.json"), &findings); err != nil {
		return cellMetrics{}, findings, err
	}
	if err := readJSON(filepath.Join(dir, "pipeline", "remediation.json"), &remediation); err != nil {
		return cellMetrics{}, findings, err
	}
	baseline, err := readFingerprint(filepath.Join(dir, name+".json"))
	if err != nil {
		return cellMetrics{}, findings, err
	}
	reprobe, err := readFingerprint(filepath.Join(dir, name+"-remediated.json"))
	if err != nil {
		return cellMetrics{}, findings, err
	}

	seccomp := baseline.Cell.Seccomp
	cell := cellMetrics{
		Cell:            name,
		SeccompEnforced: seccomp != nil && seccomp.Mode != nil && *seccomp.Mode == 2,
		Findings:        []closure{},
	}
	closable := map[string]bool{}
	for _, c := range remediation.Closures {
		closable[c.ProbeID] = true
	}
	notClosable := map[string]string{}
	for _, n := range remediation.NotClosable {
		notClosable[n.ProbeID] = n.Reason
	}
	verdicts := map[string]control.Verdict{}
	for _, r := range reprobe.Results {
		verdicts[r.ProbeID] = r.Verdict
	}
	seen := map[string]bool{}
	for _, f := range findings.ExpectationViolations {
		if seen[f.ProbeID] {
			continue
		}
		seen[f.ProbeID] = true
		verdict, ok := verdicts[f.ProbeID]
		if !ok {
			return cellMetrics{}, findings, fmt.Errorf("%s: %s was not re-probed", name, f.ProbeID)
		}
		c := closure{ProbeID: f.ProbeID, Family: f.Family, Mechanism: "other", Reprobe: verdict,
			Closed: verdict == "denied" || verdict == "killed"}
		switch {
		case !closable[f.ProbeID]:
			c.Reason = notClosable[f.ProbeID]
		case !cell.SeccompEnforced:
			c.Reason = unenforcedReason
		default:
			c.Mechanism = "seccomp"
		}
		if c.Mechanism == "seccomp" {
			cell.Seccomp.add(c.Closed)
		} else {
			cell.Other.add(c.Closed)
		}
		cell.Findings = append(cell.Findings, c)
	}
	return cell, findings, nil
}

func readJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}

func readFingerprint(path string) (control.Fingerprint, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return control.Fingerprint{}, err
	}
	fp, err := control.DecodeFingerprint(data)
	if err != nil {
		return control.Fingerprint{}, fmt.Errorf("decode %s: %w", path, err)
	}
	return fp, nil
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "caliper-closure-metrics:", err)
	os.Exit(1)
}
