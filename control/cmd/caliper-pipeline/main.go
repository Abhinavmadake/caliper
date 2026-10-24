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

// caliper-pipeline joins the control-plane stages for a baseline and a
// post-remediation measurement. Measurements are collected separately; this
// command preserves each stage's output as an artifact for review.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"strings"

	"github.com/Abhinavmadake/caliper/control"
)

type inputs struct {
	baseline, verified, corpus, revisions, posture, manifest string
	runtimeDefault, runtimeArch, ociArch, caps               string
	kernel, tier, out                                        string
}

func main() {
	var in inputs
	flag.StringVar(&in.baseline, "baseline", "", "completed baseline fingerprint JSON")
	flag.StringVar(&in.verified, "verified", "", "optional post-remediation fingerprint; supply on the verification run")
	flag.StringVar(&in.corpus, "corpus", "../corpus/index.json", "probe corpus index JSON")
	flag.StringVar(&in.revisions, "revisions", "../corpus/revisions", "registered corpus revision hashes")
	flag.StringVar(&in.posture, "posture", "../posture/v1/posture.yaml", "reference posture YAML")
	flag.StringVar(&in.manifest, "manifest", "../deploy/k8s/job.yaml", "measured workload manifest")
	flag.StringVar(&in.runtimeDefault, "runtime-default", "", "target runtime's RuntimeDefault seccomp JSON")
	flag.StringVar(&in.runtimeArch, "runtime-arch", "", "runtime architecture, e.g. amd64")
	flag.StringVar(&in.ociArch, "oci-arch", "", "OCI architecture, e.g. SCMP_ARCH_X86_64")
	flag.StringVar(&in.caps, "capabilities", "", "comma-separated effective capabilities")
	flag.StringVar(&in.kernel, "kernel", "", "target kernel release")
	flag.StringVar(&in.tier, "tier", "restricted", "posture tier")
	flag.StringVar(&in.out, "out", "pipeline-artifacts", "directory for stage outputs")
	flag.Parse()
	if flag.NArg() != 0 {
		fail(fmt.Errorf("unexpected argument %q", flag.Arg(0)))
	}
	if err := run(in); err != nil {
		fail(err)
	}
}

func run(in inputs) error {
	if in.baseline == "" || in.runtimeDefault == "" || in.runtimeArch == "" || in.ociArch == "" || in.kernel == "" {
		return errors.New("baseline, runtime-default, runtime-arch, oci-arch, and kernel are required")
	}
	corpusData, err := os.ReadFile(in.corpus)
	if err != nil {
		return fmt.Errorf("read corpus: %w", err)
	}
	var corpus []control.ProbeMetadata
	if err := json.Unmarshal(corpusData, &corpus); err != nil {
		return fmt.Errorf("parse corpus: %w", err)
	}
	revisionsData, err := os.ReadFile(in.revisions)
	if err != nil {
		return fmt.Errorf("read corpus revisions: %w", err)
	}
	expectedRevision, err := corpusRevision(corpusData, revisionsData)
	if err != nil {
		return err
	}
	postureData, err := os.ReadFile(in.posture)
	if err != nil {
		return fmt.Errorf("read posture: %w", err)
	}
	posture, err := control.ParsePosture(postureData)
	if err != nil {
		return err
	}
	manifestData, err := os.ReadFile(in.manifest)
	if err != nil {
		return fmt.Errorf("read manifest: %w", err)
	}
	manifest, err := control.ParseManifest(manifestData)
	if err != nil {
		return err
	}
	if len(manifest.Workloads) != 1 {
		return fmt.Errorf("manifest %s has %d workloads, want 1", in.manifest, len(manifest.Workloads))
	}
	baseline, baselineSource, err := readFingerprint(in.baseline)
	if err != nil {
		return fmt.Errorf("read baseline fingerprint: %w", err)
	}
	if err := validateCorpusRevision(baseline, expectedRevision); err != nil {
		return fmt.Errorf("baseline fingerprint: %w", err)
	}
	baseline, err = control.Attribute(baseline, corpus)
	if err != nil {
		return fmt.Errorf("attribute baseline: %w", err)
	}
	findings, err := control.EvaluateFindings(baseline, manifest.Workloads[0], in.tier, posture, corpus)
	if err != nil {
		return fmt.Errorf("evaluate baseline: %w", err)
	}
	runtimeData, err := os.ReadFile(in.runtimeDefault)
	if err != nil {
		return fmt.Errorf("read runtime default: %w", err)
	}
	var runtimeDefault control.RuntimeDefaultProfile
	if err := json.Unmarshal(runtimeData, &runtimeDefault); err != nil {
		return fmt.Errorf("parse runtime default: %w", err)
	}
	remediation, err := control.GenerateRemediation(findings, runtimeDefault, control.RemediationTarget{
		RuntimeArchitecture: in.runtimeArch,
		OCIArchitecture:     in.ociArch,
		Capabilities:        commaList(in.caps),
		Kernel:              in.kernel,
	})
	if err != nil {
		return fmt.Errorf("generate remediation: %w", err)
	}
	spo, err := remediation.RenderSPO()
	if err != nil {
		return fmt.Errorf("render SPO profile: %w", err)
	}
	localhost, err := remediation.RenderLocalhost()
	if err != nil {
		return fmt.Errorf("render Localhost profile: %w", err)
	}
	if err := os.MkdirAll(in.out, 0o755); err != nil {
		return fmt.Errorf("create artifact directory: %w", err)
	}
	artifacts := map[string]any{
		"baseline.fingerprint.json":  json.RawMessage(baselineSource),
		"baseline.findings.json":     findings,
		"remediation.json":           remediation,
		"remediation.spo.yaml":       string(spo),
		"remediation.localhost.json": json.RawMessage(localhost),
	}
	var verificationErr error
	if in.verified != "" {
		verified, verifiedSource, err := readFingerprint(in.verified)
		if err != nil {
			return fmt.Errorf("read verified fingerprint: %w", err)
		}
		if err := validateCorpusRevision(verified, expectedRevision); err != nil {
			return fmt.Errorf("verified fingerprint: %w", err)
		}
		verified, err = control.Attribute(verified, corpus)
		if err != nil {
			return fmt.Errorf("attribute verified fingerprint: %w", err)
		}
		classification, err := control.Classify(baseline, verified, corpus)
		if err != nil {
			return fmt.Errorf("classify measurements: %w", err)
		}
		verifiedFindings, err := control.EvaluateFindings(verified, manifest.Workloads[0], in.tier, posture, corpus)
		if err != nil {
			return fmt.Errorf("evaluate verified measurement: %w", err)
		}
		verification, verifyErr := verifyClosures(findings, verified, remediation.NotClosable)
		verificationErr = verifyErr
		report, err := control.BuildReport(findings, classification, baseline, verified)
		if err != nil {
			return fmt.Errorf("build pipeline report: %w", err)
		}
		artifacts["diff-classification.json"] = classification
		artifacts["verified.fingerprint.json"] = json.RawMessage(verifiedSource)
		artifacts["verified.findings.json"] = verifiedFindings
		artifacts["verification.json"] = verification
		artifacts["pipeline-report.json"] = report
	}
	for name, value := range artifacts {
		if err := writeArtifact(in.out, name, value); err != nil {
			return err
		}
	}
	return verificationErr
}

func readFingerprint(path string) (control.Fingerprint, []byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return control.Fingerprint{}, nil, err
	}
	fingerprint, err := control.DecodeFingerprint(data)
	if err != nil {
		return control.Fingerprint{}, nil, err
	}
	return fingerprint, data, nil
}

func corpusRevision(index, revisions []byte) (string, error) {
	// Git may check JSON out with CRLF on Windows. The registered hashes are
	// calculated from the LF corpus dump, so normalize line endings first.
	index = bytes.ReplaceAll(index, []byte("\r\n"), []byte("\n"))
	hash := fnv.New64a()
	if _, err := hash.Write(index); err != nil {
		return "", fmt.Errorf("hash corpus index: %w", err)
	}
	wantHash := fmt.Sprintf("%016x", hash.Sum64())
	var match string
	for lineNumber, line := range strings.Split(string(revisions), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		if len(fields) != 2 {
			return "", fmt.Errorf("parse corpus revisions line %d: want revision and FNV-1a hash", lineNumber+1)
		}
		if fields[1] == wantHash {
			if match != "" {
				return "", fmt.Errorf("corpus index hash %s is registered more than once", wantHash)
			}
			match = fields[0]
		}
	}
	if match == "" {
		return "", fmt.Errorf("corpus index hash %s has no registered revision", wantHash)
	}
	return match, nil
}

func validateCorpusRevision(fingerprint control.Fingerprint, expected string) error {
	if fingerprint.CorpusRevision != expected {
		return fmt.Errorf("corpus_revision %q does not match corpus index revision %q", fingerprint.CorpusRevision, expected)
	}
	return nil
}

type verificationSummary struct {
	Status      string                     `json:"status"`
	Probes      []closureProbeVerification `json:"probes"`
	NotClosable []control.NotClosable      `json:"not_closable"`
}

type closureProbeVerification struct {
	ProbeID string          `json:"probe_id"`
	Status  string          `json:"status"`
	Verdict control.Verdict `json:"verdict,omitempty"`
}

func verifyClosures(findings control.FindingReport, fingerprint control.Fingerprint, notClosable []control.NotClosable) (verificationSummary, error) {
	summary := verificationSummary{
		Status:      "passed",
		Probes:      []closureProbeVerification{},
		NotClosable: notClosable,
	}
	if len(findings.ExpectationViolations) == 0 {
		summary.Status = "nothing to verify"
		return summary, nil
	}

	results := make(map[string]control.Verdict, len(fingerprint.Results))
	for _, result := range fingerprint.Results {
		results[result.ProbeID] = result.Verdict
	}
	summary.Probes = make([]closureProbeVerification, 0, len(findings.ExpectationViolations))
	var problems []string
	for _, finding := range findings.ExpectationViolations {
		verdict, exists := results[finding.ProbeID]
		if !exists {
			summary.Probes = append(summary.Probes, closureProbeVerification{ProbeID: finding.ProbeID, Status: "missing"})
			problems = append(problems, fmt.Sprintf("verification incomplete: finding probe %q is missing from the post-remediation measurement", finding.ProbeID))
			continue
		}
		if verdict == "denied" || verdict == "killed" {
			summary.Probes = append(summary.Probes, closureProbeVerification{ProbeID: finding.ProbeID, Status: "closed", Verdict: verdict})
			continue
		}
		summary.Probes = append(summary.Probes, closureProbeVerification{ProbeID: finding.ProbeID, Status: "still open", Verdict: verdict})
		problems = append(problems, fmt.Sprintf("verification failed: finding probe %q has verdict %q, want denied or killed", finding.ProbeID, verdict))
	}
	if len(problems) > 0 {
		summary.Status = "failed"
		return summary, errors.New(strings.Join(problems, "; "))
	}
	return summary, nil
}

func writeArtifact(dir, name string, value any) error {
	var data []byte
	var err error
	if raw, ok := value.(string); ok {
		data = []byte(raw)
	} else if raw, ok := value.(json.RawMessage); ok {
		data = append([]byte(nil), raw...)
	} else {
		data, err = json.MarshalIndent(value, "", "  ")
		if err != nil {
			return fmt.Errorf("encode %s: %w", name, err)
		}
		data = append(data, '\n')
	}
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	return nil
}

func commaList(value string) []string {
	if value == "" {
		return nil
	}
	var values []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			values = append(values, item)
		}
	}
	return values
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "caliper-pipeline:", err)
	os.Exit(1)
}
