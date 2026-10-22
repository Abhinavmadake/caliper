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

package main

import (
	"fmt"
	"hash/fnv"
	"strings"
	"testing"

	"github.com/Abhinavmadake/caliper/control"
)

func TestVerifyClosures(t *testing.T) {
	findings := control.FindingReport{ExpectationViolations: []control.Finding{{ProbeID: "probe.example"}}}

	tests := []struct {
		name       string
		results    []control.ProbeResult
		wantStatus string
		wantError  string
	}{
		{
			name:       "closed probe passes",
			results:    []control.ProbeResult{{ProbeID: "probe.example", Verdict: "denied"}},
			wantStatus: "passed",
		},
		{
			name:      "missing probe fails",
			wantError: "missing from the post-remediation measurement",
		},
		{
			name:      "permitted probe fails",
			results:   []control.ProbeResult{{ProbeID: "probe.example", Verdict: "permitted"}},
			wantError: `has verdict "permitted", want denied or killed`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := verifyClosures(findings, control.Fingerprint{Results: tt.results})
			if tt.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantError) {
					t.Fatalf("verifyClosures() error = %v, want it to contain %q", err, tt.wantError)
				}
				return
			}
			if err != nil {
				t.Fatalf("verifyClosures() error = %v", err)
			}
			if got.Status != tt.wantStatus {
				t.Errorf("status = %q, want %q", got.Status, tt.wantStatus)
			}
			if len(got.CheckedProbes) != 1 || got.CheckedProbes[0] != "probe.example" {
				t.Errorf("checked probes = %#v, want [probe.example]", got.CheckedProbes)
			}
		})
	}
}

func TestCorpusRevisionUsesRegisteredLFIndexHash(t *testing.T) {
	index := []byte("[\r\n]\r\n")
	hash := fnv.New64a()
	_, _ = hash.Write([]byte("[\n]\n"))
	revisions := []byte(fmt.Sprintf("# comment\n0.3.2 %016x\n", hash.Sum64()))

	got, err := corpusRevision(index, revisions)
	if err != nil {
		t.Fatalf("corpusRevision() error = %v", err)
	}
	if got != "0.3.2" {
		t.Errorf("corpusRevision() = %q, want 0.3.2", got)
	}
}

func TestValidateCorpusRevisionRejectsMismatch(t *testing.T) {
	got := validateCorpusRevision(control.Fingerprint{CorpusRevision: "0.2.0"}, "0.3.2")
	if got == nil || !strings.Contains(got.Error(), `does not match corpus index revision "0.3.2"`) {
		t.Fatalf("validateCorpusRevision() error = %v, want mismatch", got)
	}
}
