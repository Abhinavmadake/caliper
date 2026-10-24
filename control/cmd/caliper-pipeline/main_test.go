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
	"reflect"
	"strings"
	"testing"

	"github.com/Abhinavmadake/caliper/control"
)

func TestVerifyClosures(t *testing.T) {
	findings := control.FindingReport{ExpectationViolations: []control.Finding{{ProbeID: "probe.example"}}}

	tests := []struct {
		name        string
		findings    control.FindingReport
		results     []control.ProbeResult
		wantStatus  string
		wantProbe   string
		wantError   string
		notClosable []control.NotClosable
	}{
		{
			name:       "closed probe passes",
			findings:   findings,
			results:    []control.ProbeResult{{ProbeID: "probe.example", Verdict: "denied"}},
			wantStatus: "passed",
			wantProbe:  "closed",
		},
		{
			name:       "missing probe fails",
			findings:   findings,
			wantError:  "missing from the post-remediation measurement",
			wantStatus: "failed",
			wantProbe:  "missing",
		},
		{
			name:       "permitted probe fails",
			findings:   findings,
			results:    []control.ProbeResult{{ProbeID: "probe.example", Verdict: "permitted"}},
			wantError:  `has verdict "permitted", want denied or killed`,
			wantStatus: "failed",
			wantProbe:  "still-open",
		},
		{
			name:        "not-closable probe is reported without failing",
			findings:    findings,
			results:     []control.ProbeResult{{ProbeID: "probe.example", Verdict: "permitted"}},
			wantStatus:  "passed",
			wantProbe:   "not-closable",
			notClosable: []control.NotClosable{{ProbeID: "probe.example", Reason: "argument constraint"}},
		},
		{
			name:       "no findings needs no verification",
			wantStatus: "nothing-to-verify",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := verifyClosures(tt.findings, control.Fingerprint{Results: tt.results}, tt.notClosable)
			if tt.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantError) {
					t.Fatalf("verifyClosures() error = %v, want it to contain %q", err, tt.wantError)
				}
			} else if err != nil {
				t.Fatalf("verifyClosures() error = %v", err)
			}
			if got.Status != tt.wantStatus {
				t.Errorf("status = %q, want %q", got.Status, tt.wantStatus)
			}
			if tt.name == "no findings needs no verification" {
				if len(got.Probes) != 0 {
					t.Errorf("probes = %#v, want none", got.Probes)
				}
				return
			}
			if len(got.Probes) != 1 || got.Probes[0].ProbeID != "probe.example" {
				t.Errorf("probes = %#v, want one entry for probe.example", got.Probes)
			} else if got.Probes[0].Status != tt.wantProbe {
				t.Errorf("probe status = %q, want %q", got.Probes[0].Status, tt.wantProbe)
			}
			if !reflect.DeepEqual(got.NotClosable, tt.notClosable) {
				t.Errorf("not_closable = %#v, want %#v", got.NotClosable, tt.notClosable)
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
