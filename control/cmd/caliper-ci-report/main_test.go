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
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/Abhinavmadake/caliper/control"
)

func TestEvaluateAndRenderRecordedFixture(t *testing.T) {
	data, err := os.ReadFile("../../../fixtures/x86_64-apparmor.json")
	if err != nil {
		t.Fatal(err)
	}
	fp, err := control.DecodeFingerprint(data)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := evaluate(fp, inputs{
		posture:  "../../../posture/v1/posture.yaml",
		corpus:   "../../../corpus/index.json",
		manifest: "../../../deploy/k8s/job.yaml",
		tier:     "restricted",
	})
	if err != nil {
		t.Fatal(err)
	}
	if ev.report.Attribution.Denials == 0 {
		t.Fatal("no denials attributed")
	}
	body := renderReport("test-context", ev)
	for _, want := range []string{
		reportMarker,
		"**Posture:** `v1`, tier `restricted`, workload `Job/caliper-probe`",
		"### Expectation violations (",
		"### Claim violations (",
		"### Undeclared exposures (",
		"- **socket** (",
		"Undecidable: ",
		"| `socket.family.af_alg` | `permitted` |",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("report lacks %q", want)
		}
	}
	if os.Getenv("CALIPER_SHOW_REPORT") != "" {
		t.Log(body)
	}
}

func TestReadMeasurementSkipsLeadingDiagnostics(t *testing.T) {
	data, err := os.ReadFile("../../../fixtures/x86_64-apparmor.json")
	if err != nil {
		t.Fatal(err)
	}
	data = bytes.Replace(data, []byte(`"corpus_set": "full"`), []byte(`"corpus_set": "reduced"`), 1)
	path := t.TempDir() + "/log"
	logged := append([]byte("caliper-probe: x: not measured: Undeclared\n"), data...)
	if err := os.WriteFile(path, logged, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readMeasurement(path); err != nil {
		t.Fatal(err)
	}
}
