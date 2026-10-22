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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunWritesBothProfiles(t *testing.T) {
	dir := t.TempDir()
	findings := filepath.Join(dir, "findings.json")
	runtime := filepath.Join(dir, "default.json")
	spo := filepath.Join(dir, "profile.yaml")
	localhost := filepath.Join(dir, "profile.json")
	if err := os.WriteFile(findings, []byte(`{
  "posture_revision":"v1", "tier":"baseline",
  "expectation_violations":[{
    "kind":"expectation-violation", "posture_revision":"v1", "tier":"baseline",
    "family":"socket", "probe_id":"socket.family.af_alg", "verdict":"permitted"
  }]
}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(runtime, []byte(`{
  "defaultAction":"SCMP_ACT_ERRNO",
  "syscalls":[{"names":["socket"],"action":"SCMP_ACT_ALLOW"}]
}`), 0o644); err != nil {
		t.Fatal(err)
	}
	err := run(inputs{
		findings: findings, runtime: runtime, runtimeArch: "amd64", ociArch: "SCMP_ARCH_X86_64",
		kernel: "6.8.0", spoOut: spo, localOut: localhost,
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(spo)
	if err != nil || !strings.Contains(string(data), "kind: SeccompProfile") {
		t.Fatalf("SPO = %q, %v", data, err)
	}
	data, err = os.ReadFile(localhost)
	if err != nil || !strings.Contains(string(data), "SCMP_ARCH_X86_64") {
		t.Fatalf("Localhost = %q, %v", data, err)
	}
}
