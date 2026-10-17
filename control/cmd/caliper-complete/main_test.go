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
	"testing"

	"github.com/Abhinavmadake/caliper/control"
)

func TestRunCompletesAndDigests(t *testing.T) {
	raw, err := os.ReadFile("../../../fixtures/x86_64-apparmor.json")
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err = run(bytes.NewReader(raw), &out, control.CellMetadata{
		RuntimeClass:      operator(" runsc "),
		NodeKernelVersion: "7.0.0-1014-gcp",
	})
	if err != nil {
		t.Fatal(err)
	}
	fp, err := control.DecodeFingerprint(out.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if fp.Cell.RuntimeClass == nil || fp.Cell.RuntimeClass.Value != "runsc" || fp.Cell.RuntimeClass.Source != "operator" {
		t.Errorf("runtime_class = %+v", fp.Cell.RuntimeClass)
	}
	if fp.Cell.Kernel.SandboxClaimed == nil || !*fp.Cell.Kernel.SandboxClaimed {
		t.Errorf("sandbox_claimed = %v, want true for a probe kernel unlike the node's", fp.Cell.Kernel.SandboxClaimed)
	}
	want, err := control.ComputeFingerprintDigest(fp)
	if err != nil || fp.Digest != want {
		t.Errorf("digest = %q, want %q (%v)", fp.Digest, want, err)
	}
}
