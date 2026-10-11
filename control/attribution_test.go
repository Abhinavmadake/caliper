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

package control

import (
	"reflect"
	"testing"
)

func TestAttributeRules(t *testing.T) {
	ebadf, einval := 9, 22
	seccompGuaranteed := ProbeMetadata{ID: "p", Family: "f", Oracle: Oracle{Guarantees: &ebadf, Isolates: "seccomp"}}
	seccompStructural := ProbeMetadata{ID: "p", Family: "f", Oracle: Oracle{Isolates: "seccomp"}}
	seccompOrLSM := ProbeMetadata{ID: "p", Family: "f", Oracle: Oracle{Isolates: "seccomp-or-lsm"}}
	capability := ProbeMetadata{ID: "p", Family: "f", Oracle: Oracle{Guarantees: &einval, Isolates: "undecidable"}, Capability: "CAP_SYS_BOOT"}
	noCapability := ProbeMetadata{ID: "p", Family: "f", Oracle: Oracle{Isolates: "undecidable"}}
	path := ProbeMetadata{ID: "p", Family: "path", Oracle: Oracle{Isolates: "seccomp-or-lsm"}}

	tests := []struct {
		name        string
		verdict     Verdict
		errno       int
		probe       ProbeMetadata
		mechanism   Mechanism
		confidence  Confidence
		undecidable bool
		candidates  []Mechanism
	}{
		{"killed is seccomp", "killed", 0, seccompOrLSM, Seccomp, High, false, nil},
		{"permitted is no denial", "permitted", 0, seccompOrLSM, "", High, false, nil},
		{"guaranteed errno reached the kernel", "permitted", 9, seccompGuaranteed, "", High, false, nil},
		{"unimplemented is no denial", "unimplemented", 97, seccompOrLSM, "", High, false, nil},
		{"not-applicable is no denial", "not-applicable", 0, seccompOrLSM, "", High, false, nil},
		{"timed-out is undecidable", "timed-out", 0, seccompGuaranteed, "", Low, true, nil},
		{"EPERM against a guarantee proves a filter", "denied", 1, seccompGuaranteed, Seccomp, High, false, nil},
		{"EPERM before any hook without a guarantee", "denied", 1, seccompStructural, Seccomp, Medium, false, nil},
		{"ENOSYS from an implemented syscall is a filter", "denied", 38, seccompGuaranteed, Seccomp, High, false, nil},
		{"EPERM after the LSM hook", "denied", 1, seccompOrLSM, "", Low, true, []Mechanism{Seccomp, LSM}},
		{"EPERM from the syscall's own capability check", "denied", 1, capability, "", Low, true, []Mechanism{Seccomp, CapabilityMissing}},
		{"EPERM with nothing to correlate", "denied", 1, noCapability, "", Low, true, nil},
		{"EACCES is left to LSM correlation", "denied", 13, seccompOrLSM, "", Low, true, nil},
		{"ENODATA in the path family is a mask", "denied", 61, path, Mount, High, false, nil},
		{"EROFS in the path family is a read-only mount", "denied", 30, path, Mount, High, false, nil},
		{"ENODATA elsewhere is not a mask", "denied", 61, seccompOrLSM, "", Low, true, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := attribute(ProbeResult{ProbeID: "p", Verdict: tt.verdict, Errno: tt.errno}, tt.probe)
			var mechanism Mechanism
			if got.Mechanism != nil {
				mechanism = *got.Mechanism
			}
			if mechanism != tt.mechanism || got.Confidence != tt.confidence || got.Undecidable != tt.undecidable ||
				!reflect.DeepEqual(got.Candidates, tt.candidates) {
				t.Errorf("got %+v (mechanism %q)", got, mechanism)
			}
			if got.Undecidable == (got.Mechanism != nil) && tt.verdict == "denied" {
				t.Errorf("a denial must have a mechanism or be undecidable, not both: %+v", got)
			}
		})
	}
}

func TestAttributeRecordedFixtures(t *testing.T) {
	corpus := loadCorpus(t)
	attributed := func(name string) map[string]Attribution {
		t.Helper()
		fp, err := Attribute(loadFixture(t, name), corpus)
		if err != nil {
			t.Fatalf("Attribute(%s): %v", name, err)
		}
		byID := make(map[string]Attribution, len(fp.Results))
		for _, r := range fp.Results {
			byID[r.ProbeID] = *r.Attribution
		}
		return byID
	}
	assert := func(byID map[string]Attribution, id string, mechanism Mechanism, confidence Confidence) {
		t.Helper()
		a, ok := byID[id]
		if !ok {
			t.Fatalf("%s missing", id)
		}
		var got Mechanism
		if a.Mechanism != nil {
			got = *a.Mechanism
		}
		if got != mechanism || a.Confidence != confidence {
			t.Errorf("%s = %+v (mechanism %q), want %q at %q", id, a, got, mechanism, confidence)
		}
	}

	def := attributed("x86_64-apparmor.json")
	assert(def, "io_uring.register.probe", Seccomp, High)
	assert(def, "io_uring.opcode.nop", Seccomp, Medium)
	assert(def, "clone3.args.short", Seccomp, High)
	assert(def, "socket.family.out_of_range", "", High)
	assert(def, "socket.family.af_vsock", "", Low)
	assert(def, "socket.family.af_packet", "", Low)
	assert(def, "path.masked.proc_kcore", Mount, High)
	assert(def, "path.readonly.proc_bus", Mount, High)
	if got := def["socket.family.af_packet"].Candidates; !reflect.DeepEqual(got, []Mechanism{Seccomp, CapabilityMissing}) {
		t.Errorf("af_packet candidates = %v", got)
	}

	hardened := loadFixture(t, "x86_64-apparmor-hardened.json")
	byID := attributed("x86_64-apparmor-hardened.json")
	for _, r := range hardened.Results {
		if r.Verdict == "killed" {
			assert(byID, r.ProbeID, Seccomp, High)
		}
	}
}
