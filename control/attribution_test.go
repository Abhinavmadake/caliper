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
	"encoding/json"
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

func TestCorrelationUsesProcessCapabilitiesAndLSMLabel(t *testing.T) {
	eperm, eacces := 1, 13
	capability := ProbeMetadata{ID: "cap", Oracle: Oracle{Isolates: "undecidable"}, Capability: "CAP_SYS_BOOT"}
	lsm := ProbeMetadata{ID: "lsm", Oracle: Oracle{Isolates: "seccomp-or-lsm"}}

	droppedBoot := Cell{Capabilities: json.RawMessage(`{"effective":"0000000000000000","bounding":"0000000000400000"}`)}
	got := correlate(undecidable([]Mechanism{Seccomp, CapabilityMissing}, ""), ProbeResult{Verdict: "denied", Errno: eperm}, capability, droppedBoot)
	if got.Mechanism == nil || *got.Mechanism != CapabilityMissing || got.Confidence != Low || got.Undecidable {
		t.Errorf("missing capability correlation = %+v", got)
	}

	withBoot := Cell{Capabilities: json.RawMessage(`{"effective":"0000000000400000","bounding":"0000000000400000"}`)}
	got = correlate(undecidable([]Mechanism{Seccomp, CapabilityMissing}, ""), ProbeResult{Verdict: "denied", Errno: eperm}, capability, withBoot)
	if got.Mechanism != nil || !got.Undecidable || !reflect.DeepEqual(got.Candidates, []Mechanism{Seccomp, LSM}) {
		t.Errorf("present capability correlation = %+v", got)
	}

	outsideBounding := Cell{Capabilities: json.RawMessage(`{"effective":"0000000000000000","bounding":"0000000000000000"}`)}
	got = correlate(undecidable([]Mechanism{Seccomp, CapabilityMissing}, ""), ProbeResult{Verdict: "denied", Errno: eperm}, capability, outsideBounding)
	if got.Mechanism != nil || !got.Undecidable || !reflect.DeepEqual(got.Candidates, []Mechanism{Seccomp, CapabilityMissing}) {
		t.Errorf("capability outside bounding correlation = %+v", got)
	}

	label := "docker-default (enforce)"
	enforcing := true
	confined := Cell{LSM: "apparmor", LSMLabel: &label, LSMEnforcing: &enforcing}
	got = correlate(undecidable(nil, ""), ProbeResult{Verdict: "denied", Errno: eacces}, lsm, confined)
	if got.Mechanism == nil || *got.Mechanism != LSM || got.Confidence != Low || got.Undecidable {
		t.Errorf("LSM correlation = %+v", got)
	}
}

func TestAttributePreservesSourceFingerprintDigest(t *testing.T) {
	fingerprint := testFingerprint([]ProbeResult{{ProbeID: "p", Verdict: "denied", Errno: 1}})
	fingerprint.Digest = "sha256:stale"

	attributed, err := Attribute(fingerprint, []ProbeMetadata{{
		ID:     "p",
		Oracle: Oracle{Isolates: "seccomp"},
	}})
	if err != nil {
		t.Fatalf("Attribute: %v", err)
	}
	if attributed.Digest != fingerprint.Digest {
		t.Errorf("digest = %q, want source digest %q", attributed.Digest, fingerprint.Digest)
	}
}

func TestAttributeAssignsConfidenceToEveryResult(t *testing.T) {
	ebadf := 9
	fingerprint := Fingerprint{Results: []ProbeResult{
		{ProbeID: "permitted", Verdict: "permitted"},
		{ProbeID: "denied", Verdict: "denied", Errno: errnoEPERM},
		{ProbeID: "killed", Verdict: "killed"},
		{ProbeID: "unimplemented", Verdict: "unimplemented", Errno: errnoENOSYS},
		{ProbeID: "timed-out", Verdict: "timed-out"},
	}}
	corpus := []ProbeMetadata{
		{ID: "permitted", Oracle: Oracle{Isolates: "seccomp"}},
		{ID: "denied", Oracle: Oracle{Guarantees: &ebadf, Isolates: "seccomp"}},
		{ID: "killed", Oracle: Oracle{Isolates: "seccomp"}},
		{ID: "unimplemented", Oracle: Oracle{Isolates: "seccomp"}},
		{ID: "timed-out", Oracle: Oracle{Isolates: "seccomp"}},
	}

	attributed, err := Attribute(fingerprint, corpus)
	if err != nil {
		t.Fatalf("Attribute: %v", err)
	}
	for _, result := range attributed.Results {
		if result.Attribution == nil {
			t.Errorf("%s has no attribution", result.ProbeID)
			continue
		}
		switch result.Attribution.Confidence {
		case High, Medium, Low:
		default:
			t.Errorf("%s has invalid confidence %q", result.ProbeID, result.Attribution.Confidence)
		}
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
	assert(def, "socket.family.af_packet", CapabilityMissing, Low)
	if got := def["unshare.flags.newns"]; got.Mechanism != nil || !got.Undecidable || !reflect.DeepEqual(got.Candidates, []Mechanism{Seccomp, CapabilityMissing}) {
		t.Errorf("unshare.flags.newns = %+v, want undecidable between seccomp and a missing capability", got)
	}
	assert(def, "path.masked.proc_kcore", Mount, High)
	assert(def, "path.readonly.proc_bus", Mount, High)

	hardened := loadFixture(t, "x86_64-apparmor-hardened.json")
	byID := attributed("x86_64-apparmor-hardened.json")
	for _, r := range hardened.Results {
		if r.Verdict == "killed" {
			assert(byID, r.ProbeID, Seccomp, High)
		}
	}
}

func TestLSMHookSinceTurnsSeccompIntoSeccompOrLSM(t *testing.T) {
	einval := 22
	since := KernelVersion{6, 15}
	probe := ProbeMetadata{ID: "io_uring.setup.zero_entries", Family: "io_uring",
		Kernel: KernelDependency{LSMHookSince: &since},
		Oracle: Oracle{Guarantees: &einval, Isolates: "seccomp"}}
	denied := ProbeResult{ProbeID: probe.ID, Verdict: "denied", Errno: errnoEPERM}
	for _, test := range []struct {
		release string
		want    string
	}{
		{"6.8.0-142-generic", "seccomp"},
		{"7.0.0-1014-gcp", "seccomp-or-lsm"},
		{"unparseable", "seccomp-or-lsm"},
	} {
		fp := Fingerprint{Cell: Cell{Kernel: Kernel{Release: test.release}}, Results: []ProbeResult{denied}}
		got, err := Attribute(fp, []ProbeMetadata{probe})
		if err != nil {
			t.Fatal(err)
		}
		a := got.Results[0].Attribution
		mechanismSeccomp := a.Mechanism != nil && *a.Mechanism == Seccomp
		if (test.want == "seccomp") != mechanismSeccomp || (test.want != "seccomp") != a.Undecidable {
			t.Errorf("%s: attribution = %+v, want %s", test.release, a, test.want)
		}
	}
}

func TestUserNamespaceLimitsWidenOrExplainTheDenial(t *testing.T) {
	zero, one := uint64(0), uint64(1)
	probe := ProbeMetadata{ID: "unshare.flags.newuser", Family: "clone", Oracle: Oracle{Isolates: "seccomp-or-lsm"},
		Kernel: KernelDependency{UserNamespaceLimits: true}}
	attribute := func(errno int, limits UserNamespaces, lsm string) Attribution {
		fp := Fingerprint{
			Cell:    Cell{LSM: lsm, UserNamespaces: &limits},
			Results: []ProbeResult{{ProbeID: probe.ID, Verdict: "denied", Errno: errno}},
		}
		got, err := Attribute(fp, []ProbeMetadata{probe})
		if err != nil {
			t.Fatal(err)
		}
		return *got.Results[0].Attribution
	}

	if a := attribute(errnoENOSPC, UserNamespaces{Max: &zero}, "none"); a.Mechanism == nil || *a.Mechanism != KernelLimit {
		t.Errorf("max_user_namespaces=0 ENOSPC = %+v, want kernel-limit", a)
	}
	a := attribute(errnoEPERM, UserNamespaces{UnprivilegedClone: &zero, ApparmorRestricted: &one}, "apparmor")
	want := []Mechanism{Seccomp, LSM, KernelLimit}
	if !a.Undecidable || !reflect.DeepEqual(a.Candidates, want) {
		t.Errorf("restricted EPERM = %+v, want undecidable %v", a, want)
	}
	// The limit widens the oracle's reading: an LSM other than AppArmor's
	// sysctl stays a candidate.
	if a := attribute(errnoEPERM, UserNamespaces{UnprivilegedClone: &zero}, "selinux"); !reflect.DeepEqual(a.Candidates, want) {
		t.Errorf("unprivileged_userns_clone=0 under SELinux = %+v, want %v", a, want)
	}
	if a := attribute(errnoEPERM, UserNamespaces{Max: &one, UnprivilegedClone: &one}, "apparmor"); reflect.DeepEqual(a.Candidates, want) {
		t.Errorf("no limit set should not add candidates: %+v", a)
	}
}

func TestCellStateEliminatesCandidates(t *testing.T) {
	zero, two, one := uint64(0), uint64(2), uint64(1)
	enforcing, notEnforcing := true, false
	label := "cri-containerd.apparmor.d (enforce)"
	lsmProbe := ProbeMetadata{ID: "socket.lsm", Family: "socket", Oracle: Oracle{Isolates: "seccomp-or-lsm"}}
	capProbe := ProbeMetadata{ID: "capability.sys_time", Family: "capability", Oracle: Oracle{Isolates: "undecidable"}, Capability: "CAP_SYS_TIME"}
	userns := ProbeMetadata{ID: "unshare.flags.newuser", Family: "clone", Oracle: Oracle{Isolates: "seccomp-or-lsm"},
		Kernel: KernelDependency{UserNamespaceLimits: true}}
	attribute := func(cell Cell, probe ProbeMetadata) Attribution {
		fp := Fingerprint{Cell: cell, Results: []ProbeResult{{ProbeID: probe.ID, Verdict: "denied", Errno: errnoEPERM}}}
		got, err := Attribute(fp, []ProbeMetadata{probe})
		if err != nil {
			t.Fatal(err)
		}
		return *got.Results[0].Attribution
	}
	want := func(name string, a Attribution, m Mechanism) {
		t.Helper()
		if a.Undecidable || a.Mechanism == nil || *a.Mechanism != m || a.Confidence != Medium {
			t.Errorf("%s = %+v, want %s at medium confidence", name, a, m)
		}
	}

	want("no filter under an enforcing label",
		attribute(Cell{LSM: "apparmor", LSMLabel: &label, LSMEnforcing: &enforcing, Seccomp: &SeccompState{Mode: &zero}}, lsmProbe), LSM)
	want("filter with the LSM not enforcing",
		attribute(Cell{LSM: "apparmor", LSMEnforcing: &notEnforcing, Seccomp: &SeccompState{Mode: &two}}, lsmProbe), Seccomp)
	want("filter and no LSM", attribute(Cell{LSM: "none"}, lsmProbe), Seccomp)
	want("missing capability without a filter",
		attribute(Cell{LSM: "none", Seccomp: &SeccompState{Mode: &zero}, Capabilities: json.RawMessage(`{"effective":"0000000000000000","bounding":"0000000000000000"}`)}, capProbe), CapabilityMissing)

	if a := attribute(Cell{LSM: "apparmor", LSMLabel: &label, LSMEnforcing: &enforcing}, lsmProbe); !a.Undecidable {
		t.Errorf("no seccomp state under an enforcing label = %+v, want undecidable", a)
	}
	// AppArmor's user-namespace restriction reaches unconfined tasks, so a
	// non-enforcing label does not rule the LSM out there.
	a := attribute(Cell{LSM: "apparmor", LSMEnforcing: &notEnforcing, Seccomp: &SeccompState{Mode: &zero},
		UserNamespaces: &UserNamespaces{ApparmorRestricted: &one}}, userns)
	want("restricted userns without a filter", a, LSM)
}
