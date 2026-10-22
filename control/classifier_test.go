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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClassifyRecordedFixtures(t *testing.T) {
	corpus := loadCorpus(t)
	baseline := loadFixture(t, "x86_64-apparmor.json")

	t.Run("runtime version remains policy", func(t *testing.T) {
		olderRuntime := loadFixture(t, "x86_64-apparmor-1.7.12.json")
		classified := mustClassify(t, baseline, olderRuntime, corpus)
		assertClass(t, classified, "io_uring.opcode.sendmsg_zc", PolicyExplained)
	})

	t.Run("architecture and kernel modules explain the arch pair", func(t *testing.T) {
		arm := loadFixture(t, "aarch64-apparmor.json")
		classified := mustClassify(t, baseline, arm, corpus)
		assertClass(t, classified, "capability.sys_rawio", ArchitectureExplained)
		assertClass(t, classified, "mount.type.9p", KernelVersionExplained)
		assertClass(t, classified, "mount.type.virtiofs", KernelVersionExplained)
		if classified.Counts.Policy != 0 {
			t.Errorf("counts = %#v, want no policy", classified.Counts)
		}
	})

	t.Run("architecture against hardened policy keeps socket and netlink probes as policy", func(t *testing.T) {
		arm := loadFixture(t, "aarch64-apparmor.json")
		hardened := loadFixture(t, "x86_64-apparmor-hardened.json")
		classified := mustClassify(t, arm, hardened, corpus)
		for _, id := range []string{
			"netlink.protocol.nflog",
			"netlink.protocol.smc",
			"socket.family.af_appletalk",
			"socket.family.af_ax25",
			"socket.family.af_bluetooth",
			"socket.family.af_ieee802154",
			"socket.family.af_kcm",
			"socket.family.af_nfc",
			"socket.family.af_qipcrtr",
			"socket.family.af_rds",
			"socket.family.af_smc",
			"socket.family.af_tipc",
			"socket.family.af_x25",
		} {
			assertClass(t, classified, id, PolicyExplained)
		}
	})

	t.Run("seccomp profile change is policy", func(t *testing.T) {
		hardened := loadFixture(t, "x86_64-apparmor-hardened.json")
		classified := mustClassify(t, baseline, hardened, corpus)
		want := DivergenceCounts{Policy: 120}
		if classified.Counts != want {
			t.Errorf("counts = %#v, want %#v", classified.Counts, want)
		}
	})
}

func TestClassifyUsesDeclaredArchitectureApplicability(t *testing.T) {
	left := fingerprintWithCell("x86_64", "6.8.0", "runc", []ProbeResult{{ProbeID: "x86-only", Verdict: "permitted"}})
	right := fingerprintWithCell("aarch64", "6.8.0", "runc", []ProbeResult{{ProbeID: "x86-only", Verdict: "not-applicable"}})
	classified := mustClassify(t, left, right, []ProbeMetadata{{
		ID:   "x86-only",
		Arch: Applicability{Only: []string{"x86_64"}},
	}})
	assertClass(t, classified, "x86-only", ArchitectureExplained)

	// A matching verdict alone is not enough: a probe declared for all
	// architectures is policy until some other declared explanation applies.
	classified = mustClassify(t, left, right, []ProbeMetadata{{
		ID:   "x86-only",
		Arch: Applicability{All: true},
	}})
	assertClass(t, classified, "x86-only", PolicyExplained)
}

func TestClassifyTreatsSandboxUnimplementedAsRuntimeClass(t *testing.T) {
	left := fingerprintWithCell("x86_64", "6.8.0", "runc", []ProbeResult{{ProbeID: "call", Verdict: "permitted"}})
	right := fingerprintWithCell("x86_64", "6.8.0", "gVisor", []ProbeResult{{ProbeID: "call", Verdict: "unimplemented", Errno: 38}})
	classified := mustClassify(t, left, right, []ProbeMetadata{{
		ID:     "call",
		Arch:   Applicability{All: true},
		Kernel: dependency(nil, 38),
	}})
	assertClass(t, classified, "call", RuntimeClassExplained)
	if classified.Counts.Policy != 0 || classified.Counts.RuntimeClass != 1 {
		t.Errorf("counts = %#v, want one runtime class and no policy", classified.Counts)
	}

	for _, runtimeClass := range []string{"kata", "kata-qemu", "kata-clh", "runsc", "runsc-kvm"} {
		t.Run(runtimeClass, func(t *testing.T) {
			right.Cell.RuntimeClass.Value = runtimeClass
			classified := mustClassify(t, left, right, []ProbeMetadata{{
				ID:     "call",
				Arch:   Applicability{All: true},
				Kernel: dependency(nil, 38),
			}})
			assertClass(t, classified, "call", RuntimeClassExplained)
		})
	}
}

func TestClassifyKernelDependencies(t *testing.T) {
	t.Run("encoded absence errno explains an unimplemented opcode", func(t *testing.T) {
		left := fingerprintWithCell("x86_64", "6.8.0", "runc", []ProbeResult{{ProbeID: "io_uring.opcode.sendmsg_zc", Verdict: "unimplemented", Errno: 61}})
		right := fingerprintWithCell("x86_64", "6.8.0", "runc", []ProbeResult{{ProbeID: "io_uring.opcode.sendmsg_zc", Verdict: "permitted"}})
		classified := mustClassify(t, left, right, []ProbeMetadata{{
			ID:   "io_uring.opcode.sendmsg_zc",
			Arch: Applicability{All: true},
			Kernel: KernelDependency{
				AbsentErrno:   intPointer(38),
				EncodedAbsent: intPointer(61),
			},
		}})
		assertClass(t, classified, "io_uring.opcode.sendmsg_zc", KernelVersionExplained)
	})

	t.Run("present-if dependency explains its absent errno", func(t *testing.T) {
		left := fingerprintWithCell("x86_64", "6.8.0", "runc", []ProbeResult{{ProbeID: "config-gated-call", Verdict: "unimplemented", Errno: 38}})
		right := fingerprintWithCell("x86_64", "6.8.0", "runc", []ProbeResult{{ProbeID: "config-gated-call", Verdict: "permitted"}})
		classified := mustClassify(t, left, right, []ProbeMetadata{{
			ID:   "config-gated-call",
			Arch: Applicability{All: true},
			Kernel: KernelDependency{
				AbsentErrno: intPointer(38),
				PresentIf:   "/proc/sys/kernel/io_uring_disabled",
			},
		}})
		assertClass(t, classified, "config-gated-call", KernelVersionExplained)
	})

	t.Run("declared version gate", func(t *testing.T) {
		left := fingerprintWithCell("x86_64", "5.2.0", "runc", []ProbeResult{{ProbeID: "new-call", Verdict: "unimplemented", Errno: 38}})
		right := fingerprintWithCell("x86_64", "6.8.0", "runc", []ProbeResult{{ProbeID: "new-call", Verdict: "permitted"}})
		classified := mustClassify(t, left, right, []ProbeMetadata{{
			ID:     "new-call",
			Arch:   Applicability{All: true},
			Kernel: dependency(&KernelVersion{5, 3}, 38),
		}})
		assertClass(t, classified, "new-call", KernelVersionExplained)
	})

	t.Run("unimplemented is kernel-explained only against permitted", func(t *testing.T) {
		for _, verdict := range []string{"denied", "killed", "timed-out"} {
			t.Run(verdict, func(t *testing.T) {
				left := fingerprintWithCell("x86_64", "5.2.0", "runc", []ProbeResult{{ProbeID: "new-call", Verdict: "unimplemented", Errno: 38}})
				right := fingerprintWithCell("x86_64", "6.8.0", "runc", []ProbeResult{{ProbeID: "new-call", Verdict: Verdict(verdict)}})
				classified := mustClassify(t, left, right, []ProbeMetadata{{
					ID:     "new-call",
					Arch:   Applicability{All: true},
					Kernel: dependency(&KernelVersion{5, 3}, 38),
				}})
				assertClass(t, classified, "new-call", PolicyExplained)
			})
		}
	})

	t.Run("seccomp kill remains policy across a kernel version gate", func(t *testing.T) {
		olderUnimplemented := fingerprintWithCell("x86_64", "5.2.0", "runc", []ProbeResult{{ProbeID: "new-call", Verdict: "unimplemented", Errno: 38}})
		newerKilled := fingerprintWithCell("x86_64", "6.8.0", "runc", []ProbeResult{{ProbeID: "new-call", Verdict: "killed"}})
		for _, pair := range []struct {
			name        string
			left, right Fingerprint
		}{
			{name: "older first", left: olderUnimplemented, right: newerKilled},
			{name: "newer first", left: newerKilled, right: olderUnimplemented},
		} {
			t.Run(pair.name, func(t *testing.T) {
				classified := mustClassify(t, pair.left, pair.right, []ProbeMetadata{{
					ID:     "new-call",
					Arch:   Applicability{All: true},
					Kernel: dependency(&KernelVersion{5, 3}, 38),
				}})
				assertClass(t, classified, "new-call", PolicyExplained)
			})
		}
	})

	t.Run("module-gated dependency", func(t *testing.T) {
		left := fingerprintWithCell("x86_64", "6.8.0", "runc", []ProbeResult{{ProbeID: "module-call", Verdict: "unimplemented", Errno: 93}})
		left.Cell.Kernel.Modules = modules("nf_tables", "netlink_diag")
		right := fingerprintWithCell("x86_64", "6.8.0", "runc", []ProbeResult{{ProbeID: "module-call", Verdict: "permitted"}})
		right.Cell.Kernel.Modules = modules("nf_tables")
		classified := mustClassify(t, left, right, []ProbeMetadata{{
			ID:     "module-call",
			Arch:   Applicability{All: true},
			Kernel: KernelDependency{AbsentErrno: intPointer(93), Module: "netlink_diag"},
		}})
		assertClass(t, classified, "module-call", KernelVersionExplained)
	})

	t.Run("unrelated module changes do not explain a probe", func(t *testing.T) {
		left := fingerprintWithCell("x86_64", "6.8.0", "runc", []ProbeResult{{ProbeID: "module-call", Verdict: "unimplemented", Errno: 93}})
		left.Cell.Kernel.Modules = modules("nf_tables")
		right := fingerprintWithCell("x86_64", "6.8.0", "runc", []ProbeResult{{ProbeID: "module-call", Verdict: "permitted"}})
		right.Cell.Kernel.Modules = modules("netlink_diag")
		classified := mustClassify(t, left, right, []ProbeMetadata{{
			ID: "module-call", Arch: Applicability{All: true}, Kernel: dependency(nil, 93),
		}})
		assertClass(t, classified, "module-call", PolicyExplained)
	})

	t.Run("declared module dependency requires known module lists", func(t *testing.T) {
		left := fingerprintWithCell("x86_64", "6.8.0", "runc", []ProbeResult{{ProbeID: "module-call", Verdict: "unimplemented", Errno: 93}})
		right := fingerprintWithCell("x86_64", "6.8.0", "runc", []ProbeResult{{ProbeID: "module-call", Verdict: "permitted"}})
		right.Cell.Kernel.Modules = modules("netlink_diag")
		_, err := Classify(left, right, []ProbeMetadata{{
			ID: "module-call", Arch: Applicability{All: true},
			Kernel: KernelDependency{AbsentErrno: intPointer(93), Module: "netlink_diag"},
		}})
		if err == nil || !strings.Contains(err.Error(), "no kernel module list") {
			t.Fatalf("Classify error = %v, want missing module list error", err)
		}
	})

	t.Run("release alone does not explain a probe without a dependency", func(t *testing.T) {
		left := fingerprintWithCell("x86_64", "5.2.0", "runc", []ProbeResult{{ProbeID: "ordinary", Verdict: "unimplemented", Errno: 38}})
		right := fingerprintWithCell("x86_64", "6.8.0", "runc", []ProbeResult{{ProbeID: "ordinary", Verdict: "permitted"}})
		classified := mustClassify(t, left, right, []ProbeMetadata{{ID: "ordinary", Arch: Applicability{All: true}}})
		assertClass(t, classified, "ordinary", PolicyExplained)
	})
}

func TestClassifyRejectsUnknownDivergentProbe(t *testing.T) {
	left := fingerprintWithCell("x86_64", "6.8.0", "runc", []ProbeResult{{ProbeID: "unknown", Verdict: "denied"}})
	right := fingerprintWithCell("x86_64", "6.8.0", "runc", []ProbeResult{{ProbeID: "unknown", Verdict: "permitted"}})
	if _, err := Classify(left, right, nil); err == nil || err.Error() != `no corpus metadata for divergent probe "unknown"` {
		t.Fatalf("Classify error = %v, want missing metadata error", err)
	}
}

func TestClassifyTreatsMissingRuntimeClassAsNotSandboxed(t *testing.T) {
	left := fingerprintWithCell("x86_64", "6.8.0", "runc", []ProbeResult{{ProbeID: "call", Verdict: "permitted"}})
	right := fingerprintWithCell("x86_64", "6.8.0", "runc", []ProbeResult{{ProbeID: "call", Verdict: "unimplemented", Errno: 38}})
	right.Cell.RuntimeClass = nil
	classified, err := Classify(left, right, []ProbeMetadata{{ID: "call", Arch: Applicability{All: true}}})
	if err != nil {
		t.Fatalf("Classify with default runtime class: %v", err)
	}
	assertClass(t, classified, "call", PolicyExplained)
}

func TestCorpusDeclaresPerProbeModuleDependencies(t *testing.T) {
	corpus := loadCorpus(t)
	byID, err := metadataByID(corpus)
	if err != nil {
		t.Fatalf("metadataByID: %v", err)
	}
	want := map[string]string{
		"mount.type.9p":                  "9p",
		"mount.type.virtiofs":            "virtiofs",
		"socket.family.af_alg":           "af_alg",
		"socket.family.af_packet":        "af_packet",
		"socket.family.af_inet6":         "ipv6",
		"socket.family.af_key":           "af_key",
		"socket.family.af_bluetooth":     "bluetooth",
		"socket.family.af_can":           "can",
		"socket.family.af_tipc":          "tipc",
		"socket.family.af_rds":           "rds",
		"socket.family.af_rxrpc":         "rxrpc",
		"socket.family.af_phonet":        "phonet",
		"socket.family.af_ieee802154":    "ieee802154_socket",
		"socket.family.af_nfc":           "nfc",
		"socket.family.af_vsock":         "vsock",
		"socket.family.af_kcm":           "kcm",
		"socket.family.af_qipcrtr":       "qrtr",
		"socket.family.af_smc":           "smc",
		"socket.family.af_mctp":          "mctp",
		"socket.family.af_ax25":          "ax25",
		"socket.family.af_appletalk":     "appletalk",
		"socket.family.af_x25":           "x25",
		"netlink.protocol.xfrm":          "xfrm_user",
		"netlink.protocol.iscsi":         "scsi_transport_iscsi",
		"netlink.protocol.connector":     "cn",
		"netlink.protocol.netfilter":     "nfnetlink",
		"netlink.protocol.scsitransport": "scsi_mod",
		"netlink.protocol.rdma":          "ib_core",
		"netlink.protocol.crypto":        "crypto_user",
		"netlink.protocol.smc":           "smc",
	}
	for id, module := range want {
		probe, exists := byID[id]
		if !exists {
			t.Errorf("corpus metadata missing probe %q", id)
			continue
		}
		if probe.Kernel.Module != module {
			t.Errorf("%s module = %q, want %q", id, probe.Kernel.Module, module)
		}
	}
}

func TestClassifyDefers32BitCompatKernelDetection(t *testing.T) {
	// The engine does not yet emit a runtime ABI applicability record for the
	// 32-bit compat ABI. Until it does, differences fall back to policy.
	left := fingerprintWithCell("aarch64", "6.8.0", "runc", []ProbeResult{{ProbeID: "compat", Verdict: "unimplemented", Errno: 38}})
	right := fingerprintWithCell("aarch64", "6.8.0", "runc", []ProbeResult{{ProbeID: "compat", Verdict: "permitted"}})
	classified := mustClassify(t, left, right, []ProbeMetadata{{ID: "compat", Arch: Applicability{All: true}}})
	assertClass(t, classified, "compat", PolicyExplained)
}

func loadCorpus(t *testing.T) []ProbeMetadata {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "corpus", "index.json"))
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	var corpus []ProbeMetadata
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatalf("parse corpus: %v", err)
	}
	return corpus
}

func fingerprintWithCell(architecture, release, runtimeClass string, results []ProbeResult) Fingerprint {
	fingerprint := testFingerprint(results)
	fingerprint.Cell = Cell{
		Architecture: architecture,
		Kernel:       Kernel{Release: release},
		RuntimeClass: &SourcedValue{Value: runtimeClass, Source: "test"},
	}
	return fingerprint
}

func dependency(since *KernelVersion, absentErrno int) KernelDependency {
	return KernelDependency{Since: since, AbsentErrno: &absentErrno}
}

func intPointer(value int) *int {
	return &value
}

func modules(names ...string) *[]string {
	return &names
}

func mustClassify(t *testing.T, left, right Fingerprint, corpus []ProbeMetadata) ClassificationResult {
	t.Helper()
	classified, err := Classify(left, right, corpus)
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	return classified
}

func assertClass(t *testing.T, result ClassificationResult, id string, want DivergenceClass) {
	t.Helper()
	for _, divergence := range result.Divergences {
		if divergence.ProbeID == id {
			if divergence.Class != want {
				t.Errorf("%s class = %q, want %q", id, divergence.Class, want)
			}
			return
		}
	}
	t.Errorf("no classified divergence for %q: %#v", id, result.Divergences)
}

func TestAlsoAbsentErrnoExplainsAProtocolModuleBoundary(t *testing.T) {
	eafnosupport, eprotonosupport := 97, 93
	probe := ProbeMetadata{ID: "socket.family.af_can", Arch: Applicability{All: true},
		Kernel: KernelDependency{AbsentErrno: &eafnosupport, AlsoAbsent: &eprotonosupport, Module: "can", ProtocolModule: "can_raw"}}
	classify := func(errno int, leftModules, rightModules []string) ClassificationResult {
		left := fingerprintWithCell("x86_64", "6.8.0", "runc", []ProbeResult{{ProbeID: probe.ID, Verdict: "unimplemented", Errno: errno}})
		right := fingerprintWithCell("x86_64", "6.8.0", "runc", []ProbeResult{{ProbeID: probe.ID, Verdict: "permitted"}})
		left.Cell.Kernel.Modules = &leftModules
		right.Cell.Kernel.Modules = &rightModules
		return mustClassify(t, left, right, []ProbeMetadata{probe})
	}
	// EPROTONOSUPPORT means the family is loaded on both sides: only the
	// protocol's module can tell them apart.
	assertClass(t, classify(eprotonosupport, []string{"can"}, []string{"can", "can_raw"}), probe.ID, KernelVersionExplained)
	assertClass(t, classify(eprotonosupport, []string{"can", "can_raw"}, []string{"can", "can_raw"}), probe.ID, PolicyExplained)
	assertClass(t, classify(eafnosupport, []string{}, []string{"can", "can_raw"}), probe.ID, KernelVersionExplained)
}
