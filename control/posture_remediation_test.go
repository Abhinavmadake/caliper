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
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func expectation(id string) Finding {
	return Finding{Kind: ExpectationViolation, PostureRevision: "v1", Tier: "untrusted-multi-tenant", Family: "test", ProbeID: id, Verdict: "permitted"}
}

func runtimeDefault() LocalhostProfile {
	return LocalhostProfile{
		DefaultAction: "SCMP_ACT_ERRNO",
		Syscalls: []SeccompRule{{
			Names:  []string{"read", "write", "exit", "exit_group"},
			Action: "SCMP_ACT_ALLOW",
		}},
	}
}

func TestGenerateRemediationUsesArgumentRulesAndSPO(t *testing.T) {
	report := FindingReport{PostureRevision: "v1", Tier: "untrusted-multi-tenant", ExpectationViolations: []Finding{
		expectation("socket.family.af_alg"), expectation("netlink.protocol.crypto"), expectation("unshare.flags.newuser"), expectation("io_uring.setup"),
	}}
	remediation, err := GenerateRemediation(report, runtimeDefault())
	if err != nil {
		t.Fatalf("GenerateRemediation() error = %v", err)
	}
	if remediation.SPO.Kind != "SeccompProfile" || remediation.SPO.Metadata.Name != "caliper-v1" {
		t.Fatalf("SPO = %#v", remediation.SPO)
	}
	if len(remediation.Closures) != 5 || len(remediation.NotClosable) != 0 {
		t.Fatalf("closures/not closable = %d/%d", len(remediation.Closures), len(remediation.NotClosable))
	}
	var afalg, netlink, unshare bool
	for _, closure := range remediation.Closures {
		switch closure.ProbeID {
		case "socket.family.af_alg":
			afalg = len(closure.Rule.Args) == 1 && closure.Rule.Args[0].Index == 0 && closure.Rule.Args[0].Value == 38
		case "netlink.protocol.crypto":
			netlink = len(closure.Rule.Args) == 2 && closure.Rule.Args[0].Value == 16 && closure.Rule.Args[1].Value == 21
		case "unshare.flags.newuser":
			unshare = closure.Rule.Args[0].Op == "SCMP_CMP_MASKED_EQ" && closure.Rule.Args[0].Value == 0x10000000 && closure.Rule.Args[0].ValueTwo != nil && *closure.Rule.Args[0].ValueTwo == 0x10000000
		}
	}
	if !afalg || !netlink || !unshare {
		t.Errorf("argument rules missing: af_alg=%t netlink=%t unshare=%t", afalg, netlink, unshare)
	}
	spo, err := remediation.RenderSPO()
	if err != nil {
		t.Fatal(err)
	}
	var decoded SPOProfile
	if err := yaml.Unmarshal(spo, &decoded); err != nil {
		t.Fatalf("parse SPO YAML: %v", err)
	}
	if decoded.Spec.DefaultAction != "SCMP_ACT_ERRNO" {
		t.Errorf("SPO default action = %q, want RuntimeDefault action", decoded.Spec.DefaultAction)
	}
	foundRuntimeAllowlist := false
	for _, rule := range decoded.Spec.Syscalls {
		if rule.Action == "SCMP_ACT_ALLOW" && strings.Join(rule.Names, ",") == "read,write,exit,exit_group" {
			foundRuntimeAllowlist = true
		}
	}
	if !foundRuntimeAllowlist {
		t.Errorf("SPO did not retain the RuntimeDefault allowlist: %#v", decoded.Spec.Syscalls)
	}
	localhost, err := remediation.RenderLocalhost()
	if err != nil {
		t.Fatal(err)
	}
	var local LocalhostProfile
	if err := json.Unmarshal(localhost, &local); err != nil {
		t.Fatalf("parse Localhost JSON: %v", err)
	}
	if local.DefaultAction != "SCMP_ACT_ERRNO" {
		t.Errorf("Localhost default action = %q, want RuntimeDefault action", local.DefaultAction)
	}
	if len(local.Syscalls) != len(decoded.Spec.Syscalls) {
		t.Errorf("Localhost has %d rules, SPO has %d", len(local.Syscalls), len(decoded.Spec.Syscalls))
	}
}

func TestGenerateRemediationClosesClone3AndCapabilityEquivalents(t *testing.T) {
	report := FindingReport{PostureRevision: "v1", Tier: "restricted", ExpectationViolations: []Finding{
		{Kind: ExpectationViolation, PostureRevision: "v1", Tier: "restricted", Family: "clone", ProbeID: "clone.flags.newuser", Verdict: "permitted"},
		{Kind: ExpectationViolation, PostureRevision: "v1", Tier: "restricted", Family: "capability", ProbeID: "capability.sys_time", Verdict: "permitted"},
		{Kind: ExpectationViolation, PostureRevision: "v1", Tier: "restricted", Family: "capability", ProbeID: "capability.sys_boot", Verdict: "permitted"},
		{Kind: ExpectationViolation, PostureRevision: "v1", Tier: "restricted", Family: "capability", ProbeID: "capability.sys_module", Verdict: "permitted"},
		{Kind: ExpectationViolation, PostureRevision: "v1", Tier: "restricted", Family: "capability", ProbeID: "capability.sys_rawio", Verdict: "permitted"},
		{Kind: ExpectationViolation, PostureRevision: "v1", Tier: "restricted", Family: "capability", ProbeID: "capability.sys_ptrace", Verdict: "permitted"},
	}}
	remediation, err := GenerateRemediation(report, runtimeDefault())
	if err != nil {
		t.Fatal(err)
	}
	rules := map[string]SeccompRule{}
	for _, closure := range remediation.Closures {
		rules[closure.ProbeID] = closure.Rule
	}
	if clone3, ok := rules["clone3.user_namespace_bypass"]; !ok || clone3.ErrnoRet == nil || *clone3.ErrnoRet != 38 {
		t.Errorf("clone3 closure = %#v, want ENOSYS", clone3)
	}
	for probe, want := range map[string][]string{
		"capability.sys_time":   {"settimeofday", "clock_settime", "clock_adjtime", "adjtimex"},
		"capability.sys_boot":   {"reboot", "kexec_load", "kexec_file_load"},
		"capability.sys_module": {"finit_module", "init_module", "delete_module"},
		"capability.sys_rawio":  {"iopl", "ioperm"},
		"capability.sys_ptrace": {"process_vm_readv", "process_vm_writev", "ptrace"},
	} {
		got := strings.Join(rules[probe].Names, ",")
		for _, syscall := range want {
			if !strings.Contains(got, syscall) {
				t.Errorf("%s rule %q lacks %q", probe, got, syscall)
			}
		}
	}
}

func TestGenerateRemediationReportsPointerBackedProbes(t *testing.T) {
	report := FindingReport{PostureRevision: "v1", Tier: "baseline", ExpectationViolations: []Finding{
		{Kind: ExpectationViolation, PostureRevision: "v1", Tier: "baseline", Family: "path", ProbeID: "path.masked.proc_kcore", Verdict: "permitted"},
		{Kind: ExpectationViolation, PostureRevision: "v1", Tier: "baseline", Family: "device", ProbeID: "device.open.mem", Verdict: "permitted"},
		{Kind: ExpectationViolation, PostureRevision: "v1", Tier: "baseline", Family: "mount", ProbeID: "mount.fs.proc", Verdict: "permitted"},
	}}
	remediation, err := GenerateRemediation(report, runtimeDefault())
	if err != nil {
		t.Fatal(err)
	}
	if len(remediation.Closures) != 0 || len(remediation.NotClosable) != 3 {
		t.Fatalf("closures/not closable = %d/%d", len(remediation.Closures), len(remediation.NotClosable))
	}
	for _, item := range remediation.NotClosable {
		if !strings.Contains(item.Reason, "pointer") {
			t.Errorf("reason = %q, want pointer limitation", item.Reason)
		}
	}
}

func TestGenerateRemediationRejectsMixedProvenance(t *testing.T) {
	report := FindingReport{PostureRevision: "v1", Tier: "baseline", ExpectationViolations: []Finding{{Kind: ExpectationViolation, PostureRevision: "v2", Tier: "baseline", Family: "mount", ProbeID: "mount.reach", Verdict: "permitted"}}}
	if _, err := GenerateRemediation(report, runtimeDefault()); err == nil {
		t.Fatal("GenerateRemediation() succeeded with a mismatched posture revision")
	}
}

func TestGenerateRemediationRequiresRuntimeDefault(t *testing.T) {
	report := FindingReport{PostureRevision: "v1", Tier: "baseline"}
	if _, err := GenerateRemediation(report, LocalhostProfile{}); err == nil {
		t.Fatal("GenerateRemediation() succeeded without a RuntimeDefault profile")
	}
}
