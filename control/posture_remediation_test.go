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

// runtimeDefault is the relevant excerpt of Moby's published RuntimeDefault
// profile: default errno 1, its architecture map, capability gate, and the
// existing socket allow condition. These are the fields a toy allowlist loses.
func runtimeDefault() RuntimeDefaultProfile {
	errnoRet := uint64(1)
	return RuntimeDefaultProfile{
		DefaultAction:   "SCMP_ACT_ERRNO",
		DefaultErrnoRet: &errnoRet,
		ArchMap:         []ArchMap{{Architecture: "SCMP_ARCH_X86_64", SubArchitectures: []string{"SCMP_ARCH_X86", "SCMP_ARCH_X32"}}},
		Syscalls: []RuntimeSeccompRule{
			{Names: []string{"read", "write", "close", "futex", "socket"}, Action: "SCMP_ACT_ALLOW"},
			{Names: []string{"process_vm_readv", "process_vm_writev", "ptrace"}, Action: "SCMP_ACT_ALLOW", Includes: &SeccompFilter{MinKernel: "4.8"}},
			{Names: []string{"clone", "clone3", "unshare"}, Action: "SCMP_ACT_ALLOW", Includes: &SeccompFilter{Caps: []string{"CAP_SYS_ADMIN"}}},
			{Names: []string{"clone"}, Action: "SCMP_ACT_ALLOW", Args: []SeccompArgument{{Index: 0, Op: "SCMP_CMP_MASKED_EQ", Value: 2114060288}}, Excludes: &SeccompFilter{Caps: []string{"CAP_SYS_ADMIN"}}},
		},
	}
}

func remediationTarget() RemediationTarget {
	return RemediationTarget{
		RuntimeArchitecture: "amd64",
		OCIArchitecture:     "SCMP_ARCH_X86_64",
		Capabilities:        []string{"CAP_SYS_ADMIN"},
		Kernel:              "6.8.0",
	}
}

func TestGenerateRemediationUsesArgumentRulesAndSPO(t *testing.T) {
	report := FindingReport{PostureRevision: "v1", Tier: "untrusted-multi-tenant", ExpectationViolations: []Finding{
		expectation("socket.family.af_alg"), expectation("netlink.protocol.crypto"), expectation("unshare.flags.newuser"), expectation("io_uring.setup"),
	}}
	remediation, err := GenerateRemediation(report, runtimeDefault(), remediationTarget())
	if err != nil {
		t.Fatalf("GenerateRemediation() error = %v", err)
	}
	if remediation.SPO.Kind != "SeccompProfile" || !strings.HasPrefix(remediation.SPO.Metadata.Name, "caliper-v1-untrusted-multi-tenant-") {
		t.Fatalf("SPO = %#v", remediation.SPO)
	}
	if len(remediation.Closures) != 4 || len(remediation.NotClosable) != 1 || remediation.NotClosable[0].ProbeID != "io_uring.setup" {
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
	if decoded.Spec.DefaultErrnoRet == nil || *decoded.Spec.DefaultErrnoRet != 1 || len(decoded.Spec.Architectures) != 1 {
		t.Errorf("SPO did not retain supported RuntimeDefault settings: %#v", decoded.Spec)
	}
	foundRuntimeAllowlist := false
	var socketRules []SeccompRule
	for _, rule := range decoded.Spec.Syscalls {
		if rule.Action == "SCMP_ACT_ALLOW" && strings.Join(rule.Names, ",") == "read,write,close,futex" {
			foundRuntimeAllowlist = true
		}
		if rule.Action == "SCMP_ACT_ALLOW" && len(rule.Names) == 1 && rule.Names[0] == "socket" {
			socketRules = append(socketRules, rule)
		}
	}
	if !foundRuntimeAllowlist {
		t.Errorf("SPO did not retain the RuntimeDefault allowlist: %#v", decoded.Spec.Syscalls)
	}
	hasMaskedAFALGExclusion := false
	for _, socketRule := range socketRules {
		for _, arg := range socketRule.Args {
			hasMaskedAFALGExclusion = hasMaskedAFALGExclusion || (arg.Index == 0 && arg.Op == "SCMP_CMP_MASKED_EQ" && arg.Value == 0xffffffff && arg.ValueTwo != nil && *arg.ValueTwo != 38)
		}
	}
	if !hasMaskedAFALGExclusion {
		t.Errorf("socket rules = %#v, want masked RuntimeDefault socket allows excluding AF_ALG", socketRules)
	}
	for _, rule := range decoded.Spec.Syscalls {
		if rule.Action == "SCMP_ACT_ERRNO" && len(rule.Names) == 1 && rule.Names[0] == "socket" {
			t.Error("AF_ALG must rewrite the existing socket allow rule, not add an ERRNO rule")
		}
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
	if local.DefaultErrnoRet == nil || *local.DefaultErrnoRet != 1 || len(local.Architectures) != 1 {
		t.Errorf("Localhost did not retain supported RuntimeDefault settings: %#v", local)
	}
	if len(local.Syscalls) != len(decoded.Spec.Syscalls) {
		t.Errorf("Localhost has %d rules, SPO has %d", len(local.Syscalls), len(decoded.Spec.Syscalls))
	}
}

func TestGenerateRemediationRestrictsCloneAndUnshareWithoutDeletingThem(t *testing.T) {
	report := FindingReport{PostureRevision: "v1", Tier: "untrusted-multi-tenant", ExpectationViolations: []Finding{
		expectation("clone.flags.newuser"), expectation("unshare.flags.newuser"),
	}}
	remediation, err := GenerateRemediation(report, runtimeDefault(), remediationTarget())
	if err != nil {
		t.Fatal(err)
	}
	for _, syscall := range []string{"clone", "unshare"} {
		found := false
		for _, rule := range remediation.Localhost.Syscalls {
			if rule.Action != "SCMP_ACT_ALLOW" || len(rule.Names) != 1 || rule.Names[0] != syscall {
				continue
			}
			for _, arg := range rule.Args {
				if arg.Op == "SCMP_CMP_MASKED_EQ" && arg.Value == 0x10000000 && arg.ValueTwo != nil && *arg.ValueTwo == 0 {
					found = true
				}
			}
		}
		if !found {
			t.Errorf("%s no longer has a RuntimeDefault allow rule excluding CLONE_NEWUSER", syscall)
		}
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
	remediation, err := GenerateRemediation(report, runtimeDefault(), remediationTarget())
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
		"capability.sys_ptrace": {"process_vm_readv", "process_vm_writev", "ptrace"},
	} {
		got := strings.Join(rules[probe].Names, ",")
		for _, syscall := range want {
			if !strings.Contains(got, syscall) {
				t.Errorf("%s rule %q lacks %q", probe, got, syscall)
			}
		}
	}
	if len(remediation.NotClosable) != 4 {
		t.Fatalf("not closable = %#v", remediation.NotClosable)
	}
}

func TestGenerateRemediationReportsPointerBackedProbes(t *testing.T) {
	report := FindingReport{PostureRevision: "v1", Tier: "baseline", ExpectationViolations: []Finding{
		{Kind: ExpectationViolation, PostureRevision: "v1", Tier: "baseline", Family: "path", ProbeID: "path.masked.proc_kcore", Verdict: "permitted"},
		{Kind: ExpectationViolation, PostureRevision: "v1", Tier: "baseline", Family: "device", ProbeID: "device.open.mem", Verdict: "permitted"},
		{Kind: ExpectationViolation, PostureRevision: "v1", Tier: "baseline", Family: "mount", ProbeID: "mount.fs.proc", Verdict: "permitted"},
	}}
	remediation, err := GenerateRemediation(report, runtimeDefault(), remediationTarget())
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
	if _, err := GenerateRemediation(report, runtimeDefault(), remediationTarget()); err == nil {
		t.Fatal("GenerateRemediation() succeeded with a mismatched posture revision")
	}
}

func TestGenerateRemediationRequiresRuntimeDefault(t *testing.T) {
	report := FindingReport{PostureRevision: "v1", Tier: "baseline"}
	if _, err := GenerateRemediation(report, RuntimeDefaultProfile{}, remediationTarget()); err == nil {
		t.Fatal("GenerateRemediation() succeeded without a RuntimeDefault profile")
	}
}

func TestGenerateRemediationRejectsPermissiveDefaultAndWrongKind(t *testing.T) {
	report := FindingReport{PostureRevision: "v1", Tier: "baseline"}
	permissive := runtimeDefault()
	permissive.DefaultAction = "SCMP_ACT_ALLOW"
	if _, err := GenerateRemediation(report, permissive, remediationTarget()); err == nil {
		t.Fatal("GenerateRemediation() accepted SCMP_ACT_ALLOW")
	}
	report.ExpectationViolations = []Finding{{Kind: ClaimViolation, PostureRevision: "v1", Tier: "baseline", Family: "x", ProbeID: "x", Verdict: "permitted"}}
	if _, err := GenerateRemediation(report, runtimeDefault(), remediationTarget()); err == nil {
		t.Fatal("GenerateRemediation() accepted a claim violation as policy input")
	}
}

func TestGenerateRemediationKeepsOtherNetlinkProtocols(t *testing.T) {
	report := FindingReport{PostureRevision: "v1", Tier: "untrusted-multi-tenant", ExpectationViolations: []Finding{
		expectation("netlink.protocol.crypto"),
	}}
	remediation, err := GenerateRemediation(report, runtimeDefault(), remediationTarget())
	if err != nil {
		t.Fatal(err)
	}
	var route, crypto, genericNetlink bool
	for _, rule := range remediation.Localhost.Syscalls {
		if rule.Action != "SCMP_ACT_ALLOW" || len(rule.Names) != 1 || rule.Names[0] != "socket" {
			continue
		}
		route = route || isNetlinkProtocol(rule, 0)
		crypto = crypto || isNetlinkProtocol(rule, 21)
		genericNetlink = genericNetlink || isMaskedSocketFamily(rule, 16)
	}
	if !route || crypto || genericNetlink {
		t.Fatalf("netlink allow rules route=%t crypto=%t generic=%t: %#v", route, crypto, genericNetlink, remediation.Localhost.Syscalls)
	}
}

func TestGenerateRemediationNarrowsMobySocketNEAllow(t *testing.T) {
	// These are the socket and architecture-gated rules in Moby's shipped
	// default.json: socket permits every family except AF_VSOCK (40), while
	// arch_prctl is gated by the runtime spelling "amd64".
	const mobyDefault = `{
  "defaultAction":"SCMP_ACT_ERRNO",
  "syscalls":[
    {"names":["socket"],"action":"SCMP_ACT_ALLOW","args":[{"index":0,"value":40,"op":"SCMP_CMP_NE"}]},
    {"names":["arch_prctl"],"action":"SCMP_ACT_ALLOW","includes":{"arches":["amd64","x32"]}}
  ]
}`
	var runtime RuntimeDefaultProfile
	if err := json.Unmarshal([]byte(mobyDefault), &runtime); err != nil {
		t.Fatal(err)
	}
	report := FindingReport{PostureRevision: "v1", Tier: "baseline", ExpectationViolations: []Finding{
		{Kind: ExpectationViolation, PostureRevision: "v1", Tier: "baseline", Family: "netlink", ProbeID: "netlink.protocol.netfilter", Verdict: "permitted"},
	}}
	remediation, err := GenerateRemediation(report, runtime, remediationTarget())
	if err != nil {
		t.Fatal(err)
	}
	if !hasAllowedSyscall(remediation.Localhost.Syscalls, "arch_prctl") {
		t.Fatalf("Moby amd64 gate dropped arch_prctl: %#v", remediation.Localhost.Syscalls)
	}
	var route, netfilter, vsock bool
	for _, rule := range remediation.Localhost.Syscalls {
		route = route || isNetlinkProtocol(rule, 0)
		netfilter = netfilter || isNetlinkProtocol(rule, 12)
		vsock = vsock || isMaskedSocketFamily(rule, 40)
	}
	if !route || netfilter || vsock {
		t.Fatalf("Moby socket rewrite route=%t netfilter=%t vsock=%t", route, netfilter, vsock)
	}
}

func TestResolveRuntimeRulesExcludesOnAnyMatchingPredicate(t *testing.T) {
	rules := []RuntimeSeccompRule{
		{Names: []string{"cap-rule"}, Action: "SCMP_ACT_ALLOW", Excludes: &SeccompFilter{Caps: []string{"CAP_A", "CAP_B"}}},
		{Names: []string{"arch-rule"}, Action: "SCMP_ACT_ALLOW", Excludes: &SeccompFilter{Arches: []string{"amd64", "s390x"}}},
		{Names: []string{"remaining"}, Action: "SCMP_ACT_ALLOW", Excludes: &SeccompFilter{Caps: []string{"CAP_OTHER"}}},
	}
	target := remediationTarget()
	target.Capabilities = []string{"CAP_A"}
	resolved := resolveRuntimeRules(rules, target)
	if len(resolved) != 1 || resolved[0].Names[0] != "remaining" {
		t.Fatalf("resolved rules = %#v", resolved)
	}
}

func TestRuntimeProfileJSONRetainsAndResolvesGates(t *testing.T) {
	const runtimeJSON = `{
  "defaultAction":"SCMP_ACT_ERRNO",
  "syscalls":[
    {"names":["gated"],"action":"SCMP_ACT_ALLOW","includes":{"caps":["CAP_A"]}},
    {"names":["excluded"],"action":"SCMP_ACT_ALLOW","excludes":{"arches":["amd64"]}}
  ]
}`
	var runtime RuntimeDefaultProfile
	if err := json.Unmarshal([]byte(runtimeJSON), &runtime); err != nil {
		t.Fatal(err)
	}
	if runtime.Syscalls[0].Includes == nil || runtime.Syscalls[1].Excludes == nil {
		t.Fatalf("runtime gates lost while decoding: %#v", runtime)
	}
	target := remediationTarget()
	target.Capabilities = nil
	if resolved := resolveRuntimeRules(runtime.Syscalls, target); len(resolved) != 0 {
		t.Fatalf("gated rules leaked into output: %#v", resolved)
	}
	target.Capabilities = []string{"CAP_A"}
	resolved := resolveRuntimeRules(runtime.Syscalls[:1], target)
	encoded, err := json.Marshal(resolved)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "includes") || strings.Contains(string(encoded), "excludes") {
		t.Fatalf("rendered OCI rules retain runtime-only fields: %s", encoded)
	}
}

func TestGenerateRemediationSeparatesRuntimeAndOCIArchitectures(t *testing.T) {
	runtime := runtimeDefault()
	runtime.Syscalls = append(runtime.Syscalls, RuntimeSeccompRule{
		Names: []string{"arch_prctl"}, Action: "SCMP_ACT_ALLOW", Includes: &SeccompFilter{Arches: []string{"amd64"}},
	})
	remediation, err := GenerateRemediation(FindingReport{PostureRevision: "v1", Tier: "baseline"}, runtime, remediationTarget())
	if err != nil {
		t.Fatal(err)
	}
	if got := remediation.Localhost.Architectures; len(got) != 1 || got[0] != "SCMP_ARCH_X86_64" {
		t.Fatalf("OCI architectures = %#v", got)
	}
	if !hasAllowedSyscall(remediation.Localhost.Syscalls, "arch_prctl") {
		t.Fatalf("runtime amd64 gate dropped arch_prctl: %#v", remediation.Localhost.Syscalls)
	}
}

func TestGenerateRemediationDoesNotClaimUnchangedClosure(t *testing.T) {
	runtime := runtimeDefault()
	runtime.Syscalls = []RuntimeSeccompRule{{Names: []string{"read"}, Action: "SCMP_ACT_ALLOW"}}
	remediation, err := GenerateRemediation(FindingReport{PostureRevision: "v1", Tier: "baseline", ExpectationViolations: []Finding{
		{Kind: ExpectationViolation, PostureRevision: "v1", Tier: "baseline", Family: "netlink", ProbeID: "netlink.protocol.netfilter", Verdict: "permitted"},
	}}, runtime, remediationTarget())
	if err != nil {
		t.Fatal(err)
	}
	if len(remediation.Closures) != 0 || len(remediation.NotClosable) != 1 {
		t.Fatalf("closures=%#v not_closable=%#v", remediation.Closures, remediation.NotClosable)
	}
}

func TestGenerateRemediationNamesFinalPolicy(t *testing.T) {
	runtime := runtimeDefault()
	first, err := GenerateRemediation(FindingReport{PostureRevision: "v1", Tier: "t", ExpectationViolations: []Finding{
		{Kind: ExpectationViolation, PostureRevision: "v1", Tier: "t", Family: "socket", ProbeID: "socket.family.af_alg", Verdict: "permitted"},
	}}, runtime, remediationTarget())
	if err != nil {
		t.Fatal(err)
	}
	second, err := GenerateRemediation(FindingReport{PostureRevision: "v1", Tier: "t", ExpectationViolations: []Finding{
		{Kind: ExpectationViolation, PostureRevision: "v1", Tier: "t", Family: "netlink", ProbeID: "netlink.protocol.netfilter", Verdict: "permitted"},
	}}, runtime, remediationTarget())
	if err != nil {
		t.Fatal(err)
	}
	if first.SPO.Metadata.Name == second.SPO.Metadata.Name {
		t.Fatalf("different closures share profile name %q", first.SPO.Metadata.Name)
	}
}

func hasAllowedSyscall(rules []SeccompRule, name string) bool {
	for _, rule := range rules {
		if rule.Action == "SCMP_ACT_ALLOW" && contains(rule.Names, name) {
			return true
		}
	}
	return false
}
