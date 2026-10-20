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

func TestGenerateRemediationUsesArgumentRulesAndSPO(t *testing.T) {
	report := FindingReport{PostureRevision: "v1", Tier: "untrusted-multi-tenant", ExpectationViolations: []Finding{
		expectation("socket.family.af_alg"), expectation("netlink.protocol.crypto"), expectation("unshare.flags.newuser"), expectation("io_uring.setup"),
	}}
	remediation, err := GenerateRemediation(report)
	if err != nil {
		t.Fatalf("GenerateRemediation() error = %v", err)
	}
	if remediation.SPO.Kind != "SeccompProfile" || remediation.SPO.Metadata.Name != "caliper-v1" {
		t.Fatalf("SPO = %#v", remediation.SPO)
	}
	if len(remediation.Closures) != 4 || len(remediation.NotClosable) != 0 {
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
			unshare = closure.Rule.Args[0].Op == "SCMP_CMP_MASKED_EQ" && closure.Rule.Args[0].Value == 0x10000000
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
	if decoded.Spec.DefaultAction != seccompAllow {
		t.Errorf("SPO default action = %q", decoded.Spec.DefaultAction)
	}
	localhost, err := remediation.RenderLocalhost()
	if err != nil {
		t.Fatal(err)
	}
	var local LocalhostProfile
	if err := json.Unmarshal(localhost, &local); err != nil {
		t.Fatalf("parse Localhost JSON: %v", err)
	}
	if len(local.Syscalls) != len(decoded.Spec.Syscalls) {
		t.Errorf("Localhost has %d rules, SPO has %d", len(local.Syscalls), len(decoded.Spec.Syscalls))
	}
}

func TestGenerateRemediationReportsPointerBackedProbes(t *testing.T) {
	report := FindingReport{PostureRevision: "v1", Tier: "baseline", ExpectationViolations: []Finding{
		{Kind: ExpectationViolation, PostureRevision: "v1", Tier: "baseline", Family: "path", ProbeID: "path.masked.proc_kcore", Verdict: "permitted"},
		{Kind: ExpectationViolation, PostureRevision: "v1", Tier: "baseline", Family: "device", ProbeID: "device.open.mem", Verdict: "permitted"},
		{Kind: ExpectationViolation, PostureRevision: "v1", Tier: "baseline", Family: "mount", ProbeID: "mount.fs.proc", Verdict: "permitted"},
	}}
	remediation, err := GenerateRemediation(report)
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
	if _, err := GenerateRemediation(report); err == nil {
		t.Fatal("GenerateRemediation() succeeded with a mismatched posture revision")
	}
}
