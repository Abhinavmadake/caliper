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
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	seccompAllow = "SCMP_ACT_ALLOW"
	seccompErrno = "SCMP_ACT_ERRNO"
)

// Remediation is the minimal seccomp policy derived from a finding report.
// SPO is the primary distribution format: unlike a Localhost profile, the
// operator distributes it to every node. Localhost is included for runtimes
// that consume an OCI seccomp JSON document directly.
type Remediation struct {
	PostureRevision string              `json:"posture_revision"`
	Tier            string              `json:"tier"`
	SPO             SPOProfile          `json:"spo"`
	Localhost       LocalhostProfile    `json:"localhost"`
	Closures        []RemediationAction `json:"closures"`
	NotClosable     []NotClosable       `json:"not_closable"`
}

// SPOProfile is a Security Profiles Operator SeccompProfile custom resource.
type SPOProfile struct {
	APIVersion string      `yaml:"apiVersion" json:"apiVersion"`
	Kind       string      `yaml:"kind" json:"kind"`
	Metadata   ObjectMeta  `yaml:"metadata" json:"metadata"`
	Spec       SeccompSpec `yaml:"spec" json:"spec"`
}

type ObjectMeta struct {
	Name string `yaml:"name" json:"name"`
}

// LocalhostProfile has the OCI seccomp profile shape used by Kubernetes'
// Localhost seccompProfile type.
type LocalhostProfile struct {
	DefaultAction string        `json:"defaultAction"`
	Syscalls      []SeccompRule `json:"syscalls"`
}

type SeccompSpec struct {
	DefaultAction string        `yaml:"defaultAction" json:"defaultAction"`
	Syscalls      []SeccompRule `yaml:"syscalls" json:"syscalls"`
}

type SeccompRule struct {
	Names  []string          `yaml:"names" json:"names"`
	Action string            `yaml:"action" json:"action"`
	Args   []SeccompArgument `yaml:"args,omitempty" json:"args,omitempty"`
}

type SeccompArgument struct {
	Index uint64 `yaml:"index" json:"index"`
	Op    string `yaml:"op" json:"op"`
	Value uint64 `yaml:"value" json:"value"`
}

// RemediationAction connects a generated rule to the measured probe which
// requires it. This is deliberately retained outside the rendered profile so
// applying either profile does not depend on CALIPER-specific extensions.
type RemediationAction struct {
	ProbeID string      `json:"probe_id"`
	Rule    SeccompRule `json:"rule"`
}

// NotClosable explains a permitted posture assertion that seccomp cannot
// discriminate without dereferencing a user pointer (for example a pathname,
// mount filesystem type, device, or an io_uring operation opcode).
type NotClosable struct {
	ProbeID string `json:"probe_id"`
	Reason  string `json:"reason"`
}

// GenerateRemediation emits a policy only for expectation violations from the
// stated posture revision. Claim violations and undeclared exposures have no
// independent posture authority and are intentionally not turned into policy.
func GenerateRemediation(report FindingReport) (Remediation, error) {
	if report.PostureRevision == "" || report.Tier == "" {
		return Remediation{}, fmt.Errorf("finding report posture_revision and tier are required")
	}

	name := "caliper-" + safeProfileName(report.PostureRevision)
	remediation := Remediation{
		PostureRevision: report.PostureRevision,
		Tier:            report.Tier,
		SPO: SPOProfile{
			APIVersion: "security-profiles-operator.x-k8s.io/v1beta1",
			Kind:       "SeccompProfile",
			Metadata:   ObjectMeta{Name: name},
			Spec:       SeccompSpec{DefaultAction: seccompAllow, Syscalls: []SeccompRule{}},
		},
		Localhost:   LocalhostProfile{DefaultAction: seccompAllow, Syscalls: []SeccompRule{}},
		Closures:    []RemediationAction{},
		NotClosable: []NotClosable{},
	}

	seen := map[string]struct{}{}
	for _, finding := range report.ExpectationViolations {
		if err := finding.Validate(); err != nil {
			return Remediation{}, fmt.Errorf("invalid expectation finding: %w", err)
		}
		if finding.PostureRevision != report.PostureRevision || finding.Tier != report.Tier {
			return Remediation{}, fmt.Errorf("finding %q does not match report posture revision and tier", finding.ProbeID)
		}
		if _, duplicate := seen[finding.ProbeID]; duplicate {
			continue
		}
		seen[finding.ProbeID] = struct{}{}

		rule, closable := remediationRule(finding.ProbeID)
		if !closable {
			remediation.NotClosable = append(remediation.NotClosable, NotClosable{
				ProbeID: finding.ProbeID,
				Reason:  notClosableReason(finding.ProbeID),
			})
			continue
		}
		remediation.Closures = append(remediation.Closures, RemediationAction{ProbeID: finding.ProbeID, Rule: rule})
		remediation.SPO.Spec.Syscalls = append(remediation.SPO.Spec.Syscalls, rule)
		remediation.Localhost.Syscalls = append(remediation.Localhost.Syscalls, rule)
	}
	sort.Slice(remediation.Closures, func(i, j int) bool { return remediation.Closures[i].ProbeID < remediation.Closures[j].ProbeID })
	sort.Slice(remediation.NotClosable, func(i, j int) bool { return remediation.NotClosable[i].ProbeID < remediation.NotClosable[j].ProbeID })
	sortRules(remediation.SPO.Spec.Syscalls)
	sortRules(remediation.Localhost.Syscalls)
	return remediation, nil
}

// RenderSPO renders the primary, cluster-distributable Security Profiles
// Operator custom resource.
func (r Remediation) RenderSPO() ([]byte, error) { return yaml.Marshal(r.SPO) }

// RenderLocalhost renders the secondary OCI seccomp profile.
func (r Remediation) RenderLocalhost() ([]byte, error) {
	return json.MarshalIndent(r.Localhost, "", "  ")
}

func remediationRule(id string) (SeccompRule, bool) {
	deny := func(names ...string) SeccompRule { return SeccompRule{Names: names, Action: seccompErrno} }
	argument := func(names []string, args ...SeccompArgument) SeccompRule {
		return SeccompRule{Names: names, Action: seccompErrno, Args: args}
	}
	switch id {
	case "socket.family.af_alg":
		return argument([]string{"socket"}, SeccompArgument{Index: 0, Op: "SCMP_CMP_EQ", Value: 38}), true
	case "netlink.protocol.netfilter":
		return netlinkRule(12), true
	case "netlink.protocol.xfrm":
		return netlinkRule(6), true
	case "netlink.protocol.crypto":
		return netlinkRule(21), true
	case "netlink.protocol.rdma":
		return netlinkRule(20), true
	case "unshare.flags.newuser":
		return argument([]string{"unshare"}, SeccompArgument{Index: 0, Op: "SCMP_CMP_MASKED_EQ", Value: 0x10000000}), true
	case "clone.flags.newuser":
		return argument([]string{"clone"}, SeccompArgument{Index: 0, Op: "SCMP_CMP_MASKED_EQ", Value: 0x10000000}), true
	case "capability.sys_time":
		return deny("settimeofday"), true
	case "capability.sys_boot":
		return deny("reboot"), true
	case "capability.sys_module":
		return deny("finit_module"), true
	case "capability.sys_rawio":
		return deny("iopl"), true
	case "capability.sys_ptrace":
		return deny("process_vm_readv"), true
	}
	if strings.HasPrefix(id, "io_uring.") {
		// io_uring operation codes are written through pointers and are not
		// visible to seccomp-BPF. The posture prohibits this entire family.
		return deny("io_uring_setup", "io_uring_enter", "io_uring_register"), true
	}
	return SeccompRule{}, false
}

func netlinkRule(protocol uint64) SeccompRule {
	return SeccompRule{Names: []string{"socket"}, Action: seccompErrno, Args: []SeccompArgument{
		{Index: 0, Op: "SCMP_CMP_EQ", Value: 16}, // AF_NETLINK
		{Index: 2, Op: "SCMP_CMP_EQ", Value: protocol},
	}}
}

func notClosableReason(id string) string {
	switch {
	case strings.HasPrefix(id, "path."):
		return "the pathname is a pointer argument; seccomp-BPF cannot inspect it without blocking all pathname opens"
	case strings.HasPrefix(id, "device."):
		return "the device pathname is a pointer argument; seccomp-BPF cannot distinguish it from other opens"
	case strings.HasPrefix(id, "mount."):
		return "the mount filesystem type is a pointer argument; seccomp-BPF cannot inspect it without blocking mount(2) entirely"
	default:
		return "no seccomp-BPF rule is defined for this probe; it remains a reported divergence"
	}
}

func safeProfileName(revision string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(revision) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

func sortRules(rules []SeccompRule) {
	sort.Slice(rules, func(i, j int) bool { return strings.Join(rules[i].Names, ",") < strings.Join(rules[j].Names, ",") })
}
