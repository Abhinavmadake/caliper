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
	seccompErrno = "SCMP_ACT_ERRNO"
)

// Remediation is the minimal seccomp policy derived from a finding report.
// SPO is the primary distribution format: unlike a Localhost profile, the
// operator distributes it to every node. Both rendered outputs retain the
// supplied RuntimeDefault policy and add only the measured closures.
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
	Names    []string          `yaml:"names" json:"names"`
	Action   string            `yaml:"action" json:"action"`
	ErrnoRet *uint64           `yaml:"errnoRet,omitempty" json:"errnoRet,omitempty"`
	Args     []SeccompArgument `yaml:"args,omitempty" json:"args,omitempty"`
}

type SeccompArgument struct {
	Index    uint64  `yaml:"index" json:"index"`
	Op       string  `yaml:"op" json:"op"`
	Value    uint64  `yaml:"value" json:"value"`
	ValueTwo *uint64 `yaml:"valueTwo,omitempty" json:"valueTwo,omitempty"`
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
// stated posture revision. runtimeDefault is the actual profile selected by
// the target runtime, obtained from that runtime rather than guessed from a
// Kubernetes RuntimeDefault declaration. Claim violations and undeclared
// exposures have no independent posture authority and are intentionally not
// turned into policy.
func GenerateRemediation(report FindingReport, runtimeDefault LocalhostProfile) (Remediation, error) {
	if report.PostureRevision == "" || report.Tier == "" {
		return Remediation{}, fmt.Errorf("finding report posture_revision and tier are required")
	}
	if runtimeDefault.DefaultAction == "" || len(runtimeDefault.Syscalls) == 0 {
		return Remediation{}, fmt.Errorf("runtime default profile requires defaultAction and an allowlist")
	}

	name := "caliper-" + safeProfileName(report.PostureRevision)
	remediation := Remediation{
		PostureRevision: report.PostureRevision,
		Tier:            report.Tier,
		SPO: SPOProfile{
			APIVersion: "security-profiles-operator.x-k8s.io/v1beta1",
			Kind:       "SeccompProfile",
			Metadata:   ObjectMeta{Name: name},
			Spec: SeccompSpec{
				DefaultAction: runtimeDefault.DefaultAction,
				Syscalls:      append([]SeccompRule(nil), runtimeDefault.Syscalls...),
			},
		},
		Localhost: LocalhostProfile{
			DefaultAction: runtimeDefault.DefaultAction,
			Syscalls:      append([]SeccompRule(nil), runtimeDefault.Syscalls...),
		},
		Closures:    []RemediationAction{},
		NotClosable: []NotClosable{},
	}

	seen := map[string]struct{}{}
	userNamespace := false
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
		if finding.ProbeID == "unshare.flags.newuser" || finding.ProbeID == "clone.flags.newuser" {
			userNamespace = true
		}

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
	if userNamespace {
		enosys := uint64(38)
		clone3 := SeccompRule{Names: []string{"clone3"}, Action: seccompErrno, ErrnoRet: &enosys}
		remediation.Closures = append(remediation.Closures, RemediationAction{ProbeID: "clone3.user_namespace_bypass", Rule: clone3})
		remediation.SPO.Spec.Syscalls = append(remediation.SPO.Spec.Syscalls, clone3)
		remediation.Localhost.Syscalls = append(remediation.Localhost.Syscalls, clone3)
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

// RenderLocalhost renders the secondary OCI Localhost seccomp profile.
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
		return cloneNamespaceRule("unshare"), true
	case "clone.flags.newuser":
		return cloneNamespaceRule("clone"), true
	case "capability.sys_time":
		return deny("settimeofday", "clock_settime", "clock_adjtime", "adjtimex"), true
	case "capability.sys_boot":
		return deny("reboot", "kexec_load", "kexec_file_load"), true
	case "capability.sys_module":
		return deny("finit_module", "init_module", "delete_module"), true
	case "capability.sys_rawio":
		return deny("iopl", "ioperm"), true
	case "capability.sys_ptrace":
		return deny("process_vm_readv", "process_vm_writev", "ptrace"), true
	}
	if strings.HasPrefix(id, "io_uring.") {
		// io_uring operation codes are written through pointers and are not
		// visible to seccomp-BPF. The posture prohibits this entire family.
		return deny("io_uring_setup", "io_uring_enter", "io_uring_register"), true
	}
	return SeccompRule{}, false
}

func cloneNamespaceRule(syscall string) SeccompRule {
	cloneNewUser := uint64(0x10000000)
	return SeccompRule{Names: []string{syscall}, Action: seccompErrno, Args: []SeccompArgument{{
		Index: 0, Op: "SCMP_CMP_MASKED_EQ", Value: cloneNewUser, ValueTwo: &cloneNewUser,
	}}}
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
