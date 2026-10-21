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
	"crypto/sha256"
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
	DefaultAction   string        `json:"defaultAction"`
	DefaultErrnoRet *uint64       `json:"defaultErrnoRet,omitempty"`
	Architectures   []string      `json:"architectures,omitempty"`
	ArchMap         []ArchMap     `json:"-"`
	Syscalls        []SeccompRule `json:"syscalls"`
}

type SeccompSpec struct {
	DefaultAction   string        `yaml:"defaultAction" json:"defaultAction"`
	DefaultErrnoRet *uint64       `yaml:"defaultErrnoRet,omitempty" json:"defaultErrnoRet,omitempty"`
	Architectures   []string      `yaml:"architectures,omitempty" json:"architectures,omitempty"`
	ArchMap         []ArchMap     `yaml:"-" json:"-"`
	Syscalls        []SeccompRule `yaml:"syscalls" json:"syscalls"`
}

type ArchMap struct {
	Architecture     string   `yaml:"architecture" json:"architecture"`
	SubArchitectures []string `yaml:"subArchitectures,omitempty" json:"subArchitectures,omitempty"`
}

type SeccompRule struct {
	Names    []string          `yaml:"names" json:"names"`
	Action   string            `yaml:"action" json:"action"`
	ErrnoRet *uint64           `yaml:"errnoRet,omitempty" json:"errnoRet,omitempty"`
	Args     []SeccompArgument `yaml:"args,omitempty" json:"args,omitempty"`
	Includes *SeccompFilter    `yaml:"-" json:"-"`
	Excludes *SeccompFilter    `yaml:"-" json:"-"`
	Comment  string            `yaml:"-" json:"-"`
}

// SeccompFilter is the capability, architecture, and kernel-version gate
// carried by a runtime's default profile.
type SeccompFilter struct {
	Caps      []string `yaml:"caps,omitempty" json:"caps,omitempty"`
	Arches    []string `yaml:"arches,omitempty" json:"arches,omitempty"`
	MinKernel string   `yaml:"minKernel,omitempty" json:"minKernel,omitempty"`
}

// RemediationTarget is the concrete runtime environment against which source
// profile gates are resolved before a portable OCI/SPO profile is emitted.
type RemediationTarget struct {
	Architecture string
	Capabilities []string
	Kernel       string
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
func GenerateRemediation(report FindingReport, runtimeDefault LocalhostProfile, target RemediationTarget) (Remediation, error) {
	if report.PostureRevision == "" || report.Tier == "" {
		return Remediation{}, fmt.Errorf("finding report posture_revision and tier are required")
	}
	if runtimeDefault.DefaultAction == "" || len(runtimeDefault.Syscalls) == 0 {
		return Remediation{}, fmt.Errorf("runtime default profile requires defaultAction and an allowlist")
	}
	if runtimeDefault.DefaultAction != seccompErrno {
		return Remediation{}, fmt.Errorf("runtime default action must be %s, got %q", seccompErrno, runtimeDefault.DefaultAction)
	}
	if target.Architecture == "" || target.Kernel == "" {
		return Remediation{}, fmt.Errorf("remediation target architecture and kernel are required")
	}
	runtimeRules := resolveRuntimeRules(runtimeDefault.Syscalls, target)

	name := remediationProfileName(report, runtimeRules, target)
	remediation := Remediation{
		PostureRevision: report.PostureRevision,
		Tier:            report.Tier,
		SPO: SPOProfile{
			APIVersion: "security-profiles-operator.x-k8s.io/v1beta1",
			Kind:       "SeccompProfile",
			Metadata:   ObjectMeta{Name: name},
			Spec: SeccompSpec{
				DefaultAction:   runtimeDefault.DefaultAction,
				DefaultErrnoRet: runtimeDefault.DefaultErrnoRet,
				Architectures:   []string{target.Architecture},
				Syscalls:        runtimeRules,
			},
		},
		Localhost: LocalhostProfile{
			DefaultAction:   runtimeDefault.DefaultAction,
			DefaultErrnoRet: runtimeDefault.DefaultErrnoRet,
			Architectures:   []string{target.Architecture},
			Syscalls:        cloneRules(runtimeRules),
		},
		Closures:    []RemediationAction{},
		NotClosable: []NotClosable{},
	}

	seen := map[string]struct{}{}
	userNamespace := false
	for _, finding := range report.ExpectationViolations {
		if finding.Kind != ExpectationViolation {
			return Remediation{}, fmt.Errorf("finding %q is not an expectation violation", finding.ProbeID)
		}
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
		remediation.SPO.Spec.Syscalls = applyClosure(remediation.SPO.Spec.Syscalls, rule)
		remediation.Localhost.Syscalls = applyClosure(remediation.Localhost.Syscalls, rule)
	}
	if userNamespace {
		enosys := uint64(38)
		clone3 := SeccompRule{Names: []string{"clone3"}, Action: seccompErrno, ErrnoRet: &enosys}
		remediation.Closures = append(remediation.Closures, RemediationAction{ProbeID: "clone3.user_namespace_bypass", Rule: clone3})
		remediation.SPO.Spec.Syscalls = append(applyClosure(remediation.SPO.Spec.Syscalls, clone3), clone3)
		remediation.Localhost.Syscalls = append(applyClosure(remediation.Localhost.Syscalls, clone3), clone3)
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

func cloneRules(rules []SeccompRule) []SeccompRule {
	copied := make([]SeccompRule, len(rules))
	for i, rule := range rules {
		copied[i] = rule
		copied[i].Names = append([]string(nil), rule.Names...)
		copied[i].Args = append([]SeccompArgument(nil), rule.Args...)
		if rule.Includes != nil {
			includes := *rule.Includes
			includes.Caps = append([]string(nil), rule.Includes.Caps...)
			includes.Arches = append([]string(nil), rule.Includes.Arches...)
			copied[i].Includes = &includes
		}
		if rule.Excludes != nil {
			excludes := *rule.Excludes
			excludes.Caps = append([]string(nil), rule.Excludes.Caps...)
			excludes.Arches = append([]string(nil), rule.Excludes.Arches...)
			copied[i].Excludes = &excludes
		}
	}
	return copied
}

func resolveRuntimeRules(rules []SeccompRule, target RemediationTarget) []SeccompRule {
	resolved := make([]SeccompRule, 0, len(rules))
	for _, rule := range rules {
		if !gateApplies(rule.Includes, target, true) || !gateApplies(rule.Excludes, target, false) {
			continue
		}
		rule.Includes, rule.Excludes, rule.Comment = nil, nil, ""
		resolved = append(resolved, rule)
	}
	return cloneRules(resolved)
}

func gateApplies(gate *SeccompFilter, target RemediationTarget, include bool) bool {
	if gate == nil {
		return true
	}
	match := true
	if len(gate.Arches) > 0 {
		match = contains(gate.Arches, target.Architecture)
	}
	if match && len(gate.Caps) > 0 {
		for _, cap := range gate.Caps {
			if !contains(target.Capabilities, cap) {
				match = false
			}
		}
	}
	if match && gate.MinKernel != "" {
		match = kernelAtLeast(target.Kernel, gate.MinKernel)
	}
	if include {
		return match
	}
	return !match
}

// applyClosure removes closed syscalls from RuntimeDefault's allowlist. For a
// socket-family closure it rewrites the existing socket ALLOW rule instead:
// a conditional ERRNO cannot override libseccomp's unconditional ALLOW.
func applyClosure(rules []SeccompRule, closure SeccompRule) []SeccompRule {
	if len(closure.Names) == 1 && closure.Names[0] == "socket" && len(closure.Args) > 0 {
		// libseccomp ORs comparisons on the same argument in a rule, so an
		// ERRNO exception (or stacked NE tests) cannot close an ALLOW rule.
		// Replace a broad socket allow with one masked-equality rule per known
		// family. The 32-bit mask prevents high register bits from bypassing a
		// family test. Do not add a socket allow if RuntimeDefault had none.
		return restrictSocketFamilies(rules, closure.Args[0].Value)
	}
	if len(closure.Names) == 1 && (closure.Names[0] == "clone" || closure.Names[0] == "unshare") && len(closure.Args) > 0 {
		name := closure.Names[0]
		rules = splitAllowedSyscall(rules, name)
		for i := range rules {
			if rules[i].Action == "SCMP_ACT_ALLOW" && len(rules[i].Names) == 1 && rules[i].Names[0] == name {
				if hasArgumentAt(rules[i], closure.Args[0].Index) {
					continue
				}
				zero := uint64(0)
				rules[i].Args = append(rules[i].Args, SeccompArgument{
					Index: closure.Args[0].Index, Op: "SCMP_CMP_MASKED_EQ", Value: closure.Args[0].Value, ValueTwo: &zero,
				})
			}
		}
		return rules
	}
	for i := range rules {
		if rules[i].Action != "SCMP_ACT_ALLOW" {
			continue
		}
		remaining := rules[i].Names[:0]
		for _, name := range rules[i].Names {
			if !contains(closure.Names, name) {
				remaining = append(remaining, name)
			}
		}
		rules[i].Names = remaining
	}
	filtered := rules[:0]
	for _, rule := range rules {
		if len(rule.Names) != 0 {
			filtered = append(filtered, rule)
		}
	}
	return filtered
}

func restrictSocketFamilies(rules []SeccompRule, deniedFamily uint64) []SeccompRule {
	rules = splitAllowedSyscall(rules, "socket")
	var rewritten bool
	var enumerated bool
	filtered := rules[:0]
	for _, rule := range rules {
		if rule.Action == "SCMP_ACT_ALLOW" && len(rule.Names) == 1 && rule.Names[0] == "socket" && len(rule.Args) == 0 {
			rewritten = true
			continue
		}
		if rule.Action == "SCMP_ACT_ALLOW" && len(rule.Names) == 1 && rule.Names[0] == "socket" && isMaskedSocketFamily(rule, deniedFamily) {
			enumerated = true
			continue
		}
		filtered = append(filtered, rule)
	}
	if !rewritten {
		if enumerated {
			return filtered
		}
		// The default either already denies socket or has a more-specific
		// condition. In either case, adding an allow would widen its baseline.
		return filtered
	}
	mask := uint64(0xffffffff)
	for _, family := range socketFamilies {
		if family == deniedFamily {
			continue
		}
		family := family
		filtered = append(filtered, SeccompRule{Names: []string{"socket"}, Action: "SCMP_ACT_ALLOW", Args: []SeccompArgument{{
			Index: 0, Op: "SCMP_CMP_MASKED_EQ", Value: mask, ValueTwo: &family,
		}}})
	}
	return filtered
}

func isMaskedSocketFamily(rule SeccompRule, family uint64) bool {
	return len(rule.Args) == 1 && rule.Args[0].Index == 0 && rule.Args[0].Op == "SCMP_CMP_MASKED_EQ" && rule.Args[0].Value == 0xffffffff && rule.Args[0].ValueTwo != nil && *rule.Args[0].ValueTwo == family
}

var socketFamilies = []uint64{
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
	31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45,
}

func hasArgumentAt(rule SeccompRule, index uint64) bool {
	for _, argument := range rule.Args {
		if argument.Index == index {
			return true
		}
	}
	return false
}

func kernelAtLeast(actual, minimum string) bool {
	parse := func(value string) []int {
		parts := strings.FieldsFunc(value, func(r rune) bool { return r == '.' || r == '-' })
		result := make([]int, len(parts))
		for i, part := range parts {
			fmt.Sscanf(part, "%d", &result[i])
		}
		return result
	}
	a, b := parse(actual), parse(minimum)
	for i := 0; i < len(a) || i < len(b); i++ {
		var av, bv int
		if i < len(a) {
			av = a[i]
		}
		if i < len(b) {
			bv = b[i]
		}
		if av != bv {
			return av > bv
		}
	}
	return true
}

func remediationProfileName(report FindingReport, rules []SeccompRule, target RemediationTarget) string {
	payload, _ := json.Marshal(struct {
		Target RemediationTarget
		Rules  []SeccompRule
	}{Target: target, Rules: rules})
	sum := sha256.Sum256(payload)
	return fmt.Sprintf("caliper-%s-%s-%x", safeProfileName(report.PostureRevision), safeProfileName(report.Tier), sum[:4])
}

// splitAllowedSyscall moves one syscall into its own copies of the matching
// ALLOW rules. Seccomp arguments apply to every name in a rule, so attaching a
// socket or clone constraint to a mixed rule would accidentally constrain
// unrelated calls such as read, close, or futex.
func splitAllowedSyscall(rules []SeccompRule, syscall string) []SeccompRule {
	var split []SeccompRule
	for i := range rules {
		if rules[i].Action != "SCMP_ACT_ALLOW" || !contains(rules[i].Names, syscall) {
			continue
		}
		copy := rules[i]
		copy.Names = []string{syscall}
		split = append(split, copy)
		remaining := rules[i].Names[:0]
		for _, name := range rules[i].Names {
			if name != syscall {
				remaining = append(remaining, name)
			}
		}
		rules[i].Names = remaining
	}
	filtered := rules[:0]
	for _, rule := range rules {
		if len(rule.Names) != 0 {
			filtered = append(filtered, rule)
		}
	}
	return append(filtered, split...)
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
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
