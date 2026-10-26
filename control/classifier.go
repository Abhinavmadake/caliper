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
	"strconv"
	"strings"
)

// DivergenceClass is the single explanation assigned to a verdict change.
type DivergenceClass string

const (
	ArchitectureExplained  DivergenceClass = "architecture-explained"
	KernelVersionExplained DivergenceClass = "kernel-version-explained"
	RuntimeClassExplained  DivergenceClass = "runtime-class-explained"
	PolicyExplained        DivergenceClass = "policy-explained"
)

// ProbeMetadata is the control plane's view of one entry from --dump-corpus.
// The classifier reads only the declarations which are valid explanations for
// a divergence and never derives applicability from a probe name; the oracle
// and capability are for attribution (#30).
// The 32-bit compatibility ABI remains deferred until measurements carry its
// run-time applicability record, as required by spec/probe.md.
type ProbeMetadata struct {
	ID         string           `json:"id"`
	Family     string           `json:"family"`
	Arch       Applicability    `json:"arch"`
	Kernel     KernelDependency `json:"kernel"`
	Oracle     Oracle           `json:"oracle"`
	Capability string           `json:"capability"`
}

// LoadAttributionCorpus decodes the committed corpus index used by the
// attribution accuracy measurement.
func LoadAttributionCorpus(data []byte) ([]ProbeMetadata, error) {
	var corpus []ProbeMetadata
	if err := json.Unmarshal(data, &corpus); err != nil {
		return nil, fmt.Errorf("decode corpus index: %w", err)
	}
	return corpus, nil
}

// Oracle is the probe's errno oracle as the corpus declares it.
type Oracle struct {
	Guarantees *int   `json:"guarantees"`
	Isolates   string `json:"isolates"`
	Reason     string `json:"reason"`
}

// Applicability is the corpus architecture declaration. The corpus represents
// all architectures as "all", and a restricted probe as {"only":[...]}.
type Applicability struct {
	All  bool
	Only []string
}

// UnmarshalJSON accepts the two forms emitted by the Rust corpus exporter.
func (a *Applicability) UnmarshalJSON(data []byte) error {
	var all string
	if err := json.Unmarshal(data, &all); err == nil {
		if all != "all" {
			return fmt.Errorf("unknown applicability %q", all)
		}
		a.All = true
		a.Only = nil
		return nil
	}
	var restricted struct {
		Only []string `json:"only"`
	}
	if err := json.Unmarshal(data, &restricted); err != nil {
		return fmt.Errorf("decode applicability: %w", err)
	}
	if len(restricted.Only) == 0 {
		return fmt.Errorf("restricted applicability has no architectures")
	}
	a.All = false
	a.Only = restricted.Only
	return nil
}

// Includes reports whether the corpus declaration includes architecture.
func (a Applicability) Includes(architecture string) bool {
	if a.All {
		return true
	}
	for _, candidate := range a.Only {
		if candidate == architecture {
			return true
		}
	}
	return false
}

// KernelDependency is the entry-point dependency declared in the corpus.
// Since is omitted for configuration- or module-gated entry points; PresentIf
// and EncodedAbsent carry the engine's runtime evidence for those gates.
type KernelDependency struct {
	Since       *KernelVersion `json:"since"`
	AbsentErrno *int           `json:"absent_errno"`
	// AlsoAbsent is a second errno absence produces, read like AbsentErrno.
	AlsoAbsent *int   `json:"also_absent,omitempty"`
	Module     string `json:"module,omitempty"`
	// ProtocolModule is the module AlsoAbsent reports missing while Module
	// is loaded; empty when the protocol is not a module of its own.
	ProtocolModule string `json:"protocol_module,omitempty"`
	PresentIf      string `json:"present_if,omitempty"`
	EncodedAbsent  *int   `json:"encoded_absent,omitempty"`
	// LSMHookSince is the release from which an LSM hook runs before the
	// oracle's point, so a seccomp reading becomes seccomp or an LSM.
	LSMHookSince *KernelVersion `json:"lsm_hook_since,omitempty"`
	// UserNamespaceLimits marks an entry point the kernel's user-namespace
	// limits can refuse; a denial is read against the cell's (#96).
	UserNamespaceLimits bool `json:"user_namespace_limits,omitempty"`
}

// absent reports whether errno is one the dependency reads as absence.
func (d KernelDependency) absent(errno int) bool {
	return (d.AbsentErrno != nil && errno == *d.AbsentErrno) ||
		(d.AlsoAbsent != nil && errno == *d.AlsoAbsent)
}

// KernelVersion is the major/minor release used by a version-gated probe.
type KernelVersion [2]uint

// UnmarshalJSON decodes the Rust tuple form, for example [5, 3].
func (v *KernelVersion) UnmarshalJSON(data []byte) error {
	var values []uint
	if err := json.Unmarshal(data, &values); err != nil {
		return err
	}
	if len(values) != 2 {
		return fmt.Errorf("kernel version has %d components, want 2", len(values))
	}
	*v = KernelVersion{values[0], values[1]}
	return nil
}

// ClassifiedDivergence retains the raw observations alongside their class.
type ClassifiedDivergence struct {
	Divergence
	Class DivergenceClass `json:"class"`
}

// DivergenceCounts keeps every class separate; callers cannot accidentally
// present a single, misleading total as the policy divergence metric.
type DivergenceCounts struct {
	Architecture  int `json:"architecture_explained"`
	KernelVersion int `json:"kernel_version_explained"`
	RuntimeClass  int `json:"runtime_class_explained"`
	Policy        int `json:"policy_explained"`
}

// ClassificationResult is the diff plus a class for each actual divergence.
// Corpus skew and unmeasured probes remain outside the four class counts.
type ClassificationResult struct {
	Diff        DiffResult             `json:"diff"`
	Divergences []ClassifiedDivergence `json:"divergences"`
	Counts      DivergenceCounts       `json:"counts"`
}

// Classify runs the probe-granularity diff and assigns each verdict change one
// class using the recorded cells and corpus declarations.
func Classify(left, right Fingerprint, corpus []ProbeMetadata) (ClassificationResult, error) {
	diff, err := Diff(left, right)
	if err != nil {
		return ClassificationResult{}, err
	}
	metadata, err := metadataByID(corpus)
	if err != nil {
		return ClassificationResult{}, err
	}

	result := ClassificationResult{Diff: diff}
	for _, divergence := range diff.Divergences {
		probe, exists := metadata[divergence.ProbeID]
		if !exists {
			return ClassificationResult{}, fmt.Errorf("no corpus metadata for divergent probe %q", divergence.ProbeID)
		}
		class, err := classifyDivergence(divergence, probe, left, right)
		if err != nil {
			return ClassificationResult{}, err
		}
		result.Divergences = append(result.Divergences, ClassifiedDivergence{
			Divergence: divergence,
			Class:      class,
		})
		increment(&result.Counts, class)
	}
	return result, nil
}

func metadataByID(corpus []ProbeMetadata) (map[string]ProbeMetadata, error) {
	byID := make(map[string]ProbeMetadata, len(corpus))
	for _, probe := range corpus {
		if probe.ID == "" {
			return nil, fmt.Errorf("corpus metadata has an empty id")
		}
		if _, exists := byID[probe.ID]; exists {
			return nil, fmt.Errorf("duplicate corpus metadata id %q", probe.ID)
		}
		byID[probe.ID] = probe
	}
	return byID, nil
}

func classifyDivergence(divergence Divergence, probe ProbeMetadata, left, right Fingerprint) (DivergenceClass, error) {
	if architectureExplains(divergence, probe.Arch, left.Cell.Architecture, right.Cell.Architecture) {
		return ArchitectureExplained, nil
	}
	if runtimeClassExplains(divergence, probe.Kernel, runtimeClassValue(left.Cell), runtimeClassValue(right.Cell)) {
		return RuntimeClassExplained, nil
	}
	kernelExplanation, err := kernelExplains(divergence, probe.Kernel, left, right)
	if err != nil {
		return "", err
	}
	if kernelExplanation {
		return KernelVersionExplained, nil
	}
	return PolicyExplained, nil
}

func runtimeClassValue(cell Cell) string {
	if cell.RuntimeClass == nil {
		return ""
	}
	return cell.RuntimeClass.Value
}

func architectureExplains(d Divergence, applicability Applicability, leftArch, rightArch string) bool {
	return (d.Left.Verdict == "not-applicable" && !applicability.Includes(leftArch) && applicability.Includes(rightArch)) ||
		(d.Right.Verdict == "not-applicable" && !applicability.Includes(rightArch) && applicability.Includes(leftArch))
}

func runtimeClassExplains(d Divergence, dependency KernelDependency, leftClass, rightClass string) bool {
	if leftClass == rightClass {
		return false
	}
	leftSandboxed, rightSandboxed := sandboxed(leftClass), sandboxed(rightClass)
	if (leftSandboxed && d.Left.Verdict == "unimplemented") ||
		(rightSandboxed && d.Right.Verdict == "unimplemented") {
		return true
	}
	// When the unimplemented side is the ordinary runtime, a declared kernel
	// absence can still be caused by the sandboxed runtime's guest kernel.
	return leftSandboxed != rightSandboxed && declaredAbsence(d, dependency)
}

func sandboxed(runtimeClass string) bool {
	class := strings.ToLower(strings.TrimSpace(runtimeClass))
	if class == "gvisor" || class == "kata" {
		return true
	}
	return strings.HasPrefix(class, "runsc") || strings.HasPrefix(class, "kata-")
}

func kernelExplains(d Divergence, dependency KernelDependency, left, right Fingerprint) (bool, error) {
	// A kernel dependency needs an unimplemented observation with its declared
	// absence errno. Version-gated dependencies retain the stronger requirement
	// that the other environment permits the probe; a release difference for
	// other declared absences can still explain a mixed denied/unimplemented pair.
	var errno int
	var other ProbeResult
	if d.Left.Verdict == "unimplemented" {
		errno = d.Left.Errno
		other = d.Right
	} else if d.Right.Verdict == "unimplemented" {
		errno = d.Right.Errno
		other = d.Left
	} else {
		return false, nil
	}

	// The engine's unimplemented verdict already applies present_if and
	// encoded_absent. For those dependencies it is the cell-specific evidence
	// that the entry point is absent; no release or module comparison is needed.
	if dependency.EncodedAbsent != nil && errno == *dependency.EncodedAbsent && other.Verdict == "permitted" {
		return true, nil
	}
	if !dependency.absent(errno) {
		return false, nil
	}
	if dependency.PresentIf != "" {
		return other.Verdict == "permitted", nil
	}
	if dependency.Since != nil {
		if other.Verdict != "permitted" {
			return false, nil
		}
		leftVersion, leftKnown := parseKernelVersion(left.Cell.Kernel.Release)
		rightVersion, rightKnown := parseKernelVersion(right.Cell.Kernel.Release)
		return leftKnown && rightKnown && (before(leftVersion, *dependency.Since) != before(rightVersion, *dependency.Since)), nil
	}
	// The second absence errno is the protocol missing with the family
	// loaded, so it is the protocol's module that must differ (#96).
	module := dependency.Module
	if dependency.AlsoAbsent != nil && errno == *dependency.AlsoAbsent &&
		(dependency.AbsentErrno == nil || errno != *dependency.AbsentErrno) {
		module = dependency.ProtocolModule
	}
	if module == "" {
		return kernelReleasesDiffer(left.Cell.Kernel.Release, right.Cell.Kernel.Release), nil
	}
	leftModules, leftKnown, err := modulesAfterRun(left)
	if err != nil {
		return false, err
	}
	rightModules, rightKnown, err := modulesAfterRun(right)
	if err != nil {
		return false, err
	}
	if leftKnown && rightKnown && other.Verdict == "permitted" &&
		containsModule(leftModules, module) != containsModule(rightModules, module) {
		return true, nil
	}
	// A declared absence on a different kernel release is kernel-explained,
	// including dependencies that name a module but lack comparable snapshots.
	return kernelReleasesDiffer(left.Cell.Kernel.Release, right.Cell.Kernel.Release), nil
}

func declaredAbsence(d Divergence, dependency KernelDependency) bool {
	if d.Left.Verdict == "unimplemented" {
		return (dependency.EncodedAbsent != nil && d.Left.Errno == *dependency.EncodedAbsent) || dependency.absent(d.Left.Errno)
	}
	if d.Right.Verdict == "unimplemented" {
		return (dependency.EncodedAbsent != nil && d.Right.Errno == *dependency.EncodedAbsent) || dependency.absent(d.Right.Errno)
	}
	return false
}

func modulesAfterRun(fingerprint Fingerprint) ([]string, bool, error) {
	if len(fingerprint.ModuleDelta) > 0 {
		var delta struct {
			After *[]string `json:"after"`
		}
		if err := json.Unmarshal(fingerprint.ModuleDelta, &delta); err != nil {
			return nil, false, fmt.Errorf("decode module_delta: %w", err)
		}
		if delta.After != nil {
			return *delta.After, true, nil
		}
	}
	if fingerprint.Cell.Kernel.Modules != nil {
		return *fingerprint.Cell.Kernel.Modules, true, nil
	}
	return nil, false, nil
}

func kernelReleasesDiffer(leftRelease, rightRelease string) bool {
	_, leftKnown := parseKernelVersion(leftRelease)
	_, rightKnown := parseKernelVersion(rightRelease)
	return leftKnown && rightKnown && strings.TrimSpace(leftRelease) != strings.TrimSpace(rightRelease)
}

func containsModule(modules []string, module string) bool {
	for _, loaded := range modules {
		if loaded == module {
			return true
		}
	}
	return false
}

func parseKernelVersion(release string) (KernelVersion, bool) {
	parts := strings.FieldsFunc(release, func(r rune) bool { return r < '0' || r > '9' })
	if len(parts) < 2 {
		return KernelVersion{}, false
	}
	major, majorErr := strconv.ParseUint(parts[0], 10, 32)
	minor, minorErr := strconv.ParseUint(parts[1], 10, 32)
	if majorErr != nil || minorErr != nil {
		return KernelVersion{}, false
	}
	return KernelVersion{uint(major), uint(minor)}, true
}

func before(version, threshold KernelVersion) bool {
	return version[0] < threshold[0] || (version[0] == threshold[0] && version[1] < threshold[1])
}

func increment(counts *DivergenceCounts, class DivergenceClass) {
	switch class {
	case ArchitectureExplained:
		counts.Architecture++
	case KernelVersionExplained:
		counts.KernelVersion++
	case RuntimeClassExplained:
		counts.RuntimeClass++
	case PolicyExplained:
		counts.Policy++
	}
}
