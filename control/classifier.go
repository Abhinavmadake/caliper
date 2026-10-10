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
// Since is omitted for configuration- or module-gated entry points.
type KernelDependency struct {
	Since       *KernelVersion `json:"since"`
	AbsentErrno *int           `json:"absent_errno"`
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
		class := classifyDivergence(divergence, probe, left.Cell, right.Cell)
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

func classifyDivergence(divergence Divergence, probe ProbeMetadata, left, right Cell) DivergenceClass {
	if architectureExplains(divergence, probe.Arch, left.Architecture, right.Architecture) {
		return ArchitectureExplained
	}
	if runtimeClassExplains(divergence, left.RuntimeClass.Value, right.RuntimeClass.Value) {
		return RuntimeClassExplained
	}
	if kernelExplains(divergence, probe.Kernel, left.Kernel, right.Kernel) {
		return KernelVersionExplained
	}
	return PolicyExplained
}

func architectureExplains(d Divergence, applicability Applicability, leftArch, rightArch string) bool {
	return (d.Left.Verdict == "not-applicable" && !applicability.Includes(leftArch) && applicability.Includes(rightArch)) ||
		(d.Right.Verdict == "not-applicable" && !applicability.Includes(rightArch) && applicability.Includes(leftArch))
}

func runtimeClassExplains(d Divergence, leftClass, rightClass string) bool {
	if leftClass == rightClass {
		return false
	}
	return (sandboxed(leftClass) && d.Left.Verdict == "unimplemented") ||
		(sandboxed(rightClass) && d.Right.Verdict == "unimplemented")
}

func sandboxed(runtimeClass string) bool {
	class := strings.ToLower(strings.TrimSpace(runtimeClass))
	if class == "gvisor" || class == "kata" {
		return true
	}
	return strings.HasPrefix(class, "runsc") || strings.HasPrefix(class, "kata-")
}

func kernelExplains(d Divergence, dependency KernelDependency, left, right Kernel) bool {
	if dependency.AbsentErrno == nil {
		return false
	}
	if d.Left.Verdict == "unimplemented" && d.Left.Errno != *dependency.AbsentErrno {
		return false
	}
	if d.Right.Verdict == "unimplemented" && d.Right.Errno != *dependency.AbsentErrno {
		return false
	}
	if d.Left.Verdict != "unimplemented" && d.Right.Verdict != "unimplemented" {
		return false
	}
	if dependency.Since != nil {
		leftVersion, leftKnown := parseKernelVersion(left.Release)
		rightVersion, rightKnown := parseKernelVersion(right.Release)
		return leftKnown && rightKnown && (before(leftVersion, *dependency.Since) != before(rightVersion, *dependency.Since))
	}
	return modulesDiffer(left.Modules, right.Modules)
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

func modulesDiffer(left, right *[]string) bool {
	if left == nil || right == nil {
		return false
	}
	leftModules := append([]string(nil), (*left)...)
	rightModules := append([]string(nil), (*right)...)
	sort.Strings(leftModules)
	sort.Strings(rightModules)
	return strings.Join(leftModules, "\x00") != strings.Join(rightModules, "\x00")
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
