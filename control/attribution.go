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

// Mechanism is what produced a denial (proposal §6.1).
type Mechanism string

const (
	Seccomp           Mechanism = "seccomp"
	LSM               Mechanism = "lsm"
	CapabilityMissing Mechanism = "capability"
	Mount             Mechanism = "mount"
	// KernelLimit is the kernel's own limit, such as a user-namespace sysctl.
	KernelLimit Mechanism = "kernel-limit"
)

// Confidence grades an attribution. High is a positive proof; medium is the
// oracle's structural reading without a guaranteed errno to prove it; low is
// undecidable from inside the container. The confidence model is #32's.
type Confidence string

const (
	High   Confidence = "high"
	Medium Confidence = "medium"
	Low    Confidence = "low"
)

// Attribution is the errno-oracle reading of one result (#30). Mechanism is
// null when there is no denial or the oracle cannot decide; Candidates then
// lists what the denial could be, for capability and LSM correlation (#31)
// to narrow.
type Attribution struct {
	Mechanism   *Mechanism  `json:"mechanism"`
	Confidence  Confidence  `json:"confidence"`
	Undecidable bool        `json:"undecidable"`
	Candidates  []Mechanism `json:"candidates,omitempty"`
	Reason      string      `json:"reason,omitempty"`
}

const (
	errnoENOENT  = 2
	errnoEPERM   = 1
	errnoENOSPC  = 28
	errnoENOSYS  = 38
	errnoENODATA = 61
	errnoEROFS   = 30
)

// Attribute returns a copy of the fingerprint with every result attributed
// from the probe's oracle. The digest remains the identity of the source
// fingerprint: consumers must not recompute it after decoding because
// additive fields unknown to this control-plane version may have been dropped.
func Attribute(fp Fingerprint, corpus []ProbeMetadata) (Fingerprint, error) {
	metadata, err := metadataByID(corpus)
	if err != nil {
		return Fingerprint{}, err
	}
	results := make([]ProbeResult, len(fp.Results))
	for i, r := range fp.Results {
		probe, ok := metadata[r.ProbeID]
		if !ok {
			return Fingerprint{}, fmt.Errorf("no corpus metadata for probe %q", r.ProbeID)
		}
		probe = withKernelHooks(probe, fp.Cell.Kernel.Release)
		a := correlate(attribute(r, probe), r, probe, fp.Cell)
		r.Attribution = &a
		results[i] = r
	}
	fp.Results = results
	return fp, nil
}

// correlate narrows the deliberately conservative errno-oracle result with
// facts the process recorded about itself. It never reads host state: the
// capability masks and LSM label belong to the measured process.
func correlate(a Attribution, r ProbeResult, p ProbeMetadata, cell Cell) Attribution {
	if r.Verdict != "denied" {
		return a
	}

	if r.Errno == errnoEPERM && p.Oracle.Isolates == "undecidable" && p.Capability != "" {
		if effective, bounding, known := capabilityState(cell.Capabilities, p.Capability); known {
			// A capability can only be deliberately dropped from Effective while
			// remaining usable through a later exec if it is still in Bounding.
			// When it is absent from Bounding, Docker's default seccomp policy can
			// produce this same EPERM before the kernel capability check.
			if !effective && bounding {
				return correlated(CapabilityMissing,
					fmt.Sprintf("%s is absent from Effective but remains in Bounding, which correlates the EPERM with the syscall capability gate", p.Capability))
			}

			candidates := []Mechanism{Seccomp, LSM}
			reason := fmt.Sprintf("%s is present in the effective set, so seccomp and an LSM capability or namespace hook can also return EPERM", p.Capability)
			if !bounding {
				candidates = []Mechanism{Seccomp, CapabilityMissing}
				reason = fmt.Sprintf("%s is absent from both Effective and Bounding; it is still missing, but Docker's default seccomp policy can produce the same EPERM first", p.Capability)
			}
			return undecidable(candidates, reason)
		}
	}

	if p.Kernel.UserNamespaceLimits && cell.UserNamespaces != nil {
		if a, ok := userNamespaceLimit(a, r, cell); ok {
			return a
		}
	}

	if r.Errno == 13 && p.Oracle.Isolates == "seccomp-or-lsm" && confiningLSM(cell) {
		return correlated(LSM,
			fmt.Sprintf("EACCES follows the security-module hook and %s is enforcing label %q", cell.LSM, *cell.LSMLabel))
	}
	return a
}

// withKernelHooks applies a dependency's lsm_hook_since: on that release or
// later, or when the release cannot be read, a seccomp oracle reads as
// seccomp or an LSM.
func withKernelHooks(p ProbeMetadata, release string) ProbeMetadata {
	since := p.Kernel.LSMHookSince
	if since == nil || p.Oracle.Isolates != "seccomp" {
		return p
	}
	if version, known := parseKernelVersion(release); known && before(version, *since) {
		return p
	}
	p.Oracle.Isolates = "seccomp-or-lsm"
	return p
}

func correlated(mechanism Mechanism, reason string) Attribution {
	return Attribution{Mechanism: &mechanism, Confidence: Low, Reason: reason}
}

type capabilityMasks struct {
	Effective string `json:"effective"`
	Bounding  string `json:"bounding"`
}

var capabilityBits = map[string]uint{
	"CAP_NET_ADMIN":        12,
	"CAP_NET_RAW":          13,
	"CAP_SYS_ADMIN":        21,
	"CAP_SYS_RAWIO":        17,
	"CAP_SYS_TIME":         25,
	"CAP_SYS_BOOT":         22,
	"CAP_SYS_MODULE":       16,
	"CAP_MKNOD":            27,
	"CAP_SYS_PTRACE":       19,
	"CAP_NET_BIND_SERVICE": 10,
	"CAP_SYS_NICE":         23,
	"CAP_SYS_RESOURCE":     24,
	"CAP_DAC_READ_SEARCH":  2,
	"CAP_BPF":              39,
	"CAP_PERFMON":          38,
}

func capabilityState(raw json.RawMessage, capability string) (effectivePresent, boundingPresent, known bool) {
	bit, ok := capabilityBits[capability]
	if !ok || len(raw) == 0 {
		return false, false, false
	}
	var masks capabilityMasks
	if json.Unmarshal(raw, &masks) != nil || masks.Effective == "" || masks.Bounding == "" {
		return false, false, false
	}
	effective, err := strconv.ParseUint(masks.Effective, 16, 64)
	if err != nil {
		return false, false, false
	}
	bounding, err := strconv.ParseUint(masks.Bounding, 16, 64)
	if err != nil {
		return false, false, false
	}
	return effective&(uint64(1)<<bit) != 0, bounding&(uint64(1)<<bit) != 0, true
}

func confiningLSM(cell Cell) bool {
	if cell.LSMLabel == nil || cell.LSMEnforcing == nil || !*cell.LSMEnforcing {
		return false
	}
	if cell.LSM != "apparmor" && cell.LSM != "selinux" {
		return false
	}
	return strings.TrimSpace(*cell.LSMLabel) != "" && strings.TrimSpace(*cell.LSMLabel) != "unconfined"
}

func attribute(r ProbeResult, p ProbeMetadata) Attribution {
	switch r.Verdict {
	case "killed":
		return proven(Seccomp, "terminated by SIGSYS, which only a seccomp KILL_PROCESS or KILL_THREAD filter produces")
	case "permitted":
		if r.Errno != 0 {
			return notDenied(fmt.Sprintf("returned %s, the oracle's guaranteed errno: the call reached the kernel", errnoName(r.Errno)))
		}
		return notDenied("")
	case "unimplemented":
		return notDenied(fmt.Sprintf("%s is the entry point absent from this kernel, not a denial", errnoName(r.Errno)))
	case "not-applicable":
		return notDenied("entry point absent on this cell, decided before the probe ran")
	case "timed-out":
		return undecidable(nil, "exceeded its risk class's timeout; hung and slow are not distinguished")
	case "denied":
		return denied(r, p)
	}
	return undecidable(nil, fmt.Sprintf("unknown verdict %q", r.Verdict))
}

func denied(r ProbeResult, p ProbeMetadata) Attribution {
	guaranteed := p.Oracle.Guarantees != nil
	proof := func(m Mechanism, why string) Attribution {
		if guaranteed {
			return proven(m, fmt.Sprintf("%s where the oracle guaranteed %s: %s", errnoName(r.Errno), errnoName(*p.Oracle.Guarantees), why))
		}
		a := proven(m, fmt.Sprintf("%s: %s", errnoName(r.Errno), why))
		a.Confidence = Medium
		return a
	}

	// The path family's encodings of what fstatfs reported (spec/probe.md).
	if p.Family == "path" && (r.Errno == errnoENODATA || r.Errno == errnoEROFS) {
		what := "masked by a mount over the object"
		if r.Errno == errnoEROFS {
			what = "on a read-only mount"
		}
		return proven(Mount, fmt.Sprintf("%s: the probe's encoding for an object %s", errnoName(r.Errno), what))
	}
	// spec/probe.md: ENOSYS from a syscall the kernel implements is a filter.
	// The verdict is denied, not unimplemented, only when it does.
	if r.Errno == errnoENOSYS {
		return proof(Seccomp, "the kernel implements this syscall, so ENOSYS is a filter answering in its voice")
	}
	if r.Errno != errnoEPERM {
		return undecidable(nil, fmt.Sprintf("%s is not separated by the oracle; see the probe's oracle reason", errnoName(r.Errno)))
	}

	switch p.Oracle.Isolates {
	case "seccomp":
		return proof(Seccomp, "nothing before the oracle's point answers EPERM but a filter at syscall entry")
	case "seccomp-or-lsm":
		return undecidable([]Mechanism{Seccomp, LSM}, "EPERM is a filter or a security module; the oracle does not separate them")
	case "undecidable":
		if p.Capability != "" {
			return undecidable([]Mechanism{Seccomp, CapabilityMissing},
				fmt.Sprintf("EPERM is a filter or the missing %s; the syscall's own check answers the same", p.Capability))
		}
		return undecidable(nil, "EPERM is not separable from inside the container")
	}
	return undecidable(nil, fmt.Sprintf("unknown oracle isolation %q", p.Oracle.Isolates))
}

func proven(m Mechanism, reason string) Attribution {
	return Attribution{Mechanism: &m, Confidence: High, Reason: reason}
}

func notDenied(reason string) Attribution {
	return Attribution{Confidence: High, Reason: reason}
}

func undecidable(candidates []Mechanism, reason string) Attribution {
	return Attribution{Confidence: Low, Undecidable: true, Candidates: candidates, Reason: reason}
}

var errnoNames = map[int]string{
	errnoEPERM: "EPERM", errnoENOENT: "ENOENT", 9: "EBADF", 13: "EACCES", 19: "ENODEV",
	22: "EINVAL", errnoEROFS: "EROFS", errnoENOSYS: "ENOSYS", errnoENODATA: "ENODATA",
	93: "EPROTONOSUPPORT", 95: "EOPNOTSUPP", 97: "EAFNOSUPPORT",
}

func errnoName(n int) string {
	if name, ok := errnoNames[n]; ok {
		return name
	}
	return fmt.Sprintf("errno %d", n)
}

// userNamespaceLimit reads a user-namespace probe's denial against the
// kernel's own limits recorded in the cell (#96). ENOSPC with no namespaces
// allowed is the limit; an EPERM while a limit is set could be the limit or
// whatever the oracle already allowed, so the limit widens the oracle's
// candidates rather than replacing them.
func userNamespaceLimit(a Attribution, r ProbeResult, cell Cell) (Attribution, bool) {
	limits := cell.UserNamespaces
	if r.Errno == errnoENOSPC && limits.Max != nil && *limits.Max == 0 {
		return correlated(KernelLimit, "user.max_user_namespaces is 0, and the kernel answers ENOSPC to every user-namespace creation"), true
	}
	if r.Errno != errnoEPERM {
		return Attribution{}, false
	}
	candidates := append([]Mechanism(nil), a.Candidates...)
	if a.Mechanism != nil {
		candidates = append(candidates, *a.Mechanism)
	}
	var reasons []string
	if limits.UnprivilegedClone != nil && *limits.UnprivilegedClone == 0 {
		candidates = appendMechanism(candidates, KernelLimit)
		reasons = append(reasons, "kernel.unprivileged_userns_clone is 0")
	}
	if limits.ApparmorRestricted != nil && *limits.ApparmorRestricted == 1 && cell.LSM == "apparmor" {
		candidates = appendMechanism(candidates, LSM)
		reasons = append(reasons, "kernel.apparmor_restrict_unprivileged_userns is 1")
	}
	if len(reasons) == 0 {
		return Attribution{}, false
	}
	return undecidable(candidates, "EPERM on a user-namespace creation: "+strings.Join(reasons, " and ")+", so it is "+mechanismList(candidates)), true
}

func appendMechanism(mechanisms []Mechanism, m Mechanism) []Mechanism {
	for _, have := range mechanisms {
		if have == m {
			return mechanisms
		}
	}
	return append(mechanisms, m)
}

var mechanismPhrases = map[Mechanism]string{
	Seccomp: "a filter", LSM: "an LSM", CapabilityMissing: "a missing capability",
	Mount: "a mount", KernelLimit: "the kernel's limit",
}

// mechanismList names the candidates in prose: "a filter, an LSM or the
// kernel's limit".
func mechanismList(mechanisms []Mechanism) string {
	phrases := make([]string, len(mechanisms))
	for i, m := range mechanisms {
		phrases[i] = mechanismPhrases[m]
	}
	if len(phrases) < 2 {
		return strings.Join(phrases, "")
	}
	return strings.Join(phrases[:len(phrases)-1], ", ") + " or " + phrases[len(phrases)-1]
}
