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

import "fmt"

// Mechanism is what produced a denial (proposal §6.1).
type Mechanism string

const (
	Seccomp           Mechanism = "seccomp"
	LSM               Mechanism = "lsm"
	CapabilityMissing Mechanism = "capability"
	Mount             Mechanism = "mount"
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
	errnoENOSYS  = 38
	errnoENODATA = 61
	errnoEROFS   = 30
)

// Attribute returns a copy of the fingerprint with every result attributed
// from the probe's oracle. It needs no privilege and no information beyond
// the verdict, the raw errno and the corpus declaration.
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
		a := attribute(r, probe)
		r.Attribution = &a
		results[i] = r
	}
	fp.Results = results
	return fp, nil
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
