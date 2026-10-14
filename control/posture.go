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
	"bytes"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

// ReferencePosture is the versioned policy that states what a workload at a
// given tier should not be able to reach. Tier order is least to most
// restrictive; assertions inherit to later tiers.
type ReferencePosture struct {
	Revision   string             `yaml:"posture_revision" json:"posture_revision"`
	Status     string             `yaml:"status" json:"status"`
	Tiers      []PostureTier      `yaml:"tiers" json:"tiers"`
	Assertions []PostureAssertion `yaml:"assertions" json:"assertions"`
}

// PostureTier describes a security tier and the PSS level it is named after.
type PostureTier struct {
	Name                   string `yaml:"name" json:"name"`
	NamedAfter             string `yaml:"named_after" json:"named_after"`
	Describes              string `yaml:"describes" json:"describes"`
	StrongerThanPSSBecause string `yaml:"stronger_than_pss_because" json:"stronger_than_pss_because"`
}

// PostureAssertion states that a family, or a subset of its probe IDs, should
// be unreachable at the named tier and all stricter tiers.
type PostureAssertion struct {
	Tier      string            `yaml:"tier" json:"tier"`
	Family    string            `yaml:"family" json:"family"`
	ProbeIDs  []string          `yaml:"probe_ids,omitempty" json:"probe_ids,omitempty"`
	Expect    string            `yaml:"expect" json:"expect"`
	Rationale string            `yaml:"rationale" json:"rationale"`
	Citations []PostureCitation `yaml:"citations" json:"citations"`
}

// PostureCitation identifies the evidence behind a posture assertion.
type PostureCitation struct {
	ID        string `yaml:"id,omitempty" json:"id,omitempty"`
	Title     string `yaml:"title,omitempty" json:"title,omitempty"`
	Publisher string `yaml:"publisher,omitempty" json:"publisher,omitempty"`
	URL       string `yaml:"url" json:"url"`
}

// ParsePosture decodes and validates a reference posture YAML document.
func ParsePosture(data []byte) (ReferencePosture, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var posture ReferencePosture
	if err := decoder.Decode(&posture); err != nil {
		return ReferencePosture{}, fmt.Errorf("decode posture: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return ReferencePosture{}, fmt.Errorf("decode posture: multiple YAML documents are not supported")
		}
		return ReferencePosture{}, fmt.Errorf("decode posture: %w", err)
	}
	if err := posture.Validate(); err != nil {
		return ReferencePosture{}, err
	}
	return posture, nil
}

// Validate checks the posture identity, tier ordering, and assertion shape.
func (p ReferencePosture) Validate() error {
	if p.Revision == "" {
		return fmt.Errorf("posture_revision is required")
	}
	if p.Status != "released" && p.Status != "draft" {
		return fmt.Errorf("posture status must be released or draft, got %q", p.Status)
	}
	if len(p.Tiers) == 0 {
		return fmt.Errorf("posture must declare at least one tier")
	}
	tierIndex := make(map[string]int, len(p.Tiers))
	for i, tier := range p.Tiers {
		if tier.Name == "" || tier.NamedAfter == "" {
			return fmt.Errorf("posture tier %d requires name and named_after", i)
		}
		if _, exists := tierIndex[tier.Name]; exists {
			return fmt.Errorf("duplicate posture tier %q", tier.Name)
		}
		tierIndex[tier.Name] = i
	}
	for i, assertion := range p.Assertions {
		if _, exists := tierIndex[assertion.Tier]; !exists {
			return fmt.Errorf("posture assertion %d refers to unknown tier %q", i, assertion.Tier)
		}
		if assertion.Family == "" || assertion.Expect != "unreachable" || assertion.Rationale == "" {
			return fmt.Errorf("posture assertion %d requires family, unreachable expectation, and rationale", i)
		}
		if len(assertion.Citations) == 0 {
			return fmt.Errorf("posture assertion %d requires at least one citation", i)
		}
		seen := make(map[string]struct{}, len(assertion.ProbeIDs))
		for _, id := range assertion.ProbeIDs {
			if id == "" {
				return fmt.Errorf("posture assertion %d has an empty probe_id", i)
			}
			if _, exists := seen[id]; exists {
				return fmt.Errorf("posture assertion %d has duplicate probe_id %q", i, id)
			}
			seen[id] = struct{}{}
		}
		for _, citation := range assertion.Citations {
			if citation.URL == "" || (citation.ID == "" && citation.Title == "") {
				return fmt.Errorf("posture assertion %d has an incomplete citation", i)
			}
		}
	}
	return nil
}

func (p ReferencePosture) tierIndex(name string) (int, bool) {
	for i, tier := range p.Tiers {
		if tier.Name == name {
			return i, true
		}
	}
	return 0, false
}
