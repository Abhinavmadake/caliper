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

// Finding carries the posture provenance required by issue #23. The complete
// finding shape belongs to the evaluator in issue #34; this contract does not
// prescribe its kind, tier, family, or probe fields.
type Finding struct {
	PostureRevision string `json:"posture_revision"`
}

// Validate prevents a finding from being emitted without naming the exact
// immutable posture revision used for its evaluation.
func (f Finding) Validate() error {
	if f.PostureRevision == "" {
		return fmt.Errorf("finding posture_revision is required")
	}
	return nil
}
