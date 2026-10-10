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
)

func TestFindingRequiresPostureRevision(t *testing.T) {
	if err := (Finding{}).Validate(); err == nil {
		t.Fatal("expected a finding without posture_revision to be rejected")
	}

	f := Finding{PostureRevision: "v1"}
	if err := f.Validate(); err != nil {
		t.Fatalf("valid finding rejected: %v", err)
	}

	b, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("failed to marshal finding: %v", err)
	}
	if !strings.Contains(string(b), `"posture_revision":"v1"`) {
		t.Fatalf("finding JSON omitted posture_revision: %s", b)
	}
}
