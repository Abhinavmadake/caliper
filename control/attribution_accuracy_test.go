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
	"os"
	"path/filepath"
	"testing"
)

func loadAttributionGroundTruth(t *testing.T) AttributionGroundTruth {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "fixtures", "ground-truth", "attribution.json"))
	if err != nil {
		t.Fatal(err)
	}
	var suite AttributionGroundTruth
	if err := json.Unmarshal(data, &suite); err != nil {
		t.Fatal(err)
	}
	return suite
}

func TestAttributionAccuracyGroundTruthMeetsIssue44Criteria(t *testing.T) {
	metrics, err := EvaluateAttributionAccuracy(loadAttributionGroundTruth(t))
	if err != nil {
		t.Fatal(err)
	}
	if metrics.GroundTruthEnvironments != 5 || metrics.Denials == 0 {
		t.Fatalf("ground-truth environments/denials = %d/%d, want 5/nonzero", metrics.GroundTruthEnvironments, metrics.Denials)
	}
	if metrics.Accuracy == nil || metrics.UndecidableFraction == nil {
		t.Fatalf("missing measured metrics: %#v", metrics)
	}
	if !metrics.ENOSYSFilterIncluded {
		t.Fatalf("measured ENOSYS case omitted: %#v", metrics)
	}
}
