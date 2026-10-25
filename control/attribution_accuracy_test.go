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
	if metrics.GroundTruthEnvironments != 10 || metrics.Denials != 10 {
		t.Fatalf("ground-truth environments/denials = %d/%d, want 10/10", metrics.GroundTruthEnvironments, metrics.Denials)
	}
	if metrics.Accuracy == nil || *metrics.Accuracy < .90 || !metrics.AccuracyCriterionMet {
		t.Fatalf("attribution accuracy = %#v, want at least 90%%", metrics)
	}
	if metrics.UndecidableFraction == nil || *metrics.UndecidableFraction > .10 || !metrics.UndecidableCriterionMet {
		t.Fatalf("undecidable fraction = %#v, want at most 10%%", metrics)
	}
	if !metrics.ENOSYSFilterIncluded || !metrics.LSMOnlyIncluded {
		t.Fatalf("required ambiguous cases omitted: %#v", metrics)
	}
	for _, test := range metrics.Cases {
		if !test.Correct || test.Undecidable {
			t.Errorf("%s = %#v, want correct decided attribution", test.Name, test)
		}
	}
}

func TestAttributionAccuracyRejectsNonDenial(t *testing.T) {
	suite := loadAttributionGroundTruth(t)
	suite.Cases[0].Result.Verdict = "permitted"
	if _, err := EvaluateAttributionAccuracy(suite); err == nil {
		t.Fatal("accepted a non-denial ground-truth case")
	}
}
