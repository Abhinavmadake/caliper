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

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

func TestCommittedAttributionAccuracyMetricsMatchGroundTruth(t *testing.T) {
	metrics, err := compute("../../../fixtures/ground-truth/attribution.json")
	if err != nil {
		t.Fatal(err)
	}
	if metrics.GroundTruthEnvironments != 5 || !metrics.ENOSYSFilterIncluded || !metrics.LSMOnlyIncluded {
		t.Fatalf("measured ground truth = %#v", metrics)
	}
	got, err := json.MarshalIndent(metrics, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	want, err := os.ReadFile("../../../fixtures/metrics/attribution-accuracy.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("committed attribution accuracy metrics do not match regenerated ground truth")
	}
}
