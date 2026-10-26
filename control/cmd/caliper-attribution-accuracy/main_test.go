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
	metrics, err := compute("../../../fixtures/ground-truth/attribution.json", "../../../corpus/index.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(metrics.Environments) != 6 || !metrics.ENOSYSFilterIncluded || !metrics.LSMOnlyIncluded {
		t.Fatalf("environments/ENOSYS/LSM-only = %d/%t/%t, want 6/true/true",
			len(metrics.Environments), metrics.ENOSYSFilterIncluded, metrics.LSMOnlyIncluded)
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
