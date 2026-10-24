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

	"github.com/Abhinavmadake/caliper/control"
)

func TestCommittedDivergenceMetricsMatchRegeneratedFixtures(t *testing.T) {
	metrics, err := computeMetrics("../../../fixtures/cells", "../../../corpus/index.json")
	if err != nil {
		t.Fatalf("regenerate divergence metrics: %v", err)
	}
	got, err := json.MarshalIndent(metrics, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	want, err := os.ReadFile("../../../fixtures/metrics/divergence-metrics.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("committed divergence metrics do not match regenerated cell fixtures")
	}
}

func TestAddCountsKeepsDivergenceClassesSeparate(t *testing.T) {
	total := control.DivergenceCounts{}
	addCounts(&total, control.DivergenceCounts{Architecture: 2, KernelVersion: 3, RuntimeClass: 4, Policy: 5})
	addCounts(&total, control.DivergenceCounts{Architecture: 7, KernelVersion: 11, RuntimeClass: 13, Policy: 17})
	want := control.DivergenceCounts{Architecture: 9, KernelVersion: 14, RuntimeClass: 17, Policy: 22}
	if total != want {
		t.Fatalf("totals = %#v, want %#v", total, want)
	}
}
