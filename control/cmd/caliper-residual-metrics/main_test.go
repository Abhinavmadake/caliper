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
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

const corpusJSON = `[
	{"id": "mount.a", "effects": {"residual": ["mounts"]}},
	{"id": "socket.b", "effects": {"residual": []}}
]`

// run is a fingerprint; elapsed < 0 leaves elapsed_ms out.
func run(set string, elapsed int, results, residual string) string {
	timing := ""
	if elapsed >= 0 {
		timing = fmt.Sprintf(`, "elapsed_ms": %d`, elapsed)
	}
	return fmt.Sprintf(`{"format_version": 1, "corpus_revision": "0.3.2", "corpus_set": %q,
		"cell": {"architecture": "x86_64", "kernel": {"release": "7.0.0"}, "lsm": "none"},
		"results": %s, "unmeasured": [],
		"module_delta": {"before": [], "after": ["af_alg"], "loaded_by_run": ["af_alg"]},
		"residual": %s%s}`, set, results, residual, timing)
}

const clean = `{"observability": {"mounts": "observed", "keyrings": {"unobservable": {"reason": "masked"}},
	"cgroups": "observed", "sysv_ipc": "observed", "posix_ipc": "observed", "net_namespaces": "observed"},
	"before": {"mounts": 25, "keyrings": null, "cgroups": 0, "sysv_ipc": 0, "posix_ipc": 0, "net_namespaces": 1},
	"after": {"mounts": 25, "keyrings": null, "cgroups": 0, "sysv_ipc": 0, "posix_ipc": 0, "net_namespaces": 1},
	"leaks": [], "unverifiable": [], "audit": [], "janitor": []}`

func write(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestResidualAndRuntimeAcrossRuns(t *testing.T) {
	dir := t.TempDir()
	corpus := write(t, t.TempDir(), "index.json", corpusJSON)
	write(t, dir, "a-full.json", run("full", 900, `[{"probe_id": "mount.a", "verdict": "permitted", "errno": 0}]`, clean))
	write(t, dir, "a-reduced.json", run("reduced", 40, `[{"probe_id": "mount.a", "verdict": "denied", "errno": 1}]`, clean))
	m, err := computeMetrics(dir, corpus)
	if err != nil {
		t.Fatal(err)
	}
	if !m.ZeroResidualCriterionMet || m.UnreclaimedObjects != 0 || m.Leaks != 0 {
		t.Fatalf("residual = %d unreclaimed, %d leaks, met %t", m.UnreclaimedObjects, m.Leaks, m.ZeroResidualCriterionMet)
	}
	if !reflect.DeepEqual(m.ClassesNeverObserved, []string{"keyrings"}) || !reflect.DeepEqual(m.ClassesExercised, []string{"mounts"}) {
		t.Fatalf("never observed %v, exercised %v", m.ClassesNeverObserved, m.ClassesExercised)
	}
	if *m.SlowestFullMS != 900 || *m.SlowestReducedMS != 40 || !m.FullRuntimeCriterionMet || !m.ReducedRuntimeCriterionMet {
		t.Fatalf("runtime = %+v", m)
	}
	if got := m.Runs[0].ModulesLoadedByRun; !reflect.DeepEqual(got, []string{"af_alg"}) {
		t.Fatalf("modules = %v, reported apart from residual", got)
	}

	// A mount left behind, caught per probe and in the run delta.
	leaked := `{"observability": {"mounts": "observed"}, "before": {"mounts": 25}, "after": {"mounts": 26},
		"leaks": [{"probe_id": "mount.a", "class": "mounts", "delta": 1, "declared": true}], "audit": [], "janitor": []}`
	write(t, dir, "a-full.json", run("full", 900, `[]`, leaked))
	if m, err = computeMetrics(dir, corpus); err != nil {
		t.Fatal(err)
	}
	if m.ZeroResidualCriterionMet || m.UnreclaimedObjects != 1 || m.Leaks != 1 {
		t.Fatalf("leak = %d unreclaimed, %d leaks, met %t", m.UnreclaimedObjects, m.Leaks, m.ZeroResidualCriterionMet)
	}

	// Removed by a later probe: no run delta, still a leak.
	balanced := `{"observability": {"mounts": "observed"}, "before": {"mounts": 25}, "after": {"mounts": 25},
		"leaks": [{"probe_id": "mount.a", "class": "mounts", "delta": 1, "declared": true},
		          {"probe_id": "socket.b", "class": "mounts", "delta": -1, "declared": false}], "audit": [], "janitor": []}`
	write(t, dir, "a-full.json", run("full", 900, `[]`, balanced))
	if m, err = computeMetrics(dir, corpus); err != nil {
		t.Fatal(err)
	}
	if m.ZeroResidualCriterionMet || m.UnreclaimedObjects != 0 {
		t.Fatalf("balanced leak = %d unreclaimed, met %t", m.UnreclaimedObjects, m.ZeroResidualCriterionMet)
	}

	write(t, dir, "a-full.json", run("full", -1, `[]`, clean))
	if _, err := computeMetrics(dir, corpus); err == nil {
		t.Fatal("accepted a run without elapsed_ms")
	}
}

func TestCommittedResidualMetricsMatchRegeneratedFixtures(t *testing.T) {
	metrics, err := computeMetrics("../../../fixtures/runtime", "../../../corpus/index.json")
	if err != nil {
		t.Fatalf("regenerate residual metrics: %v", err)
	}
	if !metrics.ZeroResidualCriterionMet || !metrics.FullRuntimeCriterionMet || !metrics.ReducedRuntimeCriterionMet {
		t.Fatalf("criteria = %t/%t/%t, want all met", metrics.ZeroResidualCriterionMet, metrics.FullRuntimeCriterionMet, metrics.ReducedRuntimeCriterionMet)
	}
	got, err := json.MarshalIndent(metrics, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	want, err := os.ReadFile("../../../fixtures/metrics/residual-metrics.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("committed residual metrics do not match regenerated runtime fixtures")
	}
}
