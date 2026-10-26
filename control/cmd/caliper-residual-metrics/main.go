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

// caliper-residual-metrics computes the proposal's residual-state and
// runtime-cost metrics (#46) from the runs in fixtures/runtime.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/Abhinavmadake/caliper/control"
)

// The six classes of §6.2, as the engine keys them.
var classes = []string{"mounts", "keyrings", "cgroups", "sysv_ipc", "posix_ipc", "net_namespaces"}

const (
	fullLimitMS    = 60_000
	reducedLimitMS = 5_000
)

func main() {
	fixtures := flag.String("fixtures", "../fixtures/runtime", "directory of run fingerprints")
	corpusPath := flag.String("corpus", "../corpus/index.json", "probe corpus index JSON")
	output := flag.String("out", "", "write metrics JSON to this path instead of stdout")
	flag.Parse()
	if flag.NArg() != 0 {
		fail(fmt.Errorf("unexpected argument %q", flag.Arg(0)))
	}
	metrics, err := computeMetrics(*fixtures, *corpusPath)
	if err != nil {
		fail(err)
	}
	data, err := json.MarshalIndent(metrics, "", "  ")
	if err != nil {
		fail(fmt.Errorf("encode residual metrics: %w", err))
	}
	data = append(data, '\n')
	if *output == "" {
		if _, err := os.Stdout.Write(data); err != nil {
			fail(err)
		}
		return
	}
	if err := os.WriteFile(*output, data, 0o644); err != nil {
		fail(fmt.Errorf("write residual metrics: %w", err))
	}
}

type residualMetrics struct {
	Runs               []runMetrics `json:"runs"`
	UnreclaimedObjects int64        `json:"unreclaimed_objects"`
	// Objects that outlived one probe, even where a later probe removed them.
	Leaks                    int  `json:"leaks"`
	ZeroResidualCriterionMet bool `json:"zero_residual_criterion_met"`
	// Classes no run could count, which the zero above does not cover.
	ClassesNeverObserved []string `json:"classes_never_observed"`
	// Classes some run created objects in: elsewhere zero means nothing
	// was made, not that something was reclaimed.
	ClassesExercised           []string `json:"classes_exercised"`
	SlowestFullMS              *uint64  `json:"slowest_full_ms"`
	SlowestReducedMS           *uint64  `json:"slowest_reduced_ms"`
	FullRuntimeCriterionMet    bool     `json:"full_runtime_criterion_met"`
	ReducedRuntimeCriterionMet bool     `json:"reduced_runtime_criterion_met"`
}

type runMetrics struct {
	Fingerprint     string                  `json:"fingerprint"`
	CorpusSet       string                  `json:"corpus_set"`
	ElapsedMS       uint64                  `json:"elapsed_ms"`
	Classes         map[string]classMetrics `json:"classes"`
	Leaks           int                     `json:"leaks"`
	AuditMismatches int                     `json:"audit_mismatches"`
	JanitorRemovals int                     `json:"janitor_removals"`
	// Run-level growth summed over the observed classes.
	Unreclaimed int64 `json:"unreclaimed_objects"`
	// Reported, never counted: the container cannot unload a module (§6.2).
	ModulesLoadedByRun []string `json:"modules_loaded_by_run"`
}

type classMetrics struct {
	Observed bool `json:"observed"`
	// After minus before, where both were counted.
	Delta *int64 `json:"delta"`
	// Permitted probes that declare the class, so made an object in it.
	PermittedDeclaring int `json:"permitted_declaring"`
}

type residual struct {
	Observability map[string]json.RawMessage `json:"observability"`
	Before        map[string]*int64          `json:"before"`
	After         map[string]*int64          `json:"after"`
	Leaks         []json.RawMessage          `json:"leaks"`
	Audit         []json.RawMessage          `json:"audit"`
	Janitor       []json.RawMessage          `json:"janitor"`
}

type moduleDelta struct {
	LoadedByRun []string `json:"loaded_by_run"`
}

type corpusEffects struct {
	ID      string `json:"id"`
	Effects struct {
		Residual []string `json:"residual"`
	} `json:"effects"`
}

// The corpus spells classes as values (kebab-case), the residual report as
// keys (snake_case).
var classValues = map[string]string{
	"mounts": "mounts", "keyrings": "keyrings", "cgroups": "cgroups",
	"sysv-ipc": "sysv_ipc", "posix-ipc": "posix_ipc", "net-namespaces": "net_namespaces",
}

func computeMetrics(fixturesDir, corpusPath string) (residualMetrics, error) {
	corpusData, err := os.ReadFile(corpusPath)
	if err != nil {
		return residualMetrics{}, fmt.Errorf("read corpus: %w", err)
	}
	var corpus []corpusEffects
	if err := json.Unmarshal(corpusData, &corpus); err != nil {
		return residualMetrics{}, fmt.Errorf("parse corpus: %w", err)
	}
	declares := map[string][]string{}
	for _, p := range corpus {
		for _, value := range p.Effects.Residual {
			class, ok := classValues[value]
			if !ok {
				return residualMetrics{}, fmt.Errorf("probe %s declares unknown residual class %q", p.ID, value)
			}
			declares[p.ID] = append(declares[p.ID], class)
		}
	}

	paths, err := filepath.Glob(filepath.Join(fixturesDir, "*.json"))
	if err != nil {
		return residualMetrics{}, err
	}
	sort.Strings(paths)
	metrics := residualMetrics{ClassesNeverObserved: []string{}, ClassesExercised: []string{}}
	observed, exercised := map[string]bool{}, map[string]bool{}
	for _, path := range paths {
		run, err := runFrom(path, declares)
		if err != nil {
			return residualMetrics{}, err
		}
		for class, c := range run.Classes {
			observed[class] = observed[class] || c.Observed
			exercised[class] = exercised[class] || (c.Observed && c.PermittedDeclaring > 0)
		}
		metrics.UnreclaimedObjects += run.Unreclaimed
		metrics.Leaks += run.Leaks
		slowest := &metrics.SlowestFullMS
		if run.CorpusSet == "reduced" {
			slowest = &metrics.SlowestReducedMS
		}
		if *slowest == nil || run.ElapsedMS > **slowest {
			elapsed := run.ElapsedMS
			*slowest = &elapsed
		}
		metrics.Runs = append(metrics.Runs, run)
	}
	if metrics.SlowestFullMS == nil || metrics.SlowestReducedMS == nil {
		return residualMetrics{}, errors.New("runtime metric needs at least one full and one reduced run")
	}
	for _, class := range classes {
		if !observed[class] {
			metrics.ClassesNeverObserved = append(metrics.ClassesNeverObserved, class)
		}
		if exercised[class] {
			metrics.ClassesExercised = append(metrics.ClassesExercised, class)
		}
	}
	metrics.ZeroResidualCriterionMet = metrics.UnreclaimedObjects == 0 && metrics.Leaks == 0
	metrics.FullRuntimeCriterionMet = *metrics.SlowestFullMS < fullLimitMS
	metrics.ReducedRuntimeCriterionMet = *metrics.SlowestReducedMS < reducedLimitMS
	return metrics, nil
}

func runFrom(path string, declares map[string][]string) (runMetrics, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return runMetrics{}, fmt.Errorf("read run fingerprint %s: %w", path, err)
	}
	fp, err := control.DecodeFingerprint(data)
	if err != nil {
		return runMetrics{}, fmt.Errorf("decode run fingerprint %s: %w", path, err)
	}
	name := filepath.Base(path)
	if fp.ElapsedMS == nil {
		return runMetrics{}, fmt.Errorf("%s has no elapsed_ms", name)
	}
	if fp.CorpusSet != "full" && fp.CorpusSet != "reduced" {
		return runMetrics{}, fmt.Errorf("%s has corpus_set %q", name, fp.CorpusSet)
	}
	var r residual
	if err := json.Unmarshal(fp.Residual, &r); err != nil {
		return runMetrics{}, fmt.Errorf("decode residual of %s: %w", name, err)
	}
	run := runMetrics{
		Fingerprint:        name,
		CorpusSet:          fp.CorpusSet,
		ElapsedMS:          *fp.ElapsedMS,
		Classes:            map[string]classMetrics{},
		Leaks:              len(r.Leaks),
		AuditMismatches:    len(r.Audit),
		JanitorRemovals:    len(r.Janitor),
		ModulesLoadedByRun: []string{},
	}
	for _, class := range classes {
		c := classMetrics{Observed: string(r.Observability[class]) == `"observed"`}
		if before, after := r.Before[class], r.After[class]; c.Observed && before != nil && after != nil {
			delta := *after - *before
			c.Delta = &delta
			if delta > 0 {
				run.Unreclaimed += delta
			}
		}
		run.Classes[class] = c
	}
	for _, result := range fp.Results {
		if result.Verdict != "permitted" {
			continue
		}
		for _, class := range declares[result.ProbeID] {
			c := run.Classes[class]
			c.PermittedDeclaring++
			run.Classes[class] = c
		}
	}
	if len(fp.ModuleDelta) > 0 {
		var delta moduleDelta
		if err := json.Unmarshal(fp.ModuleDelta, &delta); err != nil {
			return runMetrics{}, fmt.Errorf("decode module_delta of %s: %w", name, err)
		}
		if delta.LoadedByRun != nil {
			run.ModulesLoadedByRun = delta.LoadedByRun
		}
	}
	return run, nil
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "caliper-residual-metrics:", err)
	os.Exit(1)
}
