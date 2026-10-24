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

// caliper-ci-report evaluates either a target-cluster measurement for a pull
// request comment or the committed cell fingerprints for the six-cell metric.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Abhinavmadake/caliper/control"
	"github.com/google/go-github/v68/github"
	"golang.org/x/oauth2"
)

const reportMarker = "<!-- caliper-ci-cell-report -->"

func main() {
	var fingerprintPaths, clusters stringListFlag
	flag.Var(&fingerprintPaths, "fingerprint", "path to a target-cluster measurement JSON (repeat for multiple cells)")
	flag.Var(&clusters, "cluster", "named target cluster context, in the same order as -fingerprint (repeat for multiple cells)")
	cellFixtures := flag.String("cell-fixtures", "", "directory of committed cellN.json fingerprints for the six-cell metric")
	metricsOut := flag.String("metrics-out", "", "write the six-cell finding metric JSON to this path")
	repository := flag.String("repository", "", "GitHub repository in owner/name form")
	prNumber := flag.Int("pr", 0, "pull request number")
	in := inputs{}
	flag.StringVar(&in.posture, "posture", "../posture/v1/posture.yaml", "reference posture YAML")
	flag.StringVar(&in.corpus, "corpus", "../corpus/index.json", "corpus index JSON")
	flag.StringVar(&in.manifest, "manifest", "../deploy/k8s/job.yaml", "manifest of the measured workload")
	flag.StringVar(&in.tier, "tier", "restricted", "posture tier to evaluate against")
	flag.Parse()

	if *cellFixtures != "" {
		if err := runCellMetrics(*cellFixtures, *metricsOut, in); err != nil {
			fmt.Fprintln(os.Stderr, "caliper-ci-report:", err)
			os.Exit(1)
		}
		return
	}
	if err := runMany(fingerprintPaths, clusters, *repository, *prNumber, in); err != nil {
		fmt.Fprintln(os.Stderr, "caliper-ci-report:", err)
		os.Exit(1)
	}
}

type inputs struct {
	posture, corpus, manifest, tier string
}

type evaluation struct {
	fingerprint control.Fingerprint
	workload    control.ManifestWorkload
	report      control.Report
}

type cellFindingMetrics struct {
	PostureRevision           string                `json:"posture_revision"`
	Tier                      string                `json:"tier"`
	FingerprintsEvaluated     int                   `json:"fingerprints_evaluated"`
	DistinctCells             int                   `json:"distinct_cells"`
	ExpectationViolationCells int                   `json:"expectation_violation_cells"`
	ThreeCellCriterionMet     bool                  `json:"three_cell_criterion_met"`
	CategoryTotals            findingCategoryTotals `json:"category_totals"`
	Cells                     []cellFindingMetric   `json:"cells"`
}

type findingCategoryTotals struct {
	ExpectationViolations int `json:"expectation_violations"`
	ClaimViolations       int `json:"claim_violations"`
	UndeclaredExposures   int `json:"undeclared_exposures"`
}

type cellFindingMetric struct {
	CellID                string                `json:"cell_id"`
	Fingerprint           string                `json:"fingerprint"`
	Cell                  control.Cell          `json:"cell"`
	CategoryCounts        findingCategoryTotals `json:"category_counts"`
	ExpectationViolations []control.Finding     `json:"expectation_violations"`
	ClaimViolations       []control.Finding     `json:"claim_violations"`
	UndeclaredExposures   []control.Finding     `json:"undeclared_exposures"`
}

type stringListFlag []string

func (values *stringListFlag) String() string { return strings.Join(*values, ",") }
func (values *stringListFlag) Set(value string) error {
	*values = append(*values, value)
	return nil
}

func runMany(fingerprintPaths, clusters []string, repository string, prNumber int, in inputs) error {
	if len(fingerprintPaths) == 0 || len(clusters) == 0 || prNumber < 1 {
		return errors.New("at least one fingerprint, its cluster context, and a positive PR number are required")
	}
	if len(fingerprintPaths) != len(clusters) {
		return errors.New("each -fingerprint must have one corresponding -cluster, in the same order")
	}
	for i := range fingerprintPaths {
		if strings.TrimSpace(fingerprintPaths[i]) == "" || strings.TrimSpace(clusters[i]) == "" {
			return errors.New("fingerprint paths and cluster contexts cannot be empty")
		}
	}
	parts := strings.Split(repository, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return errors.New("repository must be owner/name")
	}
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return errors.New("GITHUB_TOKEN is required to post the PR report")
	}

	evaluations := make([]evaluation, 0, len(fingerprintPaths))
	for i, fingerprintPath := range fingerprintPaths {
		measurement, err := readMeasurement(fingerprintPath)
		if err != nil {
			return fmt.Errorf("read fingerprint %q: %w", fingerprintPath, err)
		}
		ev, err := evaluate(measurement, in)
		if err != nil {
			return fmt.Errorf("evaluate cell %q: %w", clusters[i], err)
		}
		evaluations = append(evaluations, ev)
	}
	var body string
	if len(evaluations) == 1 {
		body = renderReport(clusters[0], evaluations[0])
	} else {
		body = renderReportMany(evaluations)
	}
	ctx := context.Background()
	client := github.NewClient(oauth2.NewClient(ctx, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})))
	if err := upsertComment(ctx, client, parts[0], parts[1], prNumber, body); err != nil {
		return fmt.Errorf("post pull-request report: %w", err)
	}
	fmt.Print(body)
	return nil
}

func runCellMetrics(fixturesDir, outputPath string, in inputs) error {
	paths, err := filepath.Glob(filepath.Join(fixturesDir, "cell[1-6].json"))
	if err != nil {
		return fmt.Errorf("list cell fingerprints: %w", err)
	}
	if len(paths) != 6 {
		return fmt.Errorf("cell fixtures directory %s has %d cell1-cell6 fingerprints, want 6", fixturesDir, len(paths))
	}
	evaluations := make([]evaluation, 0, len(paths))
	sources := make([]string, 0, len(paths))
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read cell fingerprint %s: %w", path, err)
		}
		fingerprint, err := control.DecodeFingerprint(data)
		if err != nil {
			return fmt.Errorf("decode cell fingerprint %s: %w", path, err)
		}
		ev, err := evaluate(fingerprint, in)
		if err != nil {
			return fmt.Errorf("evaluate cell fingerprint %s: %w", path, err)
		}
		evaluations = append(evaluations, ev)
		sources = append(sources, filepath.Base(path))
	}
	metrics, err := buildCellMetrics(evaluations, sources)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(metrics, "", "  ")
	if err != nil {
		return fmt.Errorf("encode cell finding metrics: %w", err)
	}
	data = append(data, '\n')
	if outputPath == "" {
		_, err = os.Stdout.Write(data)
		return err
	}
	if err := os.WriteFile(outputPath, data, 0o644); err != nil {
		return fmt.Errorf("write cell finding metrics: %w", err)
	}
	return nil
}

func buildCellMetrics(evaluations []evaluation, sources []string) (cellFindingMetrics, error) {
	if len(evaluations) == 0 || len(evaluations) != len(sources) {
		return cellFindingMetrics{}, errors.New("cell evaluations and source names must have the same non-zero length")
	}
	metrics := cellFindingMetrics{
		PostureRevision:       evaluations[0].report.Findings.PostureRevision,
		Tier:                  evaluations[0].report.Findings.Tier,
		FingerprintsEvaluated: len(evaluations),
		Cells:                 make([]cellFindingMetric, 0, len(evaluations)),
	}
	distinctCells := map[string]struct{}{}
	expectationCells := map[string]struct{}{}
	for i, ev := range evaluations {
		id, err := cellIdentityChecked(ev.fingerprint.Cell)
		if err != nil {
			return cellFindingMetrics{}, fmt.Errorf("identify cell in %s: %w", sources[i], err)
		}
		distinctCells[id] = struct{}{}
		findings := ev.report.Findings
		if len(findings.ExpectationViolations) > 0 {
			expectationCells[id] = struct{}{}
		}
		metrics.CategoryTotals.ExpectationViolations += len(findings.ExpectationViolations)
		metrics.CategoryTotals.ClaimViolations += len(findings.ClaimViolations)
		metrics.CategoryTotals.UndeclaredExposures += len(findings.UndeclaredExposures)
		metrics.Cells = append(metrics.Cells, cellFindingMetric{
			CellID:      id,
			Fingerprint: sources[i],
			Cell:        ev.fingerprint.Cell,
			CategoryCounts: findingCategoryTotals{
				ExpectationViolations: len(findings.ExpectationViolations),
				ClaimViolations:       len(findings.ClaimViolations),
				UndeclaredExposures:   len(findings.UndeclaredExposures),
			},
			ExpectationViolations: findings.ExpectationViolations,
			ClaimViolations:       findings.ClaimViolations,
			UndeclaredExposures:   findings.UndeclaredExposures,
		})
	}
	metrics.DistinctCells = len(distinctCells)
	metrics.ExpectationViolationCells = len(expectationCells)
	metrics.ThreeCellCriterionMet = metrics.ExpectationViolationCells >= 3
	return metrics, nil
}

// cellIdentity hashes the complete cell object so the identifier stays tied
// to measured cell properties instead of a cluster context or fingerprint digest.
func cellIdentity(cell control.Cell) string {
	identity, _ := cellIdentityChecked(cell)
	return identity
}

func cellIdentityChecked(cell control.Cell) (string, error) {
	data, err := json.Marshal(cell)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return "cell-" + hex.EncodeToString(digest[:6]), nil
}

func renderReportMany(evaluations []evaluation) string {
	var b strings.Builder
	b.WriteString(reportMarker + "\n")
	b.WriteString("## CALIPER target-cluster evaluation\n\n")
	violatingCells := map[string]bool{}
	cellIDs := make([]string, len(evaluations))
	for i, ev := range evaluations {
		cellIDs[i] = cellIdentity(ev.fingerprint.Cell)
		findings := ev.report.Findings
		if len(findings.ExpectationViolations) > 0 {
			violatingCells[cellIDs[i]] = true
		}
	}
	criterion := "not met"
	if len(violatingCells) >= 3 {
		criterion = "met"
	}
	fmt.Fprintf(&b, "**Cells evaluated:** %d  \n**Cells with expectation violations:** %d  \n**Three-cell criterion:** %s (requires expectation violations in at least 3 distinct cells)\n\n", len(evaluations), len(violatingCells), criterion)
	b.WriteString("| Cell | Expectation violations | Claim violations | Undeclared exposures |\n|---|---:|---:|---:|\n")
	for i, ev := range evaluations {
		f := ev.report.Findings
		fmt.Fprintf(&b, "| `%s` | %d | %d | %d |\n", cellIDs[i], len(f.ExpectationViolations), len(f.ClaimViolations), len(f.UndeclaredExposures))
	}
	b.WriteString("\n")
	for i, ev := range evaluations {
		fp, findings, attribution := ev.fingerprint, ev.report.Findings, ev.report.Attribution
		fmt.Fprintf(&b, "### Cell: `%s`\n\n**Architecture:** `%s`  \n**Kernel:** `%s`  \n**Corpus:** `%s` revision `%s`  \n**Posture:** `%s`, tier `%s`, workload `%s/%s`\n\n",
			cellIDs[i], fp.Cell.Architecture, fp.Cell.Kernel.Release, fp.CorpusSet, fp.CorpusRevision,
			findings.PostureRevision, findings.Tier, ev.workload.Kind, ev.workload.Name)
		writeFindings(&b, "Expectation violations", findings.ExpectationViolations)
		writeFindings(&b, "Claim violations", findings.ClaimViolations)
		writeExposures(&b, findings.UndeclaredExposures)
		if attribution.UndecidableFraction == nil {
			b.WriteString("Attribution: no denials.\n\n")
		} else {
			fmt.Fprintf(&b, "Attribution: undecidable %d/%d denials (%.1f%%).\n\n", attribution.Undecidable, attribution.Denials, *attribution.UndecidableFraction*100)
		}
	}
	b.WriteString(control.AuthorizationNotice + "\n")
	return b.String()
}

// kubectl logs combines the container's stdout and stderr. The probe prints
// human-readable diagnostics to stderr before emitting the JSON measurement
// on stdout, so scan for the first valid measurement object in the log stream.
func readMeasurement(path string) (control.Fingerprint, error) {
	var measurement control.Fingerprint
	data, err := os.ReadFile(path)
	if err != nil {
		return measurement, err
	}
	for start, b := range data {
		if b != '{' {
			continue
		}
		candidate, err := control.DecodeFingerprint(data[start:])
		if err == nil && candidate.CorpusSet == "reduced" {
			return candidate, nil
		}
	}
	return measurement, errors.New("no CALIPER measurement JSON found in container logs")
}

func evaluate(fp control.Fingerprint, in inputs) (evaluation, error) {
	var corpus []control.ProbeMetadata
	data, err := os.ReadFile(in.corpus)
	if err != nil {
		return evaluation{}, fmt.Errorf("read corpus: %w", err)
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		return evaluation{}, fmt.Errorf("parse corpus: %w", err)
	}
	data, err = os.ReadFile(in.posture)
	if err != nil {
		return evaluation{}, fmt.Errorf("read posture: %w", err)
	}
	posture, err := control.ParsePosture(data)
	if err != nil {
		return evaluation{}, err
	}
	data, err = os.ReadFile(in.manifest)
	if err != nil {
		return evaluation{}, fmt.Errorf("read manifest: %w", err)
	}
	manifest, err := control.ParseManifest(data)
	if err != nil {
		return evaluation{}, err
	}
	if len(manifest.Workloads) != 1 {
		return evaluation{}, fmt.Errorf("manifest %s has %d workloads, want 1", in.manifest, len(manifest.Workloads))
	}
	workload := manifest.Workloads[0]

	fp, err = control.Attribute(fp, corpus)
	if err != nil {
		return evaluation{}, fmt.Errorf("attribute: %w", err)
	}
	findings, err := control.EvaluateFindings(fp, workload, in.tier, posture, corpus)
	if err != nil {
		return evaluation{}, fmt.Errorf("evaluate: %w", err)
	}
	report, err := control.BuildReport(findings, control.ClassificationResult{}, fp)
	if err != nil {
		return evaluation{}, err
	}
	return evaluation{fingerprint: fp, workload: workload, report: report}, nil
}

func renderReport(cluster string, ev evaluation) string {
	fp, findings, attribution := ev.fingerprint, ev.report.Findings, ev.report.Attribution
	var b strings.Builder
	b.WriteString(reportMarker + "\n")
	b.WriteString("## CALIPER target-cluster evaluation\n\n")
	fmt.Fprintf(&b, "**Target:** `%s`  \n**Cell:** `%s`, kernel `%s`  \n**Corpus:** `%s` revision `%s`  \n",
		cluster, fp.Cell.Architecture, fp.Cell.Kernel.Release, fp.CorpusSet, fp.CorpusRevision)
	fmt.Fprintf(&b, "**Posture:** `%s`, tier `%s`, workload `%s/%s`\n\n",
		findings.PostureRevision, findings.Tier, ev.workload.Kind, ev.workload.Name)

	writeFindings(&b, "Expectation violations", findings.ExpectationViolations)
	writeFindings(&b, "Claim violations", findings.ClaimViolations)
	writeExposures(&b, findings.UndeclaredExposures)

	b.WriteString("### Attribution\n\n")
	if attribution.UndecidableFraction == nil {
		b.WriteString("No denials.\n\n")
	} else {
		fmt.Fprintf(&b, "Undecidable: %d/%d denials (%.1f%%). Confidence: high %d, medium %d, low %d, unknown %d.\n\n",
			attribution.Undecidable, attribution.Denials, *attribution.UndecidableFraction*100,
			attribution.ConfidenceCounts.High, attribution.ConfidenceCounts.Medium,
			attribution.ConfidenceCounts.Low, attribution.ConfidenceCounts.Unknown)
	}

	fmt.Fprintf(&b, "<details><summary>%d measured probe(s), %d unmeasured</summary>\n\n", len(fp.Results), len(fp.Unmeasured))
	b.WriteString("| Probe | Verdict | Errno | Mechanism |\n|---|---|---|---|\n")
	for _, result := range fp.Results {
		mechanism := ""
		if result.Attribution != nil && result.Attribution.Mechanism != nil {
			mechanism = string(*result.Attribution.Mechanism)
		}
		fmt.Fprintf(&b, "| `%s` | `%s` | %d | %s |\n", result.ProbeID, result.Verdict, result.Errno, mechanism)
	}
	b.WriteString("\n</details>\n\n")
	b.WriteString(control.AuthorizationNotice + "\n")
	return b.String()
}

func writeFindings(b *strings.Builder, title string, findings []control.Finding) {
	fmt.Fprintf(b, "### %s (%d)\n\n", title, len(findings))
	if len(findings) == 0 {
		return
	}
	b.WriteString("| Probe | Family | Reason | Evidence |\n|---|---|---|---|\n")
	for _, f := range findings {
		reason := strings.ReplaceAll(strings.Join(strings.Fields(f.Reason), " "), "|", "\\|")
		fmt.Fprintf(b, "| `%s` | %s | %s | %s |\n", f.ProbeID, f.Family, reason, citationLinks(f.Citations))
	}
	b.WriteString("\n")
}

func citationLinks(citations []control.PostureCitation) string {
	links := make([]string, 0, len(citations))
	for _, citation := range citations {
		label := citation.ID
		if label == "" {
			label = citation.Title
		}
		if label == "" {
			label = citation.URL
		}
		links = append(links, fmt.Sprintf("[%s](%s)", label, citation.URL))
	}
	return strings.Join(links, ", ")
}

// Undeclared exposures share one reason, so they are listed per family.
func writeExposures(b *strings.Builder, findings []control.Finding) {
	fmt.Fprintf(b, "### Undeclared exposures (%d)\n\n", len(findings))
	if len(findings) == 0 {
		return
	}
	b.WriteString("Permitted, and neither the posture tier nor the manifest declares them unreachable.\n\n")
	byFamily := map[string][]string{}
	var families []string
	for _, f := range findings {
		if _, seen := byFamily[f.Family]; !seen {
			families = append(families, f.Family)
		}
		byFamily[f.Family] = append(byFamily[f.Family], "`"+f.ProbeID+"`")
	}
	sort.Strings(families)
	for _, family := range families {
		fmt.Fprintf(b, "- **%s** (%d): %s\n", family, len(byFamily[family]), strings.Join(byFamily[family], ", "))
	}
	b.WriteString("\n")
}

func upsertComment(ctx context.Context, client *github.Client, owner, repo string, pr int, body string) error {
	page := 1
	for {
		comments, response, err := client.Issues.ListComments(ctx, owner, repo, pr, &github.IssueListCommentsOptions{
			ListOptions: github.ListOptions{Page: page, PerPage: 100},
		})
		if err != nil {
			return err
		}
		for _, comment := range comments {
			if comment.GetUser().GetLogin() == "github-actions[bot]" && strings.Contains(comment.GetBody(), reportMarker) {
				_, _, err := client.Issues.EditComment(ctx, owner, repo, comment.GetID(), &github.IssueComment{Body: github.Ptr(body)})
				return err
			}
		}
		if response.NextPage == 0 {
			break
		}
		page = response.NextPage
	}
	_, _, err := client.Issues.CreateComment(ctx, owner, repo, pr, &github.IssueComment{Body: github.Ptr(body)})
	return err
}
