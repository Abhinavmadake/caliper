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

// caliper-ci-report evaluates a measured target-cluster fingerprint against the
// reference posture and posts the result as an idempotent GitHub PR comment.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
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
	repository := flag.String("repository", "", "GitHub repository in owner/name form")
	prNumber := flag.Int("pr", 0, "pull request number")
	in := inputs{}
	flag.StringVar(&in.posture, "posture", "../posture/v1/posture.yaml", "reference posture YAML")
	flag.StringVar(&in.corpus, "corpus", "../corpus/index.json", "corpus index JSON")
	flag.StringVar(&in.manifest, "manifest", "../deploy/k8s/job.yaml", "manifest of the measured workload")
	flag.StringVar(&in.tier, "tier", "restricted", "posture tier to evaluate against")
	flag.Parse()

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

type stringListFlag []string

func (values *stringListFlag) String() string { return strings.Join(*values, ",") }
func (values *stringListFlag) Set(value string) error {
	*values = append(*values, value)
	return nil
}

func run(fingerprintPath, cluster, repository string, prNumber int, in inputs) error {
	return runMany([]string{fingerprintPath}, []string{cluster}, repository, prNumber, in)
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
	body := renderReportMany(clusters, evaluations)
	ctx := context.Background()
	client := github.NewClient(oauth2.NewClient(ctx, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})))
	if err := upsertComment(ctx, client, parts[0], parts[1], prNumber, body); err != nil {
		return fmt.Errorf("post pull-request report: %w", err)
	}
	fmt.Print(body)
	return nil
}

func renderReportMany(clusters []string, evaluations []evaluation) string {
	if len(evaluations) == 1 && len(clusters) == 1 {
		return renderReport(clusters[0], evaluations[0])
	}
	var b strings.Builder
	b.WriteString(reportMarker + "\n")
	b.WriteString("## CALIPER target-cluster evaluation\n\n")
	violatingCells := map[string]bool{}
	for i, ev := range evaluations {
		findings := ev.report.Findings
		if len(findings.ExpectationViolations) > 0 {
			violatingCells[clusters[i]] = true
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
		fmt.Fprintf(&b, "| `%s` | %d | %d | %d |\n", clusters[i], len(f.ExpectationViolations), len(f.ClaimViolations), len(f.UndeclaredExposures))
	}
	b.WriteString("\n")
	for i, ev := range evaluations {
		fp, findings, attribution := ev.fingerprint, ev.report.Findings, ev.report.Attribution
		fmt.Fprintf(&b, "### Cell: `%s`\n\n**Architecture:** `%s`  \n**Kernel:** `%s`  \n**Corpus:** `%s` revision `%s`  \n**Posture:** `%s`, tier `%s`, workload `%s/%s`\n\n",
			clusters[i], fp.Cell.Architecture, fp.Cell.Kernel.Release, fp.CorpusSet, fp.CorpusRevision,
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
