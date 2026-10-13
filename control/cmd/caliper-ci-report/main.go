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

// caliper-ci-report evaluates the measured target-cluster cell against the
// selected reference posture and posts an idempotent GitHub PR comment.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/google/go-github/v68/github"
	"golang.org/x/oauth2"
	"gopkg.in/yaml.v3"
)

const reportMarker = "<!-- caliper-ci-cell-report -->"

type fingerprint struct {
	FormatVersion  int           `json:"format_version"`
	CorpusRevision string        `json:"corpus_revision"`
	CorpusSet      string        `json:"corpus_set"`
	Cell           cell          `json:"cell"`
	Results        []probeResult `json:"results"`
	Unmeasured     []unmeasured  `json:"unmeasured"`
}

type cell struct {
	Architecture string `json:"architecture"`
	Kernel       struct {
		Release string `json:"release"`
	} `json:"kernel"`
}

type probeResult struct {
	ProbeID string `json:"probe_id"`
	Verdict string `json:"verdict"`
}

type unmeasured struct {
	ProbeID string `json:"probe_id"`
	Why     any    `json:"why"`
}

type posture struct {
	Revision   string      `yaml:"posture_revision"`
	Assertions []assertion `yaml:"assertions"`
}

type assertion struct {
	Tier     string   `yaml:"tier"`
	Family   string   `yaml:"family"`
	ProbeIDs []string `yaml:"probe_ids"`
	Expect   string   `yaml:"expect"`
}

type corpusProbe struct {
	ID     string `json:"id"`
	Family string `json:"family"`
}

type corpusIndex []corpusProbe

type finding struct {
	ProbeID string
	Family  string
	Verdict string
	Status  string
}

func main() {
	fingerprintPath := flag.String("fingerprint", "", "path to the target-cluster measurement JSON")
	posturePath := flag.String("posture", "", "path to the posture YAML")
	corpusPath := flag.String("corpus", "", "path to the compiled corpus index JSON")
	cluster := flag.String("cluster", "", "named target cluster context")
	repository := flag.String("repository", "", "GitHub repository in owner/name form")
	prNumber := flag.Int("pr", 0, "pull request number")
	flag.Parse()

	if err := run(*fingerprintPath, *posturePath, *corpusPath, *cluster, *repository, *prNumber); err != nil {
		fmt.Fprintln(os.Stderr, "caliper-ci-report:", err)
		os.Exit(1)
	}
}

func run(fingerprintPath, posturePath, corpusPath, cluster, repository string, prNumber int) error {
	if fingerprintPath == "" || posturePath == "" || corpusPath == "" || cluster == "" || prNumber < 1 {
		return errors.New("fingerprint, posture, corpus, cluster and positive PR number are required")
	}
	parts := strings.Split(repository, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return errors.New("repository must be owner/name")
	}
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return errors.New("GITHUB_TOKEN is required to post the PR report")
	}

	measurement, err := readMeasurement(fingerprintPath)
	if err != nil {
		return fmt.Errorf("read fingerprint: %w", err)
	}
	postureDoc, err := readYAML[posture](posturePath)
	if err != nil {
		return fmt.Errorf("read posture: %w", err)
	}
	corpus, err := readJSON[corpusIndex](corpusPath)
	if err != nil {
		return fmt.Errorf("read corpus index: %w", err)
	}
	if measurement.CorpusSet != "reduced" {
		return fmt.Errorf("target measurement corpus_set is %q, expected reduced", measurement.CorpusSet)
	}

	findings, err := evaluate(measurement, postureDoc, corpus)
	if err != nil {
		return err
	}
	body := renderReport(cluster, measurement, postureDoc.Revision, findings)
	ctx := context.Background()
	client := github.NewClient(oauth2.NewClient(ctx, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})))
	if err := upsertComment(ctx, client, parts[0], parts[1], prNumber, body); err != nil {
		return fmt.Errorf("post pull-request report: %w", err)
	}
	fmt.Print(body)
	return nil
}

// kubectl logs combines the container's stdout and stderr. The probe prints
// human-readable diagnostics to stderr before emitting the JSON measurement
// on stdout, so scan for the first valid measurement object in the log stream.
func readMeasurement(path string) (fingerprint, error) {
	var measurement fingerprint
	data, err := os.ReadFile(path)
	if err != nil {
		return measurement, err
	}
	for start, b := range data {
		if b != '{' {
			continue
		}
		decoder := json.NewDecoder(bytes.NewReader(data[start:]))
		var candidate fingerprint
		if decoder.Decode(&candidate) == nil && candidate.FormatVersion > 0 && candidate.CorpusSet != "" {
			return candidate, nil
		}
	}
	return measurement, errors.New("no CALIPER measurement JSON found in container logs")
}

func readJSON[T any](path string) (T, error) {
	var value T
	data, err := os.ReadFile(path)
	if err != nil {
		return value, err
	}
	err = json.Unmarshal(data, &value)
	return value, err
}

func readYAML[T any](path string) (T, error) {
	var value T
	data, err := os.ReadFile(path)
	if err != nil {
		return value, err
	}
	err = yaml.Unmarshal(data, &value)
	return value, err
}

func evaluate(fp fingerprint, p posture, corpus corpusIndex) ([]finding, error) {
	families := make(map[string]string, len(corpus))
	for _, probe := range corpus {
		families[probe.ID] = probe.Family
	}
	results := make(map[string]string, len(fp.Results))
	for _, result := range fp.Results {
		results[result.ProbeID] = result.Verdict
	}
	measuredAbsent := make(map[string]bool, len(fp.Unmeasured))
	for _, result := range fp.Unmeasured {
		measuredAbsent[result.ProbeID] = true
	}

	var findings []finding
	for _, rule := range p.Assertions {
		// The CI workload is treated as untrusted multi-tenant code. Assertions
		// at baseline/restricted flow down to this strongest tier; privileged
		// assertions do not.
		if rule.Tier == "privileged" || rule.Expect != "unreachable" {
			continue
		}
		ids := append([]string(nil), rule.ProbeIDs...)
		if len(ids) == 0 {
			for id, family := range families {
				if family == rule.Family {
					ids = append(ids, id)
				}
			}
		}
		if len(ids) == 0 {
			findings = append(findings, finding{Family: rule.Family, Status: "not measured"})
			continue
		}
		sort.Strings(ids)
		for _, id := range ids {
			verdict, ok := results[id]
			status := "unknown"
			switch verdict {
			case "permitted":
				status = "violation"
			case "denied", "killed", "unimplemented":
				status = "satisfied"
			case "not-applicable":
				status = "not applicable"
			case "timed-out":
				status = "timed out"
			}
			if !ok {
				if _, inCorpus := families[id]; !inCorpus {
					return nil, fmt.Errorf("posture references probe %q absent from corpus index", id)
				}
				if measuredAbsent[id] {
					status = "not measured"
				}
			}
			findings = append(findings, finding{ProbeID: id, Family: families[id], Verdict: verdict, Status: status})
		}
	}
	return findings, nil
}

func renderReport(cluster string, fp fingerprint, revision string, findings []finding) string {
	var b strings.Builder
	b.WriteString(reportMarker + "\n")
	fmt.Fprintf(&b, "## CALIPER target-cluster evaluation\n\n")
	fmt.Fprintf(&b, "**Target:** `%s`  \n**Cell:** `%s`, kernel `%s`  \n**Corpus:** `%s` revision `%s`  \n**Posture:** `%s`\n\n",
		cluster, fp.Cell.Architecture, fp.Cell.Kernel.Release, fp.CorpusSet, fp.CorpusRevision, revision)
	b.WriteString("| Probe | Family | Verdict | Evaluation |\n|---|---|---|---|\n")
	violations, unknown := 0, 0
	for _, item := range findings {
		if item.Status == "violation" {
			violations++
		}
		if item.Status == "unknown" || item.Status == "timed out" || item.Status == "not measured" {
			unknown++
		}
		probeID := item.ProbeID
		if probeID == "" {
			probeID = "(family assertion)"
		}
		verdict := item.Verdict
		if verdict == "" {
			verdict = "—"
		}
		fmt.Fprintf(&b, "| `%s` | `%s` | `%s` | **%s** |\n", probeID, item.Family, verdict, item.Status)
	}
	fmt.Fprintf(&b, "\n**Summary:** %d posture violation(s), %d unknown/not measured assertion(s), %d evaluated probe assertion(s).\n",
		violations, unknown, len(findings))
	b.WriteString("\nThis report measures the configured target cluster; it does not evaluate the GitHub runner's container.\n")
	return b.String()
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
