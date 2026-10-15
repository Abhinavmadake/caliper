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

// caliper-ci-report summarizes a measured target-cluster fingerprint and posts
// an idempotent GitHub PR comment. Posture evaluation belongs to issue #34.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/Abhinavmadake/caliper/control"
	"github.com/google/go-github/v68/github"
	"golang.org/x/oauth2"
)

const reportMarker = "<!-- caliper-ci-cell-report -->"

func main() {
	fingerprintPath := flag.String("fingerprint", "", "path to the target-cluster measurement JSON")
	cluster := flag.String("cluster", "", "named target cluster context")
	repository := flag.String("repository", "", "GitHub repository in owner/name form")
	prNumber := flag.Int("pr", 0, "pull request number")
	flag.Parse()

	if err := run(*fingerprintPath, *cluster, *repository, *prNumber); err != nil {
		fmt.Fprintln(os.Stderr, "caliper-ci-report:", err)
		os.Exit(1)
	}
}

func run(fingerprintPath, cluster, repository string, prNumber int) error {
	if fingerprintPath == "" || cluster == "" || prNumber < 1 {
		return errors.New("fingerprint, cluster and positive PR number are required")
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
	body := renderReport(cluster, measurement)
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

func renderReport(cluster string, fp control.Fingerprint) string {
	var b strings.Builder
	b.WriteString(reportMarker + "\n")
	fmt.Fprintf(&b, "## CALIPER target-cluster measurement\n\n")
	fmt.Fprintf(&b, "**Target:** `%s`  \n**Cell:** `%s`, kernel `%s`  \n**Corpus:** `%s` revision `%s`\n\n",
		cluster, fp.Cell.Architecture, fp.Cell.Kernel.Release, fp.CorpusSet, fp.CorpusRevision)
	b.WriteString("| Probe | Verdict |\n|---|---|\n")
	for _, result := range fp.Results {
		fmt.Fprintf(&b, "| `%s` | `%s` |\n", result.ProbeID, result.Verdict)
	}
	fmt.Fprintf(&b, "\n**Summary:** %d measured probe(s), %d unmeasured probe(s).\n", len(fp.Results), len(fp.Unmeasured))
	b.WriteString("\nThis report records measurements only. Posture evaluation is handled separately under issue #34.\n")
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
