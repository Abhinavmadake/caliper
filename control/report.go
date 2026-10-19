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
	"fmt"
	"io"
	"sort"
	"strings"
)

// AuthorizationNotice is included in every report format to make the
// instrument's intended authorization boundary explicit.
const AuthorizationNotice = "This instrument is intended for infrastructure you own or have written authorization to test."

// Report combines evaluator findings, classified divergences, and attribution
// confidence for all measured fingerprints in the comparison.
type Report struct {
	Notice         string               `json:"notice"`
	Findings       FindingReport        `json:"findings"`
	Classification ClassificationResult `json:"classification"`
	Attribution    AttributionReport    `json:"attribution"`
}

// AttributionReport summarizes uncertainty across denied and killed probe
// results, as required by proposal §11.2. SIGSYS kills are denials; a denial
// without attribution is counted as undecidable.
type AttributionReport struct {
	Denials             int                         `json:"denials"`
	Undecidable         int                         `json:"undecidable"`
	UndecidableFraction *float64                    `json:"undecidable_fraction"`
	ConfidenceCounts    AttributionConfidenceCounts `json:"confidence_counts"`
	Results             []AttributionObservation    `json:"results"`
}

// AttributionConfidenceCounts keeps confidence levels visible independently
// of the overall undecidable fraction.
type AttributionConfidenceCounts struct {
	High    int `json:"high"`
	Medium  int `json:"medium"`
	Low     int `json:"low"`
	Unknown int `json:"unknown"`
}

// AttributionObservation associates one result's attribution with its cell.
// Undecidable is true when attribution is absent as well as when its oracle
// explicitly could not separate the mechanism.
type AttributionObservation struct {
	CellLabel   string       `json:"cell_label"`
	Cell        Cell         `json:"cell"`
	ProbeID     string       `json:"probe_id"`
	Undecidable bool         `json:"undecidable"`
	Attribution *Attribution `json:"attribution,omitempty"`
}

// BuildReport combines already-computed evaluation and classification results
// with attribution details from one or more fingerprints. The undecidable
// fraction's denominator is all denied probe results across those cells.
func BuildReport(findings FindingReport, classification ClassificationResult, fingerprints ...Fingerprint) (Report, error) {
	report := Report{
		Notice:         AuthorizationNotice,
		Findings:       findings,
		Classification: classification,
		Attribution: AttributionReport{
			Results: []AttributionObservation{},
		},
	}
	for i, fingerprint := range fingerprints {
		cellLabel, err := reportCellLabel(fingerprint, i)
		if err != nil {
			return Report{}, fmt.Errorf("fingerprint %d: %w", i+1, err)
		}
		for _, result := range fingerprint.Results {
			if result.Verdict != "denied" && result.Verdict != "killed" {
				continue
			}
			report.Attribution.Denials++
			observation := AttributionObservation{
				CellLabel:   cellLabel,
				Cell:        fingerprint.Cell,
				ProbeID:     result.ProbeID,
				Attribution: result.Attribution,
			}
			if result.Attribution == nil {
				observation.Undecidable = true
				report.Attribution.Undecidable++
				report.Attribution.ConfidenceCounts.Unknown++
			} else {
				observation.Undecidable = result.Attribution.Undecidable
				if observation.Undecidable {
					report.Attribution.Undecidable++
				}
				switch result.Attribution.Confidence {
				case High:
					report.Attribution.ConfidenceCounts.High++
				case Medium:
					report.Attribution.ConfidenceCounts.Medium++
				case Low:
					report.Attribution.ConfidenceCounts.Low++
				default:
					report.Attribution.ConfidenceCounts.Unknown++
				}
			}
			report.Attribution.Results = append(report.Attribution.Results, observation)
		}
	}
	if report.Attribution.Denials > 0 {
		fraction := float64(report.Attribution.Undecidable) / float64(report.Attribution.Denials)
		report.Attribution.UndecidableFraction = &fraction
	}
	sort.Slice(report.Attribution.Results, func(i, j int) bool {
		if report.Attribution.Results[i].CellLabel != report.Attribution.Results[j].CellLabel {
			return report.Attribution.Results[i].CellLabel < report.Attribution.Results[j].CellLabel
		}
		return report.Attribution.Results[i].ProbeID < report.Attribution.Results[j].ProbeID
	})
	return report, nil
}

// WriteJSONReport writes an indented JSON report and does not close w.
func WriteJSONReport(w io.Writer, report Report) error {
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return fmt.Errorf("write JSON report: %w", err)
	}
	return nil
}

// WriteTextReport writes a readable report with divergence classes and finding
// categories shown independently. It does not close w.
func WriteTextReport(w io.Writer, report Report) error {
	var b strings.Builder
	fmt.Fprintf(&b, "CALIPER report\nNotice: %s\n\n", report.Notice)
	fmt.Fprintf(&b, "Findings (posture %s, tier %s)\n", report.Findings.PostureRevision, report.Findings.Tier)
	writeFindings(&b, "Expectation violations", report.Findings.ExpectationViolations)
	writeFindings(&b, "Claim violations", report.Findings.ClaimViolations)
	writeFindings(&b, "Undeclared exposures", report.Findings.UndeclaredExposures)

	classification := report.Classification
	fmt.Fprintf(&b, "\nDivergences (corpus %s vs %s; sets %s vs %s)\n",
		classification.Diff.CorpusRevisions.Left,
		classification.Diff.CorpusRevisions.Right,
		classification.Diff.CorpusSets.Left,
		classification.Diff.CorpusSets.Right)
	writeDivergenceClass(&b, ArchitectureExplained, classification.Divergences)
	writeDivergenceClass(&b, KernelVersionExplained, classification.Divergences)
	writeDivergenceClass(&b, RuntimeClassExplained, classification.Divergences)
	writeDivergenceClass(&b, PolicyExplained, classification.Divergences)
	fmt.Fprintf(&b, "  Corpus skew: %d only on left, %d only on right\n", len(classification.Diff.CorpusSkew.OnlyLeft), len(classification.Diff.CorpusSkew.OnlyRight))
	fmt.Fprintf(&b, "  Unmeasured: %d\n", len(classification.Diff.Unmeasured))

	fmt.Fprintf(&b, "\nAttribution confidence\n")
	if report.Attribution.UndecidableFraction == nil {
		fmt.Fprintf(&b, "  Undecidable: n/a (0/0 denials)\n")
	} else {
		fmt.Fprintf(&b, "  Undecidable: %d/%d denials (including kills; %.1f%%)\n", report.Attribution.Undecidable, report.Attribution.Denials, *report.Attribution.UndecidableFraction*100)
	}
	fmt.Fprintf(&b, "  Confidence counts: high %d, medium %d, low %d, unknown %d\n",
		report.Attribution.ConfidenceCounts.High,
		report.Attribution.ConfidenceCounts.Medium,
		report.Attribution.ConfidenceCounts.Low,
		report.Attribution.ConfidenceCounts.Unknown)
	for _, observation := range report.Attribution.Results {
		confidence := "unknown"
		mechanism := "undetermined"
		if observation.Attribution != nil {
			confidence = string(observation.Attribution.Confidence)
			if observation.Attribution.Mechanism != nil {
				mechanism = string(*observation.Attribution.Mechanism)
			}
		}
		marker := ""
		if observation.Undecidable {
			marker = " (undecidable)"
		}
		fmt.Fprintf(&b, "  %s (%s) / %s: %s confidence, %s%s\n",
			observation.CellLabel,
			reportCellDetail(observation.Cell),
			observation.ProbeID,
			confidence,
			mechanism,
			marker)
	}
	if _, err := io.WriteString(w, b.String()); err != nil {
		return fmt.Errorf("write text report: %w", err)
	}
	return nil
}

func writeFindings(b *strings.Builder, title string, findings []Finding) {
	fmt.Fprintf(b, "  %s (%d)\n", title, len(findings))
	for _, finding := range findings {
		fmt.Fprintf(b, "    %s [%s]: %s\n", finding.ProbeID, finding.Family, finding.Reason)
	}
}

func writeDivergenceClass(b *strings.Builder, class DivergenceClass, divergences []ClassifiedDivergence) {
	matched := 0
	for _, divergence := range divergences {
		if divergence.Class == class {
			matched++
		}
	}
	fmt.Fprintf(b, "  %s (%d)\n", divergenceClassLabel(class), matched)
	for _, divergence := range divergences {
		if divergence.Class == class {
			fmt.Fprintf(b, "    %s: %s -> %s\n", divergence.ProbeID, divergence.Left.Verdict, divergence.Right.Verdict)
		}
	}
}

func divergenceClassLabel(class DivergenceClass) string {
	switch class {
	case ArchitectureExplained:
		return "Architecture-explained"
	case KernelVersionExplained:
		return "Kernel-version-explained"
	case RuntimeClassExplained:
		return "Runtime-class-explained"
	case PolicyExplained:
		return "Policy-explained"
	default:
		return string(class)
	}
}

func reportCellLabel(fingerprint Fingerprint, index int) (string, error) {
	if fingerprint.Digest == "" {
		return fmt.Sprintf("cell-%d", index+1), nil
	}
	digestHex := strings.TrimPrefix(fingerprint.Digest, "sha256:")
	if len(digestHex) < 12 {
		return "", fmt.Errorf("fingerprint digest %q is too short", fingerprint.Digest)
	}
	return fmt.Sprintf("cell-%d-%s", index+1, digestHex[:12]), nil
}

func reportCellDetail(cell Cell) string {
	parts := make([]string, 0, 3)
	if cell.Architecture != "" {
		parts = append(parts, cell.Architecture)
	}
	if cell.Kernel.Release != "" {
		parts = append(parts, "kernel="+cell.Kernel.Release)
	}
	if cell.RuntimeClass != nil && cell.RuntimeClass.Value != "" {
		parts = append(parts, "runtime-class="+cell.RuntimeClass.Value)
	}
	if len(parts) == 0 {
		return "cell details unavailable"
	}
	return strings.Join(parts, ", ")
}
