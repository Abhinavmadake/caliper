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

// caliper-remediate renders a target-specific SPO SeccompProfile and OCI
// Localhost profile from an evaluated findings report and that target's actual
// RuntimeDefault profile.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/Abhinavmadake/caliper/control"
)

func main() {
	var in inputs
	flag.StringVar(&in.findings, "findings", "", "path to FindingReport JSON (or Report JSON containing findings)")
	flag.StringVar(&in.runtime, "runtime-default", "", "path to the selected runtime's default seccomp JSON")
	flag.StringVar(&in.runtimeArch, "runtime-arch", "", "runtime gate architecture, e.g. amd64")
	flag.StringVar(&in.ociArch, "oci-arch", "", "OCI/libseccomp architecture, e.g. SCMP_ARCH_X86_64")
	flag.StringVar(&in.caps, "capabilities", "", "comma-separated effective capabilities")
	flag.StringVar(&in.kernel, "kernel", "", "target kernel release")
	flag.StringVar(&in.spoOut, "spo-out", "", "output path for the SPO YAML")
	flag.StringVar(&in.localOut, "localhost-out", "", "output path for the OCI Localhost JSON")
	flag.Parse()
	if flag.NArg() != 0 {
		fail(fmt.Errorf("unexpected argument %q", flag.Arg(0)))
	}
	if err := run(in); err != nil {
		fail(err)
	}
}

type inputs struct {
	findings, runtime, runtimeArch, ociArch, caps, kernel, spoOut, localOut string
}

func run(in inputs) error {
	if in.findings == "" || in.runtime == "" || in.runtimeArch == "" || in.ociArch == "" || in.kernel == "" || in.spoOut == "" || in.localOut == "" {
		return errors.New("findings, runtime-default, runtime-arch, oci-arch, kernel, spo-out, and localhost-out are required")
	}
	report, err := readFindings(in.findings)
	if err != nil {
		return fmt.Errorf("read findings: %w", err)
	}
	data, err := os.ReadFile(in.runtime)
	if err != nil {
		return fmt.Errorf("read runtime default: %w", err)
	}
	var runtime control.RuntimeDefaultProfile
	if err := json.Unmarshal(data, &runtime); err != nil {
		return fmt.Errorf("parse runtime default: %w", err)
	}
	target := control.RemediationTarget{
		RuntimeArchitecture: in.runtimeArch,
		OCIArchitecture:     in.ociArch,
		Capabilities:        commaList(in.caps),
		Kernel:              in.kernel,
	}
	remediation, err := control.GenerateRemediation(report, runtime, target)
	if err != nil {
		return err
	}
	spo, err := remediation.RenderSPO()
	if err != nil {
		return fmt.Errorf("render SPO: %w", err)
	}
	localhost, err := remediation.RenderLocalhost()
	if err != nil {
		return fmt.Errorf("render Localhost: %w", err)
	}
	if err := os.WriteFile(in.spoOut, spo, 0o644); err != nil {
		return fmt.Errorf("write SPO profile: %w", err)
	}
	if err := os.WriteFile(in.localOut, localhost, 0o644); err != nil {
		return fmt.Errorf("write Localhost profile: %w", err)
	}
	return nil
}

func readFindings(path string) (control.FindingReport, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return control.FindingReport{}, err
	}
	var report control.FindingReport
	if err := json.Unmarshal(data, &report); err == nil && report.PostureRevision != "" {
		return report, nil
	}
	var wrapped control.Report
	if err := json.Unmarshal(data, &wrapped); err != nil {
		return control.FindingReport{}, err
	}
	if wrapped.Findings.PostureRevision == "" {
		return control.FindingReport{}, errors.New("file does not contain findings")
	}
	return wrapped.Findings, nil
}

func commaList(value string) []string {
	if value == "" {
		return nil
	}
	var values []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			values = append(values, item)
		}
	}
	return values
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "caliper-remediate:", err)
	os.Exit(1)
}
