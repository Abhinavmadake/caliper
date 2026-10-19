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

// caliper-complete turns raw caliper-probe output into a fingerprint by adding
// the cell facts the probe cannot observe, supplied by the operator, and the
// digest. Outside Kubernetes this is how a cell's measurement is recorded.
// -runtime-class is the RuntimeClass handler, as the Kubernetes path records
// it; -node-kernel is the node's own release (on a cell, the "kernel" line of
// deploy/gce/cells.sh packages), not the machine running this command.
//
//	caliper-complete -distribution "Ubuntu 24.04" -runtime containerd \
//	    -runtime-version 2.2.1 -runtime-class runc -node-kernel 7.0.0-1014-gcp \
//	    < raw.json > fingerprint.json
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Abhinavmadake/caliper/control"
)

func main() {
	distribution := flag.String("distribution", "", "node distribution")
	runtime := flag.String("runtime", "", "container runtime")
	runtimeVersion := flag.String("runtime-version", "", "container runtime version")
	runtimeClass := flag.String("runtime-class", "", "RuntimeClass the probe ran under")
	nodeKernel := flag.String("node-kernel", "", "the node's own kernel release, for sandbox_claimed")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintf(os.Stderr, "caliper-complete: unexpected argument %q (quote values with spaces)\n", flag.Arg(0))
		os.Exit(2)
	}

	if err := run(os.Stdin, os.Stdout, control.CellMetadata{
		Distribution:      operator(*distribution),
		Runtime:           operator(*runtime),
		RuntimeVersion:    operator(*runtimeVersion),
		RuntimeClass:      operator(*runtimeClass),
		NodeKernelVersion: strings.TrimSpace(*nodeKernel),
	}); err != nil {
		fmt.Fprintln(os.Stderr, "caliper-complete:", err)
		os.Exit(1)
	}
}

func operator(value string) *control.SourcedValue {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	return &control.SourcedValue{Value: value, Source: "operator"}
}

func run(in io.Reader, out io.Writer, metadata control.CellMetadata) error {
	data, err := io.ReadAll(in)
	if err != nil {
		return err
	}
	var probe control.ProbeMeasurement
	if err := json.Unmarshal(data, &probe); err != nil {
		return fmt.Errorf("decode probe output: %w", err)
	}
	if probe.FormatVersion != control.SupportedFormatVersion {
		return errors.New("unsupported format_version")
	}
	fingerprint, err := control.CompleteFingerprint(probe, metadata)
	if err != nil {
		return err
	}
	encoded, err := control.EncodeFingerprint(fingerprint)
	if err != nil {
		return err
	}
	var indented bytes.Buffer
	if err := json.Indent(&indented, encoded, "", "  "); err != nil {
		return err
	}
	indented.WriteByte('\n')
	_, err = out.Write(indented.Bytes())
	return err
}
