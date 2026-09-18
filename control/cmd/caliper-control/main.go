package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: caliper-control [evaluate|remediate]")
		os.Exit(1)
	}

	cmd := os.Args[1]

	switch cmd {
	case "evaluate":
		// Mock evaluation logic for integration pipeline and demo
		fmt.Println(`{
  "status": "completed",
  "evaluation": {
    "expectation_violations": [
      {
        "probe_id": "af-alg",
        "expected": "denied",
        "actual": "permitted",
        "rationale": "The kernel crypto API is a known attack surface (CVE-2026-31431) and not needed by standard workloads."
      }
    ],
    "claim_violations": [],
    "undeclared_exposures": []
  },
  "divergence": {
    "policy_explained": 1,
    "architecture_explained": 0,
    "runtime_class_explained": 0,
    "kernel_version_explained": 0
  }
}`)
	case "remediate":
		// Mock remediation logic
		fmt.Println(`apiVersion: security-profiles-operator.x-k8s.io/v1beta1
kind: SeccompProfile
metadata:
  name: caliper-remediation-af-alg
  namespace: default
spec:
  defaultAction: SCMP_ACT_ERRNO
  architectures:
  - SCMP_ARCH_X86_64
  syscalls:
  - action: SCMP_ACT_ALLOW
    names:
    - socket
    args:
    - index: 0
      value: 38 # AF_ALG
      op: SCMP_CMP_NE`)
	default:
		fmt.Printf("Unknown command: %s\n", cmd)
		os.Exit(1)
	}
}
