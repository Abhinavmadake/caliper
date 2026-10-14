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

import "testing"

func TestParseManifestReadsNamespacePSSAndPodSecurity(t *testing.T) {
	manifest, err := ParseManifest([]byte(`apiVersion: v1
kind: Pod
metadata:
  name: api
  namespace: app
spec:
  securityContext:
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: web
      image: example.invalid/web
      securityContext:
        capabilities:
          add: [NET_BIND_SERVICE]
          drop: [ALL]
    - name: debug
      image: example.invalid/debug
      securityContext:
        seccompProfile:
          type: Unconfined
        capabilities: {}
  initContainers:
    - name: setup
      image: example.invalid/setup
---
apiVersion: v1
kind: Namespace
metadata:
  name: app
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: v1.32
    pod-security.kubernetes.io/warn: baseline
    pod-security.kubernetes.io/audit: privileged
`))
	if err != nil {
		t.Fatalf("ParseManifest() error = %v", err)
	}
	if len(manifest.Namespaces) != 1 || len(manifest.Workloads) != 1 {
		t.Fatalf("got %d namespaces and %d workloads, want 1 each", len(manifest.Namespaces), len(manifest.Workloads))
	}

	workload := manifest.Workloads[0]
	if workload.Kind != "Pod" || workload.Name != "api" || workload.Namespace != "app" {
		t.Errorf("workload identity = %#v", workload)
	}
	if workload.PodSecurityStandard == nil || workload.PodSecurityStandard.Enforce == nil {
		t.Fatal("workload did not inherit the namespace PSS labels")
	}
	if got := workload.PodSecurityStandard.Enforce; got.Level != "restricted" || got.Version != "v1.32" {
		t.Errorf("enforce PSS = %#v, want restricted v1.32", got)
	}
	if got := workload.PodSecurityStandard.Warn; got == nil || got.Level != "baseline" {
		t.Errorf("warn PSS = %#v, want baseline", got)
	}
	if got := workload.PodSecurityStandard.Audit; got == nil || got.Level != "privileged" {
		t.Errorf("audit PSS = %#v, want privileged", got)
	}
	if got := workload.Pod.Seccomp; got == nil || got.Type != "RuntimeDefault" || !got.RuntimeDefined {
		t.Errorf("pod seccomp = %#v, want runtime-defined RuntimeDefault", got)
	}
	if len(workload.Pod.Containers) != 3 {
		t.Fatalf("got %d containers, want regular, debug, and init", len(workload.Pod.Containers))
	}

	web := workload.Pod.Containers[0]
	if web.Name != "web" || web.Kind != "container" || web.Capabilities == nil {
		t.Fatalf("web security = %#v", web)
	}
	if len(web.Capabilities.Add) != 1 || web.Capabilities.Add[0] != "NET_BIND_SERVICE" {
		t.Errorf("web capabilities added = %v", web.Capabilities.Add)
	}
	if len(web.Capabilities.Drop) != 1 || web.Capabilities.Drop[0] != "ALL" {
		t.Errorf("web capabilities dropped = %v", web.Capabilities.Drop)
	}
	if got := workload.Pod.EffectiveSeccomp(web); got != workload.Pod.Seccomp {
		t.Errorf("effective web seccomp = %#v, want Pod RuntimeDefault", got)
	}

	debug := workload.Pod.Containers[1]
	if debug.Seccomp == nil || debug.Seccomp.Type != "Unconfined" || debug.Seccomp.RuntimeDefined {
		t.Errorf("debug seccomp = %#v, want explicit Unconfined", debug.Seccomp)
	}
	if debug.Capabilities == nil {
		t.Error("explicit empty capabilities object was lost")
	}
	if got := workload.Pod.EffectiveSeccomp(debug); got != debug.Seccomp {
		t.Errorf("effective debug seccomp = %#v, want container override", got)
	}

	setup := workload.Pod.Containers[2]
	if setup.Kind != "init" || setup.Capabilities != nil || setup.Seccomp != nil {
		t.Errorf("undeclared init-container security settings = %#v, want nil", setup)
	}
}

func TestParseManifestDistinguishesUnspecifiedFromPermissive(t *testing.T) {
	manifest, err := ParseManifest([]byte(`apiVersion: v1
kind: List
items:
  - apiVersion: v1
    kind: Namespace
    metadata:
      name: permissive
      labels:
        pod-security.kubernetes.io/enforce: privileged
  - apiVersion: v1
    kind: Pod
    metadata:
      name: unspecified
      namespace: permissive
    spec:
      containers:
        - name: app
          image: example.invalid/app
  - apiVersion: v1
    kind: Pod
    metadata:
      name: explicit
    spec:
      containers:
        - name: app
          image: example.invalid/app
          securityContext:
            seccompProfile:
              type: Unconfined
            capabilities:
              add: [SYS_ADMIN]
`))
	if err != nil {
		t.Fatalf("ParseManifest() error = %v", err)
	}
	if len(manifest.Namespaces) != 1 || len(manifest.Workloads) != 2 {
		t.Fatalf("got %d namespaces and %d workloads, want 1 and 2", len(manifest.Namespaces), len(manifest.Workloads))
	}
	if got := manifest.Workloads[0].PodSecurityStandard; got == nil || got.Enforce == nil || got.Enforce.Level != "privileged" {
		t.Errorf("explicit permissive PSS label = %#v", got)
	}
	unspecified := manifest.Workloads[0].Pod.Containers[0]
	if unspecified.Seccomp != nil || unspecified.Capabilities != nil {
		t.Errorf("omitted settings became declarations: %#v", unspecified)
	}
	explicit := manifest.Workloads[1].Pod.Containers[0]
	if explicit.Seccomp == nil || explicit.Seccomp.Type != "Unconfined" {
		t.Errorf("explicit seccomp setting = %#v, want Unconfined", explicit.Seccomp)
	}
	if explicit.Capabilities == nil || len(explicit.Capabilities.Add) != 1 || explicit.Capabilities.Add[0] != "SYS_ADMIN" {
		t.Errorf("explicit capabilities = %#v, want SYS_ADMIN", explicit.Capabilities)
	}
}

func TestParseManifestReadsWorkloadPodTemplatesAndJSON(t *testing.T) {
	manifest, err := ParseManifest([]byte(`{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"api","namespace":"app"},"spec":{"template":{"spec":{"containers":[{"name":"web","image":"example.invalid/web","securityContext":{"capabilities":{"drop":["ALL"]}}}]}}}}`))
	if err != nil {
		t.Fatalf("ParseManifest() error = %v", err)
	}
	if len(manifest.Workloads) != 1 {
		t.Fatalf("got %d workloads, want 1", len(manifest.Workloads))
	}
	workload := manifest.Workloads[0]
	if workload.Kind != "Deployment" || workload.Name != "api" || len(workload.Pod.Containers) != 1 {
		t.Fatalf("parsed Deployment = %#v", workload)
	}
	if got := workload.Pod.Containers[0].Capabilities; got == nil || len(got.Drop) != 1 || got.Drop[0] != "ALL" {
		t.Errorf("Deployment container capabilities = %#v", got)
	}
}

func TestParseManifestReadsLocalhostSeccompProfile(t *testing.T) {
	manifest, err := ParseManifest([]byte(`apiVersion: v1
kind: Pod
metadata:
  name: local-profile
spec:
  containers:
    - name: app
      image: example.invalid/app
      securityContext:
        seccompProfile:
          type: Localhost
          localhostProfile: profiles/api.json
`))
	if err != nil {
		t.Fatalf("ParseManifest() error = %v", err)
	}
	profile := manifest.Workloads[0].Pod.Containers[0].Seccomp
	if profile == nil || profile.Type != "Localhost" || profile.RuntimeDefined || profile.LocalhostProfilePath == nil || *profile.LocalhostProfilePath != "profiles/api.json" {
		t.Errorf("Localhost seccomp profile = %#v", profile)
	}
}

func TestParseManifestRejectsInvalidPSSLabel(t *testing.T) {
	_, err := ParseManifest([]byte(`apiVersion: v1
kind: Namespace
metadata:
  name: app
  labels:
    pod-security.kubernetes.io/enforce: unknown
`))
	if err == nil {
		t.Fatal("ParseManifest() accepted an unknown PSS level")
	}
}
