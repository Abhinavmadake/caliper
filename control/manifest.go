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
	"bytes"
	"fmt"
	"io"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
)

const (
	pssEnforceLabel        = "pod-security.kubernetes.io/enforce"
	pssEnforceVersionLabel = "pod-security.kubernetes.io/enforce-version"
	pssWarnLabel           = "pod-security.kubernetes.io/warn"
	pssWarnVersionLabel    = "pod-security.kubernetes.io/warn-version"
	pssAuditLabel          = "pod-security.kubernetes.io/audit"
	pssAuditVersionLabel   = "pod-security.kubernetes.io/audit-version"
)

// Manifest contains the security-relevant declarations found in a Kubernetes
// YAML or JSON manifest. Namespace policies are retained separately and also
// associated with workloads by namespace, regardless of document order.
type Manifest struct {
	Namespaces []ManifestNamespace `json:"namespaces,omitempty"`
	Workloads  []ManifestWorkload  `json:"workloads,omitempty"`
}

// ManifestNamespace records Pod Security Admission labels. A missing label is
// nil; it is not interpreted as the most permissive PSS level.
type ManifestNamespace struct {
	Name string            `json:"name"`
	PSS  PodSecurityLevels `json:"pod_security_standard"`
}

// PodSecurityLevels preserves the distinct enforce, warn, and audit PSS
// declarations made on a Namespace.
type PodSecurityLevels struct {
	Enforce *PodSecurityLevel `json:"enforce,omitempty"`
	Warn    *PodSecurityLevel `json:"warn,omitempty"`
	Audit   *PodSecurityLevel `json:"audit,omitempty"`
}

// PodSecurityLevel is the PSS level and optional policy version from a
// pod-security.kubernetes.io label pair.
type PodSecurityLevel struct {
	Level   string `json:"level"`
	Version string `json:"version,omitempty"`
}

// ManifestWorkload contains a Pod or a supported workload's Pod template.
// PodSecurityStandard is nil if no matching Namespace PSS labels were present
// in the manifest.
type ManifestWorkload struct {
	APIVersion          string             `json:"api_version"`
	Kind                string             `json:"kind"`
	Name                string             `json:"name,omitempty"`
	Namespace           string             `json:"namespace,omitempty"`
	PodSecurityStandard *PodSecurityLevels `json:"pod_security_standard,omitempty"`
	Pod                 PodSecuritySpec    `json:"pod"`
}

// PodSecuritySpec retains pod-level seccomp and per-container security
// declarations. It does not infer Kubernetes defaults that are not in the
// manifest.
type PodSecuritySpec struct {
	Seccomp    *SeccompProfile     `json:"seccomp,omitempty"`
	Containers []ContainerSecurity `json:"containers,omitempty"`
}

// ContainerSecurity identifies a regular, init, or ephemeral container and
// retains only the security settings relevant to this workstream.
type ContainerSecurity struct {
	Name         string          `json:"name"`
	Kind         string          `json:"kind"`
	Privileged   *bool           `json:"privileged,omitempty"`
	Seccomp      *SeccompProfile `json:"seccomp,omitempty"`
	Capabilities *CapabilitySet  `json:"capabilities,omitempty"`
}

// SeccompProfile is the profile explicitly declared in the manifest.
// RuntimeDefault is marked RuntimeDefined because its rules belong to the
// runtime implementation on the node, not to the manifest.
type SeccompProfile struct {
	Type                 string  `json:"type"`
	LocalhostProfilePath *string `json:"localhost_profile,omitempty"`
	RuntimeDefined       bool    `json:"runtime_defined"`
}

// CapabilitySet records explicit Add/Drop lists. A nil CapabilitySet means
// capabilities were not declared for that container; an empty non-nil set
// means the manifest explicitly supplied an empty capabilities object.
type CapabilitySet struct {
	All  bool     `json:"all,omitempty"`
	Add  []string `json:"add,omitempty"`
	Drop []string `json:"drop,omitempty"`
}

// EffectiveSeccomp returns the profile implied by Kubernetes security
// semantics. Privileged containers are unconfined even if a seccomp profile
// is also declared; otherwise the container declaration overrides the Pod
// declaration. A nil result means neither scope declares a profile.
func (p PodSecuritySpec) EffectiveSeccomp(container ContainerSecurity) *SeccompProfile {
	if container.Privileged != nil && *container.Privileged {
		return &SeccompProfile{Type: string(corev1.SeccompProfileTypeUnconfined)}
	}
	if container.Seccomp != nil {
		return container.Seccomp
	}
	return p.Seccomp
}

// EffectiveCapabilities returns the capability effect of the container's
// declaration. A privileged container receives all capabilities regardless
// of its explicit Add/Drop lists.
func (c ContainerSecurity) EffectiveCapabilities() *CapabilitySet {
	if c.Privileged != nil && *c.Privileged {
		return &CapabilitySet{All: true}
	}
	return c.Capabilities
}

// ParseManifest parses Kubernetes YAML or JSON documents using the Kubernetes
// YAML decoder. It extracts Pod security settings from Pods and common
// workload templates, and PSS labels from Namespace objects.
func ParseManifest(data []byte) (Manifest, error) {
	decoder := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096)
	var resources []*unstructured.Unstructured
	for document := 1; ; document++ {
		object := map[string]interface{}{}
		if err := decoder.Decode(&object); err != nil {
			if err == io.EOF {
				break
			}
			return Manifest{}, fmt.Errorf("decode manifest document %d: %w", document, err)
		}
		if len(object) == 0 {
			continue
		}
		resources = append(resources, &unstructured.Unstructured{Object: object})
	}
	resources, err := flattenManifestLists(resources)
	if err != nil {
		return Manifest{}, err
	}
	if len(resources) == 0 {
		return Manifest{}, fmt.Errorf("manifest contains no Kubernetes resources")
	}

	manifest := Manifest{}
	namespacePolicies := make(map[string]PodSecurityLevels)
	for _, resource := range resources {
		if resource.GetKind() != "Namespace" {
			continue
		}
		policy, err := parseNamespace(resource)
		if err != nil {
			return Manifest{}, err
		}
		manifest.Namespaces = append(manifest.Namespaces, policy)
		namespacePolicies[policy.Name] = policy.PSS
	}

	for _, resource := range resources {
		workload, supported, err := parseWorkload(resource)
		if err != nil {
			return Manifest{}, err
		}
		if !supported {
			continue
		}
		if pss, ok := namespacePolicies[workload.Namespace]; ok && (pss.Enforce != nil || pss.Warn != nil || pss.Audit != nil) {
			copy := pss
			workload.PodSecurityStandard = &copy
		}
		manifest.Workloads = append(manifest.Workloads, workload)
	}
	return manifest, nil
}

func flattenManifestLists(resources []*unstructured.Unstructured) ([]*unstructured.Unstructured, error) {
	var flattened []*unstructured.Unstructured
	for _, resource := range resources {
		if resource.GetKind() != "List" {
			flattened = append(flattened, resource)
			continue
		}
		items, found, err := unstructured.NestedSlice(resource.Object, "items")
		if err != nil {
			return nil, fmt.Errorf("read Kubernetes List items: %w", err)
		}
		if !found {
			continue
		}
		for i, item := range items {
			object, ok := item.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("Kubernetes List item %d is not an object", i)
			}
			flattened = append(flattened, &unstructured.Unstructured{Object: object})
		}
	}
	return flattened, nil
}

func parseNamespace(resource *unstructured.Unstructured) (ManifestNamespace, error) {
	var namespace corev1.Namespace
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(resource.Object, &namespace); err != nil {
		return ManifestNamespace{}, fmt.Errorf("parse Namespace %q: %w", resource.GetName(), err)
	}
	labels := namespace.Labels
	pss := PodSecurityLevels{}
	var err error
	if pss.Enforce, err = parsePSSLabel(labels, pssEnforceLabel, pssEnforceVersionLabel); err != nil {
		return ManifestNamespace{}, err
	}
	if pss.Warn, err = parsePSSLabel(labels, pssWarnLabel, pssWarnVersionLabel); err != nil {
		return ManifestNamespace{}, err
	}
	if pss.Audit, err = parsePSSLabel(labels, pssAuditLabel, pssAuditVersionLabel); err != nil {
		return ManifestNamespace{}, err
	}
	return ManifestNamespace{Name: namespace.Name, PSS: pss}, nil
}

func parsePSSLabel(labels map[string]string, levelKey, versionKey string) (*PodSecurityLevel, error) {
	level, present := labels[levelKey]
	if !present {
		return nil, nil
	}
	switch level {
	case "privileged", "baseline", "restricted":
	default:
		return nil, fmt.Errorf("invalid Pod Security Standard level %q in label %s", level, levelKey)
	}
	return &PodSecurityLevel{Level: level, Version: labels[versionKey]}, nil
}

func parseWorkload(resource *unstructured.Unstructured) (ManifestWorkload, bool, error) {
	kind := resource.GetKind()
	var path []string
	switch kind {
	case "Pod":
		path = []string{"spec"}
	case "PodTemplate", "Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "ReplicationController", "Job":
		path = []string{"spec", "template", "spec"}
	case "CronJob":
		path = []string{"spec", "jobTemplate", "spec", "template", "spec"}
	default:
		return ManifestWorkload{}, false, nil
	}

	podSpecMap, found, err := unstructured.NestedMap(resource.Object, path...)
	if err != nil {
		return ManifestWorkload{}, false, fmt.Errorf("read Pod spec from %s %q: %w", kind, resource.GetName(), err)
	}
	if !found {
		return ManifestWorkload{}, false, fmt.Errorf("%s %q is missing its Pod spec", kind, resource.GetName())
	}
	var podSpec corev1.PodSpec
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(podSpecMap, &podSpec); err != nil {
		return ManifestWorkload{}, false, fmt.Errorf("parse Pod spec from %s %q: %w", kind, resource.GetName(), err)
	}

	parsed := PodSecuritySpec{}
	if podSpec.SecurityContext != nil {
		parsed.Seccomp = seccompProfile(podSpec.SecurityContext.SeccompProfile)
	}
	for _, container := range podSpec.Containers {
		parsed.Containers = append(parsed.Containers, parseContainer(container.Name, "container", container.SecurityContext))
	}
	for _, container := range podSpec.InitContainers {
		parsed.Containers = append(parsed.Containers, parseContainer(container.Name, "init", container.SecurityContext))
	}
	for _, container := range podSpec.EphemeralContainers {
		parsed.Containers = append(parsed.Containers, parseContainer(container.Name, "ephemeral", container.SecurityContext))
	}

	return ManifestWorkload{
		APIVersion: resource.GetAPIVersion(),
		Kind:       kind,
		Name:       resource.GetName(),
		Namespace:  resource.GetNamespace(),
		Pod:        parsed,
	}, true, nil
}

func parseContainer(name, kind string, context *corev1.SecurityContext) ContainerSecurity {
	parsed := ContainerSecurity{Name: name, Kind: kind}
	if context == nil {
		return parsed
	}
	if context.Privileged != nil {
		privileged := *context.Privileged
		parsed.Privileged = &privileged
	}
	parsed.Seccomp = seccompProfile(context.SeccompProfile)
	if context.Capabilities != nil {
		capabilities := &CapabilitySet{}
		for _, capability := range context.Capabilities.Add {
			capabilities.Add = append(capabilities.Add, string(capability))
		}
		for _, capability := range context.Capabilities.Drop {
			capabilities.Drop = append(capabilities.Drop, string(capability))
		}
		parsed.Capabilities = capabilities
	}
	return parsed
}

func seccompProfile(profile *corev1.SeccompProfile) *SeccompProfile {
	if profile == nil {
		return nil
	}
	parsed := &SeccompProfile{Type: string(profile.Type), RuntimeDefined: profile.Type == corev1.SeccompProfileTypeRuntimeDefault}
	if profile.LocalhostProfile != nil {
		path := *profile.LocalhostProfile
		parsed.LocalhostProfilePath = &path
	}
	return parsed
}
