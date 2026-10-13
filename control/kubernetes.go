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
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// ReadKubernetesCellMetadata reads the scheduled Pod and its Node and extracts
// the environment fields that are not observable from inside the workload.
// Values are left unknown when the Kubernetes objects do not provide them.
func ReadKubernetesCellMetadata(ctx context.Context, client kubernetes.Interface, namespace, podName string) (CellMetadata, error) {
	if client == nil {
		return CellMetadata{}, fmt.Errorf("Kubernetes client is required")
	}
	if namespace == "" || podName == "" {
		return CellMetadata{}, fmt.Errorf("namespace and pod name are required")
	}

	pod, err := client.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		return CellMetadata{}, fmt.Errorf("read pod %s/%s: %w", namespace, podName, err)
	}

	metadata := CellMetadata{}
	if pod.Spec.RuntimeClassName != nil && strings.TrimSpace(*pod.Spec.RuntimeClassName) != "" {
		metadata.RuntimeClass = sourcedValue(*pod.Spec.RuntimeClassName, "pod-spec")
	}
	if pod.Spec.NodeName == "" {
		return metadata, nil
	}

	node, err := client.CoreV1().Nodes().Get(ctx, pod.Spec.NodeName, metav1.GetOptions{})
	if err != nil {
		return CellMetadata{}, fmt.Errorf("read node %s for pod %s/%s: %w", pod.Spec.NodeName, namespace, podName, err)
	}
	return completeMetadataFromNode(metadata, node), nil
}

// CellMetadataFromKubernetesObjects extracts cell metadata from already-read
// Kubernetes objects. A nil object or an unavailable field remains unknown.
func CellMetadataFromKubernetesObjects(node *corev1.Node, pod *corev1.Pod) CellMetadata {
	metadata := CellMetadata{}
	if pod != nil && pod.Spec.RuntimeClassName != nil && strings.TrimSpace(*pod.Spec.RuntimeClassName) != "" {
		metadata.RuntimeClass = sourcedValue(*pod.Spec.RuntimeClassName, "pod-spec")
	}
	return completeMetadataFromNode(metadata, node)
}

func completeMetadataFromNode(metadata CellMetadata, node *corev1.Node) CellMetadata {
	if node == nil {
		return metadata
	}

	info := node.Status.NodeInfo
	metadata.NodeKernelVersion = strings.TrimSpace(info.KernelVersion)
	if value := strings.TrimSpace(info.OSImage); value != "" {
		metadata.Distribution = sourcedValue(value, "node-object")
	}
	if name, version, ok := parseContainerRuntimeVersion(info.ContainerRuntimeVersion); ok {
		metadata.Runtime = sourcedValue(name, "node-object")
		metadata.RuntimeVersion = sourcedValue(version, "node-object")
	}
	return metadata
}

func parseContainerRuntimeVersion(value string) (name, version string, ok bool) {
	name, version, ok = strings.Cut(strings.TrimSpace(value), "://")
	name = strings.TrimSpace(name)
	version = strings.TrimSpace(version)
	return name, version, ok && name != "" && version != ""
}

func sourcedValue(value, source string) *SourcedValue {
	return &SourcedValue{Value: value, Source: source}
}
