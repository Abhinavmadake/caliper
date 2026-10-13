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
	"testing"

	corev1 "k8s.io/api/core/v1"
	nodev1 "k8s.io/api/node/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
)

func TestReadKubernetesCellMetadata(t *testing.T) {
	tests := []struct {
		name              string
		runtimeClassName  *string
		runtimeClass      *nodev1.RuntimeClass
		nodeName          string
		containerRuntime  string
		wantRuntime       string
		wantVersion       string
		wantRuntimeClass  string
		wantRuntimeSource string
	}{
		{
			name:              "runtime class handler and containerd version",
			runtimeClassName:  stringPointer("sandboxed"),
			runtimeClass:      &nodev1.RuntimeClass{ObjectMeta: metav1.ObjectMeta{Name: "sandboxed"}, Handler: "runsc"},
			nodeName:          "node-1",
			containerRuntime:  "containerd://2.2.1",
			wantRuntime:       "containerd",
			wantVersion:       "2.2.1",
			wantRuntimeClass:  "runsc",
			wantRuntimeSource: "runtime-class",
		},
		{
			name:             "unset runtime class",
			nodeName:         "node-1",
			containerRuntime: "containerd://2.2.1",
			wantRuntime:      "containerd",
			wantVersion:      "2.2.1",
		},
		{
			name:             "malformed runtime version remains unknown",
			nodeName:         "node-1",
			containerRuntime: "containerd://",
		},
		{
			name:              "pod without a node",
			runtimeClassName:  stringPointer("sandboxed"),
			runtimeClass:      &nodev1.RuntimeClass{ObjectMeta: metav1.ObjectMeta{Name: "sandboxed"}, Handler: "kata-qemu"},
			wantRuntimeClass:  "kata-qemu",
			wantRuntimeSource: "runtime-class",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "probe"},
				Spec:       corev1.PodSpec{NodeName: tt.nodeName, RuntimeClassName: tt.runtimeClassName},
			}
			objects := []runtime.Object{pod}
			if tt.nodeName != "" {
				objects = append(objects, &corev1.Node{
					ObjectMeta: metav1.ObjectMeta{Name: tt.nodeName},
					Status:     corev1.NodeStatus{NodeInfo: corev1.NodeSystemInfo{ContainerRuntimeVersion: tt.containerRuntime}},
				})
			}
			if tt.runtimeClass != nil {
				objects = append(objects, tt.runtimeClass)
			}
			client := fake.NewSimpleClientset(objects...)

			got, err := ReadKubernetesCellMetadata(context.Background(), client, "default", "probe")
			if err != nil {
				t.Fatalf("ReadKubernetesCellMetadata() error = %v", err)
			}
			if got.Runtime != nil && got.Runtime.Value != tt.wantRuntime {
				t.Errorf("runtime = %q, want %q", got.Runtime.Value, tt.wantRuntime)
			}
			if got.RuntimeVersion != nil && got.RuntimeVersion.Value != tt.wantVersion {
				t.Errorf("runtime version = %q, want %q", got.RuntimeVersion.Value, tt.wantVersion)
			}
			if (got.Runtime == nil) != (tt.wantRuntime == "") {
				t.Errorf("runtime = %#v, want present=%t", got.Runtime, tt.wantRuntime != "")
			}
			if (got.RuntimeVersion == nil) != (tt.wantVersion == "") {
				t.Errorf("runtime version = %#v, want present=%t", got.RuntimeVersion, tt.wantVersion != "")
			}
			if (got.RuntimeClass == nil) != (tt.wantRuntimeClass == "") {
				t.Errorf("runtime class = %#v, want present=%t", got.RuntimeClass, tt.wantRuntimeClass != "")
			} else if got.RuntimeClass != nil {
				if got.RuntimeClass.Value != tt.wantRuntimeClass || got.RuntimeClass.Source != tt.wantRuntimeSource {
					t.Errorf("runtime class = %#v, want handler %q from %q", got.RuntimeClass, tt.wantRuntimeClass, tt.wantRuntimeSource)
				}
			}
			if tt.nodeName == "" && got.NodeKernelVersion != "" {
				t.Errorf("node kernel version = %q, want unknown for unscheduled pod", got.NodeKernelVersion)
			}
		})
	}
}

func stringPointer(value string) *string {
	return &value
}
