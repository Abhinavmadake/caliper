# Copyright 2026 Abhinav Ajit Madake, Sahil Tatyabhau Waje,
# Ritesh Aresh Saindane, Yogesh Babaji Palve
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# The probe image: the caliper-probe binary and nothing else.
#
# CI and developers build the static musl target before creating this image.
# The image stage only packages that artifact; it must not download a Rust
# toolchain or recompile the workspace over the network. The result is
# `scratch`: no shell, no libc, no CA bundle, nothing that could issue a
# syscall the engine did not.
#
#   docker build -t caliper-probe engine/
#   docker run --rm caliper-probe --noop

FROM scratch
COPY target/x86_64-unknown-linux-musl/release/caliper-probe /caliper-probe
# A writable directory for probes that need a path of their own (the mount
# family's target, #13): the only thing in the image the probe may write,
# owned by the user it runs as. Empty, and nothing is read from it.
COPY --chown=65534:65534 image-tmp/.keep /tmp/.keep
# Unprivileged by default; the measurement is of what an ordinary workload
# can reach. Deployments that need to measure a different identity say so.
USER 65534:65534
ENTRYPOINT ["/caliper-probe"]
CMD ["--noop"]
