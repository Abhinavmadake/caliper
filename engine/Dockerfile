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
# Two stages. The first is a glibc host that cross-builds the static musl
# target, which is the same build path as a developer's machine and CI
# (self-contained musl target, linked with rust-lld — see .cargo/config.toml).
# Not Alpine: there the musl target is the host, self-contained mode is off,
# and proc-macro crates then need the system linker. One path is easier to
# reason about than two. The second stage is `scratch`: no shell, no libc,
# no CA bundle, nothing that could issue a syscall the engine did not.
#
#   docker build -t caliper-probe engine/
#   docker run --rm caliper-probe --noop

FROM rust:1.93-bookworm AS build
ARG TARGETARCH
WORKDIR /src
COPY . .
RUN case "$TARGETARCH" in \
      amd64) triple=x86_64-unknown-linux-musl ;; \
      arm64) triple=aarch64-unknown-linux-musl ;; \
      *) echo "unsupported TARGETARCH=$TARGETARCH" >&2; exit 1 ;; \
    esac \
 && cargo build --release --locked --target "$triple" \
 && cp "target/$triple/release/caliper-probe" /caliper-probe

FROM scratch
COPY --from=build /caliper-probe /caliper-probe
# Unprivileged by default; the measurement is of what an ordinary workload
# can reach. Deployments that need to measure a different identity say so.
USER 65534:65534
ENTRYPOINT ["/caliper-probe"]
CMD ["--noop"]
