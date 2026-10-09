#!/bin/bash
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

set -eux -o pipefail

# Sign the caliper-probe image using Cosign.
# This script is intended to be run in CI using keyless signing (OIDC),
# or locally if a cosign key pair is provided.

IMAGE="${1:-ghcr.io/abhinavmadake/caliper-probe:latest}"

if [ -f "cosign.key" ]; then
    echo "Signing $IMAGE with local key..."
    cosign sign --key cosign.key -y "$IMAGE"
else
    echo "Signing $IMAGE with keyless signature..."
    cosign sign --yes "$IMAGE"
fi

# Verify the signature
echo "Verifying signature for $IMAGE..."
if [ -f "cosign.pub" ]; then
    cosign verify --key cosign.pub "$IMAGE"
else
    cosign verify --certificate-identity "https://github.com/Abhinavmadake/caliper/.github/workflows/ci.yml@refs/heads/main" --certificate-oidc-issuer "https://token.actions.githubusercontent.com" "$IMAGE"
fi
