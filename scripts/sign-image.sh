#!/bin/bash
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
    cosign verify --certificate-identity-regexp ".*" --certificate-oidc-issuer-regexp ".*" "$IMAGE"
fi
