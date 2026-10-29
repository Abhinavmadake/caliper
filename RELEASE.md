# Releases

A release is a `v*` tag on `main`. `.github/workflows/release.yml` then:

1. builds the probe image from the tag on a native amd64 and a native arm64
   runner (`engine/Dockerfile`), and checks each with `--noop`;
2. joins them as one multi-architecture image,
   `ghcr.io/abhinavmadake/caliper:<tag>`, and signs its digest with cosign,
   keyless, through GitHub's OIDC identity for this workflow;
3. creates the GitHub release with the reference posture
   (`posture-v1.yaml` and its rationale) and the corpus index
   (`corpus-<revision>.json`) attached, and the signed digest in its notes.

```sh
git tag -a v1.0.0 -m "CALIPER v1.0.0" && git push origin v1.0.0
```

## Verifying the probe image

Run the image by the digest in the release notes, after checking its
signature. Admission controllers and runtime security tooling can allowlist
the same identity, so that a deliberate CALIPER run is not mistaken for an
attack (proposal §12).

```sh
cosign verify ghcr.io/abhinavmadake/caliper@sha256:<digest> \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github\.com/Abhinavmadake/caliper/\.github/workflows/release\.yml@refs/tags/v'
```

A valid signature proves the image was built by this repository's release
workflow from a `v*` tag. Any other image, including the `pr-<sha>` images CI
builds for pull requests, is unsigned and not a release.

## What a release is, and is not

CALIPER measures and reports what the kernel permits a container to reach. It
does not enforce anything, and it is not a substitute for seccomp, an LSM,
dropped capabilities or the other mechanisms whose effect it measures. The
generated remediation profiles are inputs for an operator to review and apply.

Run it only on infrastructure you own or have written authorisation to test.
