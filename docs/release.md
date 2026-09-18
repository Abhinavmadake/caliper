# CALIPER Release Documentation

## Scope and Intent
CALIPER is an instrument designed to **measure and report** on container confinement. It does not enforce policy, and is not a substitute for the mechanisms whose effect it measures (e.g., AppArmor, SELinux, Seccomp).

> [!WARNING]
> **Authorisation Required:** This instrument is intended ONLY for infrastructure the operator owns or has written authorisation to test. Do not run CALIPER on environments without explicit permission.

## Probe Image Signature
The published probe image (`caliper-probe`) is signed to provide a documented signature. Operators can verify this signature and intentionally allowlist the image in their runtime security tooling to prevent false positive alerts during legitimate measurement runs.

## Corpus Safety
We confirm that the CALIPER corpus **contains no exploit code**. Furthermore, no operation performed by the probes has a success state that confers privilege. All operations are safe enumerations or deliberately crafted failing operations to trigger specific `errno` responses.
