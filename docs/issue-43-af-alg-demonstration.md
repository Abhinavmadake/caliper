# AF_ALG RuntimeDefault demonstration

Issue #43's workload is [the standard CALIPER probe Job](../deploy/k8s/af-alg-demonstration.yaml).
It is admitted by a PSS Restricted namespace, runs as a non-root UID with all
capabilities dropped, and requests `RuntimeDefault`. It uses the ordinary
`caliper-probe` image and has neither an AF_ALG-specific image nor a bespoke
seccomp profile.

The evaluator is deliberately run at the `untrusted-multi-tenant` reference
posture tier. That tier is stronger than PSS Restricted; PSS itself makes no
AF_ALG assertion. A permitted `socket.family.af_alg` result is therefore an
**expectation violation**, not a manifest claim violation. The finding carries
the assertion's evidence, including `CVE-2026-31431`, from `posture/v1`.

The automated regression uses the ordinary recorded RuntimeDefault measurement
in `fixtures/x86_64-apparmor.json`, so it detects the reachability without an
exploit image or a custom profile. The separate cell-4 reproduction and the
pre-probe `algif_aead` module snapshot are intentionally outside this artifact.
