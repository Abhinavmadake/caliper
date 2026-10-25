# Attribution accuracy against constructed ground truth

Issue #44 evaluates attribution against deliberately constructed, single-cause
denial environments. This is distinct from the six-cell matrix: real cells can
apply seccomp, capabilities, LSMs and kernel limits at once, so their ground
truth is not observable from inside a workload.

The suite is in [`fixtures/ground-truth/attribution.json`](../fixtures/ground-truth/attribution.json).
Each case supplies one denial, its known cause, the observed errno/verdict, and
the process-visible facts that CALIPER is allowed to use. It includes both
ambiguous cases required by §6.1:

- an `ENOSYS`-returning seccomp filter; and
- an LSM-only `EACCES` denial under an enforcing AppArmor label.

Run the metric from `control/`:

```sh
go run ./cmd/caliper-attribution-accuracy \
  -ground-truth ../fixtures/ground-truth/attribution.json \
  -out ../fixtures/metrics/attribution-accuracy.json
```

The output reports correct attribution over attributed denials and undecidable
fraction over all denials. The issue gate is at least 90% correct attribution
and no more than 10% undecidable denials.
