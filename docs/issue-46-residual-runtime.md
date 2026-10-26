# Residual state and runtime cost

Issue #46 reports two §11.2 criteria from one set of runs: zero unreclaimed
objects after a full run across the six classes of §6.2, with autoloaded
modules reported apart, and the full corpus under 60 s and the reduced corpus
under 5 s.

The runs are in `fixtures/runtime/`: the full and the reduced corpus on cells 1
to 6, each from a fresh boot (`cells.sh measure`, `CALIPER_CORPUS_SET=reduced`
for the reduced one), and `cell2-none.json`, the full corpus on cell 2 with
every control off (`measure.sh`'s ground-truth mode `none`). Images are local
builds of `9dde9c1`; the `.packages` files have the IDs.

```sh
cd control && go run ./cmd/caliper-residual-metrics -out ../fixtures/metrics/residual-metrics.json
```

The test regenerates the metric from `fixtures/runtime/` and compares it with
the committed file.

## How each class is counted

The engine snapshots every class before and after each probe, after the child
is reaped, and before and after the run (`engine/crates/engine/src/residual.rs`):

| Class | Source |
|---|---|
| mounts | lines of `/proc/self/mountinfo` |
| keyrings | lines of `/proc/keys`; where it is masked (RuntimeDefault), `nkeys` of the process's fsuid in `/proc/key-users` |
| cgroups | directories below `/sys/fs/cgroup` |
| sysv_ipc | entries in `/proc/sysvipc/{shm,sem,msg}` |
| posix_ipc | entries in `/dev/shm` and `/dev/mqueue` |
| net_namespaces | distinct `ns/net` links among visible processes |

A class the environment does not expose is `null`, never `0`. The
`/proc/key-users` fallback is new here: before it, keyrings were unobservable
in every RuntimeDefault cell. It was checked in a masked container by adding a
key to the user keyring and unlinking it (71, 72, 71). How soon the count
drops after a key is removed was not measured; no probe creates keys today.

`unreclaimed_objects` is the growth of each counted class over the run.
`leaks` counts per-probe changes, so an object one probe leaves and a later
one removes still fails the criterion. Modules loaded by the run are listed
per run and not counted.

## Result

| Run | Full ms | Reduced ms | Classes counted | Unreclaimed | Leaks |
|---|---:|---:|---|---:|---:|
| cell1 (arm64) | 241 | 56 | 6 | 0 | 0 |
| cell2 | 585 | 158 | 6 | 0 | 0 |
| cell3 (SELinux) | 247 | 175 | 6 | 0 | 0 |
| cell4 (containerd 1.7) | 629 | 175 | 6 | 0 | 0 |
| cell5 (gVisor) | 8632 | 2851 | 3 | 0 | 0 |
| cell6 (Kata) | 109 | 92 | 6 | 0 | 0 |
| cell2, controls off | 899 | | 6 | 0 | 0 |

All three criteria are met. The slowest full run is gVisor at 8.6 s, the
slowest reduced one gVisor at 2.9 s. `ci.yml` also times the reduced corpus on
the CI runner (`scripts/check-reduced-runtime.sh`).

gVisor exposes neither keyrings nor either IPC class, so its zero covers three
classes. Kata exposes no module list, so cell 6 reports no autoload.

## What the zero covers

Only two classes have probes that create objects: mounts (4 probes) and
network namespaces (4). Under RuntimeDefault none of them is permitted, except
two network-namespace probes under gVisor, so a zero there means nothing was
created. `cell2-none.json` is the run in which all eight are permitted and
create their objects, and it ends with nothing left. No probe creates
keyrings, cgroups or IPC objects; the engine's leak tests
(`engine/crates/engine/tests/effects.rs`) are the evidence that those classes
would be caught.
