# Probe corpus

Owners: A + B. Split between two members because it is the largest single body
of work and because attribution metadata is authored with each probe.

**Committed set** (weeks 4-8, frozen end of week 8): socket address families
and netlink protocol numbers, io_uring opcode reach, mount filesystem types,
clone and unshare flags, masked and read-only path coverage, device node
access, capability effect.

**Deferred set**, specified in the same format so it is additive work rather
than redesign, entered only if the committed set is complete and the schedule
is intact: ioctl request codes, bpf commands and program types, keyctl
operations, prctl options, perf_event_open, userfaultfd, open_by_handle_at,
module loading, seccomp user notification.
