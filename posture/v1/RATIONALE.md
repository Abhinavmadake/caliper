# Rationale for Reference Posture v1

## untrusted-multi-tenant

This tier describes workloads from untrusted operators in a multi-tenant environment, where the hypervisor or node kernel is shared. It is stronger than the standard `Restricted` Pod Security Standard.

### socket-address-family / af-alg
**Expectation:** denied
**Rationale:** The kernel crypto API (AF_ALG) exposes a significant amount of kernel surface that has been subject to vulnerabilities, such as CVE-2026-31431. Typical workloads do not need direct access to the kernel crypto API.

### io-uring
**Expectation:** denied
**Rationale:** `io_uring` allows bypassing standard syscall filtering mechanisms by submitting operations via shared memory rings. This has been a recurring source of escapes. Containerd 2.0+ denies `io_uring` by default.

### netlink / netlink-raw
**Expectation:** denied
**Rationale:** Raw netlink sockets allow workloads to introspect and modify deep network configuration, which is unnecessary for standard application workloads and presents an escape vector.
