# Reference posture rationale

Issue #21 defines the names and scope of the reference posture. It does not
yet assign probe expectations; those assertions are authored in #22 and the
document is versioned in #23.

The tiers are named after the Kubernetes Pod Security Standards (PSS) levels
from the Kubernetes documentation: [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/).
The names are deliberately not a restatement of PSS. PSS evaluates fields in a
pod's declared configuration, while this posture evaluates the kernel surface
that the running workload can actually reach.

## privileged

This is the floor for node-facing infrastructure: CNI plugins, CSI/storage
drivers, and node agents may need host administration interfaces. It is named
after PSS Privileged and is intentionally not stronger than that level. Keeping
the tier lets the evaluator detect a workload that was granted the privileged
floor when a narrower tier would have described it.

## baseline

Baseline describes ordinary trusted services such as internal APIs, batch
workers, and monitoring components. PSS Baseline removes obvious pod-level
escape mechanisms (privileged mode, host namespaces, and hostPath), but does
not specify which argument-level kernel families a default-profile container
can reach. The baseline posture adds those expectations without changing what
PSS itself means.

## restricted

Restricted describes services that process untrusted requests in a normal
hardened deployment: public APIs, ingress controllers, and image-processing
workers. PSS Restricted requires non-root execution, dropped capabilities, and
RuntimeDefault seccomp. RuntimeDefault is supplied by the runtime and can
change with the node image, so this posture is deliberately stronger: it keeps
the expected kernel surface stable even when the manifest is unchanged.

## untrusted-multi-tenant

This tier describes code the operator does not trust while other tenants share
the node: pull-request CI, serverless functions, and SaaS/customer plugin
sandboxes. It is named after PSS Restricted because Kubernetes defines no PSS
level above Restricted; that absence is the point. The tier strengthens
Restricted with a defense-in-depth model covering kernel crypto, module
loading, perf events, raw netlink, io_uring, the 32-bit ABI, unmasked procfs,
and other high-consequence entry families. The evaluator can therefore report
an expectation violation even when the pod manifest is valid PSS Restricted.

## Assertions (#22)

Each entry below corresponds to one assertion in `posture.yaml`. Deferred
families are intentionally retained as assertions so the evaluator can report
"asserted, not measured" until issue #20 implements their probes.

### `socket.family.af_alg` — kernel crypto API and module autoload

AF_ALG is an argument-level entry point to the kernel crypto API and can cause
`algif_*` module resolution on first use. Copy Fail (CVE-2026-31431) was
reachable through `algif_aead` from a container satisfying ordinary Restricted
expectations. CVE-2017-2636 provides additional evidence that autoloaded kernel
components can become an escalation path.

### Raw netlink families

The selected netfilter, XFRM, crypto, and RDMA protocols are control-plane
interfaces rather than ordinary application networking. CVE-2024-1086 shows
why reachable netfilter operations can become a kernel escalation path, so raw
access is inappropriate for a multi-tenant sandbox.

### `io_uring`

io_uring provides many asynchronous operations behind a small set of entry
points and has repeatedly been removed from default container profiles. The
kernel io_uring documentation establishes the interface and its breadth; the
posture assertion keeps the desired denial independent of runtime version.

### `perf_event_open` (deferred)

Performance counters expose kernel observations that a tenant does not need.
CVE-2013-2094 is the cited historical privilege-escalation example; until #20
implements the family, the evaluator reports this as asserted-but-not-measured.

### Masked procfs paths

`/proc/kcore` and `/proc/keys` are host-sensitive views. OCI's `maskedPaths`
contract exists specifically to remove such views from a container, so the
baseline and tenant tiers assert that the corresponding probes remain
unreachable.

### User namespaces

User namespaces can turn an unprivileged process into a namespace root with a
larger kernel attack surface. CVE-2022-0185 demonstrates why a multi-tenant
posture treats the `newuser` probes as an expectation violation even if a
runtime permits their syscall entry.

### BPF (deferred)

The deferred BPF family covers verifier and program-loading bugs that have
historically crossed the privilege boundary. CVE-2017-16995 supplies the
cited example; the assertion remains independent of whether #20 has landed.

### Keyrings (deferred)

Kernel keyring operations expose shared credential and key-management state.
CVE-2016-0728 is the cited keyring escalation, so customer code should not
reach this family in the multi-tenant tier.

### `userfaultfd` (deferred)

Userfaultfd lets a process interpose on page faults, a primitive used to build
exploitation races. The Linux kernel administration guide documents the
interface and its controls; the posture keeps it outside the tenant surface.

### `open_by_handle_at` (deferred)

File-handle lookup bypasses normal pathname assumptions and is not a service
requirement. The Shocker proof of concept is a concrete cited escape
technique, so the deferred family is still asserted against.

### Restricted io_uring

Restricted services process untrusted input but do not need the broad
asynchronous kernel interface. This turns runtime-profile drift into an
explicit expectation violation instead of silently accepting a weaker node.

### Restricted capability effects

Restricted workloads should have dropped all capabilities. The selected probes
cover module loading, reboot, clock setting, raw I/O, and ptrace; the
`capabilities(7)` reference supplies the kernel contract rather than relying on
CALIPER's authority.

### Baseline mount

Ordinary services do not need to create or probe mount filesystems. The
`mount(2)` contract and CAP_SYS_ADMIN gate support treating mount reach as a
baseline expectation violation.

### Baseline device nodes

FUSE, KVM, and raw-memory device nodes expose host drivers or hardware state.
The OCI Linux resources specification documents device-cgroup controls, which
is the external basis for asserting that ordinary services should not reach
these nodes.
