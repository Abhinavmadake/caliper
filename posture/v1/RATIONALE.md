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
