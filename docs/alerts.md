# Alert-Safe Reduced Corpus and Image Signatures

When running `caliper-probe`, the instrument performs actions designed to test the boundary of the kernel's sandboxing and confinement mechanisms. Because of this, it is highly likely that standard runtime security monitors (like Falco, Tetragon, or Tracee) will flag the instrument as malicious behavior.

To address this, we provide two mechanisms to ensure operators can run the probe without unintentionally setting off alarms.

## 1. Image Signatures

Future published container images for the `caliper-probe` will be cryptographically signed using [Cosign](https://github.com/sigstore/cosign). 
This allows operators and security teams to verify the authenticity of the probe before execution and deliberately allowlist the image digest in their runtime monitors.

A script is provided at `scripts/sign-image.sh` to illustrate how the image is signed during our release process.

## 2. Alert-Safe Reduced Corpus

The instrument provides an `--reduced` flag:

```bash
caliper-probe --reduced
```

When this flag is passed, the engine runs a **reduced corpus** that omits the probes most likely to trigger high-severity alerts.

### Omitted Probes and Rationale

The probes omitted from the reduced corpus are those that declare the `module_autoload: true` side-effect. These include:

* **`AF_ALG` (Cryptographic API)**: The `AF_ALG` probe attempts to bind to the kernel's cryptographic API. This action is omitted because published Copy Fail detection rules specifically key on `AF_ALG` socket creation as an indicator of compromise (see proposal §12). 
* **Socket Families and Netlink Protocols**: Attempting to create sockets for uncommon families (like `AF_VSOCK`, `AF_XDP`) or netlink protocols can cause the kernel to autoload modules. This side-effect is un-reclaimable and often triggers module-loading alerts in runtime security tooling.

By omitting these probes, the reduced corpus allows the instrument to evaluate the vast majority of the kernel surface without triggering the specific rules in monitors that track `AF_ALG` and module loading.
