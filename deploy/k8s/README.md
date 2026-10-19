# Caliper Kubernetes Manifests

These manifests deploy the caliper-probe on a Kubernetes cluster. They satisfy the Pod Security Standards (PSS) Restricted profile, ensuring the instrument uses no more privileges than it needs, and making it deployable on hardened clusters.

## Retrieving the Fingerprint

The probe writes its fingerprint directly to stdout. There are no volume mounts for data and no sidecars required. 

### For the Job

The Job writes the fingerprint to its pod's standard output. You can retrieve it by redirecting the logs:

```bash
kubectl logs job/caliper-probe > fingerprint.json
```

### For the DaemonSet

The DaemonSet deploys the probe across multiple nodes. The probe is an init
container: it measures once, then the restricted pause container keeps the pod
alive so the DaemonSet does not restart the measurement. Retrieve the completed
init-container logs by label, prefixing output with the pod name to distinguish
nodes:

```bash
kubectl logs -l app=caliper-probe -c probe --prefix --tail=-1
```

Delete a DaemonSet pod only when you intentionally want to measure that node
again; its replacement will run the probe once.
