# Kubernetes - insecure vs hardened

The same SangyShop app, deployed two ways on a local cluster. See
[`cluster-setup.md`](./cluster-setup.md) to spin up a cluster and build/import the images.

## Apply

```
# insecure baseline
kubectl apply -f deployment-security/kubernetes/insecure/sangyshop-insecure.yaml

# hardened (create the secret first - see cluster-setup.md)
kubectl apply -f deployment-security/kubernetes/hardened/sangyshop-hardened.yaml

kubectl get pods -A -l app=sangyshop
```

## Risk -> countermeasure

| Insecure (`insecure/`) | Hardened (`hardened/`) |
|---|---|
| namespace without Pod Security Standards | namespace labeled `pod-security.kubernetes.io/enforce: restricted` |
| `privileged: true`, `runAsUser: 0` | `runAsNonRoot`, `privileged: false`, `cap drop ALL`, `readOnlyRootFilesystem` (with writable `/app/config` + `/app/logs`), `seccomp RuntimeDefault` |
| `hostNetwork` / `hostPID` / `hostPath` to `/` | none; the Pod cannot reach the node |
| ServiceAccount bound to `cluster-admin` | empty namespaced Role; token not mounted |
| plaintext `Secret` in the manifest | secret created out-of-band; etcd encryption-at-rest in real clusters |
| no NetworkPolicy (flat network) | default-deny ingress + explicit allow on 3000 |
| no resource limits | `requests`/`limits` for CPU and memory |

## Measure the difference

```
# CIS benchmark of the cluster config (manifests live in kube-bench/ - see that README)
kubectl apply -f kube-bench/job-master.yaml
kubectl logs job/kube-bench-master

# active surface probing from inside a Pod
kubectl run kube-hunter --image=aquasec/kube-hunter --restart=Never -it -- --pod

# cluster inventory + component CVEs
trivy k8s --format cyclonedx --output kbom.cdx.json cluster
trivy k8s --scanners vuln --report summary cluster

# runtime detection (one Pod per node), then trigger something suspicious
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm install falco falcosecurity/falco --namespace falco --create-namespace --set driver.kind=modern_ebpf
kubectl logs -n falco -l app.kubernetes.io/name=falco -f
```

The hardened side should show fewer reachable kube-hunter findings, and - because Pod
Security Standards reject the unsafe Pod outright - less to detect at runtime.

> **kube-bench measures the cluster, not the app.** The versioned kube-bench manifests
> live in [`kube-bench/`](./kube-bench/) (one Job per node, run inside the cluster because
> there is no kube-bench binary on the Windows host). Its PASS/FAIL counts reflect the
> **cluster/node configuration** and are the **same** on the insecure and hardened sides;
> see [`kube-bench/README.md`](./kube-bench/README.md).
