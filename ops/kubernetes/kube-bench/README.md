# kube-bench: CIS audit of the cluster

[kube-bench](https://github.com/aquasecurity/kube-bench) is the Aqua Security tool
that automatically checks whether the cluster follows the **CIS Kubernetes
Benchmark**. It inspects configuration files, permissions and flags of the
control-plane components (API server, scheduler, controller-manager, etcd) and of the
nodes (kubelet), and emits a report with each item marked **PASS**, **FAIL** or
**WARN**.

## Why we run it as a Job in the cluster (and not as a binary on the host)

Here the cluster is a **kind** cluster on top of Docker Desktop: each "node" (control-plane
and workers) is actually a Linux container. kube-bench needs to see the configuration
files **from inside the Linux node**, and there is no kube-bench binary running on the
**Windows** host. Running kube-bench locally on Windows would not audit anything in the
cluster.

The solution is to run the tool as an **ephemeral Job inside the cluster itself**. Each
Job starts a Pod on the node we want to audit, mounts the relevant node paths
**read-only** (`readOnly: true`), runs kube-bench, prints the report to the log
and finishes (`restartPolicy: Never`). The Pods change nothing on the node, they only read.

- `job-master.yaml` audits the **control-plane** (`--targets master`). It uses
  `affinity`/`tolerations` to land on the `desktop-control-plane` node and also mounts
  `/etc/passwd` and `/etc/group`.
- `job-node-worker1.yaml` audits the kubelet of **worker 1** (`--targets node`), pinned
  to `nodeName: desktop-worker`.
- `job-node-worker2.yaml` audits the kubelet of **worker 2** (`--targets node`), pinned
  to `nodeName: desktop-worker2`.

## What kube-bench measures (and what it does NOT measure)

kube-bench audits the **configuration of the cluster and of the nodes**: the control-plane
and the kubelets. It does **not** look at the SangyShop manifests. That is why the
kube-bench result is **the same** whether SangyShop is on the *insecure* or the *hardened*
deployment: the cluster posture does not change when you swap the application manifests.

What reflects the **insecure vs hardened** difference of the application is **kube-hunter**
(which looks for attack surface exposed by the Pods) and **Falco** (runtime detection).
kube-bench sits in a different layer: it measures the **posture of the cluster** itself.

## Commands (PowerShell / Windows, Docker Desktop kind cluster)

Cluster nodes: `desktop-control-plane`, `desktop-worker`, `desktop-worker2`.

```powershell
# 0) (once) pull the pinned image
docker pull aquasec/kube-bench:v0.16.0

# 1) audit the CONTROL-PLANE
kubectl apply -f job-master.yaml
kubectl wait --for=condition=complete job/kube-bench-master --timeout=600s
kubectl logs job/kube-bench-master | Tee-Object .\report-control-plane.txt
kubectl delete job kube-bench-master

# 2) audit WORKER 1 (desktop-worker)
kubectl apply -f job-node-worker1.yaml
kubectl wait --for=condition=complete job/kube-bench-node-worker1 --timeout=600s
kubectl logs job/kube-bench-node-worker1 | Tee-Object .\report-worker1.txt
kubectl delete job kube-bench-node-worker1

# 3) audit WORKER 2 (desktop-worker2)
kubectl apply -f job-node-worker2.yaml
kubectl wait --for=condition=complete job/kube-bench-node-worker2 --timeout=600s
kubectl logs job/kube-bench-node-worker2 | Tee-Object .\report-worker2.txt
kubectl delete job kube-bench-node-worker2
```

## Reference results (measured on this cluster)

Measured on a **kind v1.34.11** cluster with **kube-bench v0.16.0**. They are a snapshot
of the **default kind cluster configuration**, and, as explained above, they are
**independent** of whether SangyShop is insecure or hardened.

| Target | PASS | FAIL | WARN |
|---|---|---|---|
| control-plane (`--targets master`) | 39 | 10 | 11 |
| worker `desktop-worker` (`--targets node`) | 17 | 2 | 6 |
| worker `desktop-worker2` (`--targets node`) | 17 | 2 | 6 |

Examples of **FAIL** on the control-plane: `1.2.15` / `1.4.1` (the `--profiling` flag is not
`false`); `1.2.16`-`1.2.19` (audit log not configured); `1.1.12` (owner of the etcd
data directory).

Examples of **FAIL** on each worker: `4.1.1` (permissions of the kubelet service
file); `4.1.9` (permissions of the kubelet `config.yaml`).

The two workers are **identical nodes**, so they show exactly the same numbers.
