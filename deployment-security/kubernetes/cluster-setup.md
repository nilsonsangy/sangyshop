# Local cluster setup

Any local Kubernetes works for these manifests. Pick one; k3d is the lightest if you
already have Docker.

## Option A - k3d (k3s in Docker)

```
curl -s https://raw.githubusercontent.com/k3d-io/k3d/main/install.sh | bash
k3d cluster create demo --servers 1 --agents 2
kubectl get nodes          # 3 nodes Ready
kubectl cluster-info
# teardown when done:
# k3d cluster delete demo
```

## Option B - kind / minikube

```
kind create cluster --name demo
# or
minikube start
```

## Build the images into the cluster

The manifests use `imagePullPolicy: IfNotPresent` with local tags, so make the images
available to the cluster first:

```
# build both images (from the repo root)
docker build -t sangyshop:insecure -f deployment-security/docker/insecure/Dockerfile .
docker build -t sangyshop:hardened -f deployment-security/docker/hardened/Dockerfile .

# import them into the local cluster
k3d image import sangyshop:insecure sangyshop:hardened -c demo
# (kind: `kind load docker-image sangyshop:insecure --name demo`, etc.)
```

## Create the secret out-of-band (hardened side)

Never commit the real secret. Create it directly in the cluster:

```
kubectl create namespace sangyshop-hardened
kubectl -n sangyshop-hardened create secret generic sangyshop-db \
  --from-literal=DB_PASSWORD="choose-a-real-secret"
```

> **Network Policies need a CNI that enforces them.** k3d/k3s ships one that does; on some
> minimal setups a default-deny policy has no effect until you install a supporting CNN.
