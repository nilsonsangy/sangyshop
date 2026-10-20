# kube-bench — auditoria CIS do cluster

O [kube-bench](https://github.com/aquasecurity/kube-bench) é a ferramenta da Aqua
Security que confere, de forma automatizada, se o cluster segue o **CIS Kubernetes
Benchmark**. Ele inspeciona arquivos de configuração, permissões e flags dos
componentes do control-plane (API server, scheduler, controller-manager, etcd) e dos
nós (kubelet), e emite um relatório com cada item marcado como **PASS**, **FAIL** ou
**WARN**.

## Por que rodamos como Job no cluster (e não como binário no host)

Aqui o cluster é um **kind** em cima do Docker Desktop: cada "nó" (control-plane e
workers) é, na verdade, um container Linux. O kube-bench precisa enxergar os arquivos
de configuração **de dentro do nó Linux** — e não existe binário kube-bench rodando no
host **Windows**. Rodar o kube-bench localmente no Windows não auditaria coisa alguma do
cluster.

A solução é rodar a ferramenta como um **Job efêmero dentro do próprio cluster**. Cada
Job sobe um Pod no nó que queremos auditar, monta os caminhos relevantes do nó em
**somente leitura** (`readOnly: true`), executa o kube-bench, imprime o relatório no log
e termina (`restartPolicy: Never`). Os Pods não alteram nada no nó — só leem.

- `job-master.yaml` — audita o **control-plane** (`--targets master`). Usa
  `affinity`/`tolerations` para cair no nó `desktop-control-plane` e monta também
  `/etc/passwd` e `/etc/group`.
- `job-node-worker1.yaml` — audita o kubelet do **worker 1** (`--targets node`), fixado
  em `nodeName: desktop-worker`.
- `job-node-worker2.yaml` — audita o kubelet do **worker 2** (`--targets node`), fixado
  em `nodeName: desktop-worker2`.

## O que o kube-bench mede (e o que NÃO mede)

O kube-bench audita a **configuração do cluster e dos nós** — o control-plane e os
kubelets. Ele **não** olha os manifestos da SangyShop. Por isso o resultado do kube-bench
é **o mesmo** quer a SangyShop esteja no deployment *insecure* ou no *hardened*: a postura
do cluster não muda ao trocar os manifestos da aplicação.

Quem reflete a diferença **insecure vs hardened** da aplicação é o **kube-hunter** (busca
superfície de ataque exposta pelos Pods) e o **Falco** (detecção em tempo de execução). O
kube-bench fica numa camada diferente: ele mede a **postura do cluster** em si.

## Comandos (PowerShell / Windows — cluster kind do Docker Desktop)

Nós do cluster: `desktop-control-plane`, `desktop-worker`, `desktop-worker2`.

```powershell
# 0) (uma vez) baixar a imagem fixada
docker pull aquasec/kube-bench:v0.16.0

# 1) auditar o CONTROL-PLANE
kubectl apply -f job-master.yaml
kubectl wait --for=condition=complete job/kube-bench-master --timeout=600s
kubectl logs job/kube-bench-master | Tee-Object .\report-control-plane.txt
kubectl delete job kube-bench-master

# 2) auditar o WORKER 1 (desktop-worker)
kubectl apply -f job-node-worker1.yaml
kubectl wait --for=condition=complete job/kube-bench-node-worker1 --timeout=600s
kubectl logs job/kube-bench-node-worker1 | Tee-Object .\report-worker1.txt
kubectl delete job kube-bench-node-worker1

# 3) auditar o WORKER 2 (desktop-worker2)
kubectl apply -f job-node-worker2.yaml
kubectl wait --for=condition=complete job/kube-bench-node-worker2 --timeout=600s
kubectl logs job/kube-bench-node-worker2 | Tee-Object .\report-worker2.txt
kubectl delete job kube-bench-node-worker2
```

## Resultados de referência (medidos neste cluster)

Medidos num cluster **kind v1.34.11** com **kube-bench v0.16.0**. São um retrato da
configuração **padrão do cluster kind** — e, como explicado acima, são **independentes**
de a SangyShop estar insecure ou hardened.

| Alvo | PASS | FAIL | WARN |
|---|---|---|---|
| control-plane (`--targets master`) | 39 | 10 | 11 |
| worker `desktop-worker` (`--targets node`) | 17 | 2 | 6 |
| worker `desktop-worker2` (`--targets node`) | 17 | 2 | 6 |

Exemplos de **FAIL** no control-plane: `1.2.15` / `1.4.1` (flag `--profiling` não está
`false`); `1.2.16`–`1.2.19` (audit-log não configurado); `1.1.12` (dono do diretório de
dados do etcd).

Exemplos de **FAIL** em cada worker: `4.1.1` (permissões do arquivo de service do
kubelet); `4.1.9` (permissões do `config.yaml` do kubelet).

Os dois workers são **nós idênticos**, por isso apresentam exatamente os mesmos números.
