
## Installation

Afin de déployer les fonctions OpenFaas, il est nécessaire au préalable de posséder un cluster Kubernetes ainsi qu'une base de données PostgreSQL.

Installation d'OpenFaas via le Chart Helm

```bash
kubectl apply -f https://raw.githubusercontent.com/openfaas/faas-netes/master/namespaces.yml
helm repo add openfaas https://openfaas.github.io/faas-netes/
helm repo update && helm upgrade openfaas --install openfaas/openfaas --namespace openfaas -f values.yml
```

Build, push et déploiement des fonctions

```bash
./launch.sh
```