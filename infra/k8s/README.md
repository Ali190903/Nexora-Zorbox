# ZORBOX K8s Manifests (MVP)

Basic Deployments and Services for local cluster testing.

## Components
- Namespace: `zorbox`
- Services: orchestrator (8080), reporter (8090), ti (8070), static-analyzer (8060), sandbox (8050)
- NetworkPolicy: orchestrator egress restricted to internal services

## Usage
```bash
kubectl apply -f infra/k8s/namespace.yaml
kubectl apply -f infra/k8s/static-analyzer.yaml
kubectl apply -f infra/k8s/reporter.yaml
kubectl apply -f infra/k8s/ti.yaml
kubectl apply -f infra/k8s/sandbox.yaml
kubectl apply -f infra/k8s/orchestrator.yaml
```

## Notes
- Set `ti` VirusTotal API key via Secret `vt-api` (edit `infra/k8s/ti.yaml`).
- Images default to `zorbox/*:latest`; adjust for your registry.
- For external access, create NodePort/Ingress as needed.

