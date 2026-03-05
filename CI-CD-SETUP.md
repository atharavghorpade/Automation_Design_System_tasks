# CI/CD Setup Guide

This guide explains how to configure the GitHub Actions CI/CD pipeline for deploying to AWS EKS.

## Prerequisites

1. AWS Account with EKS cluster created
2. GitHub repository with the application code
3. Docker registry (AWS ECR recommended)

## Required GitHub Secrets

Navigate to your GitHub repository → Settings → Secrets and variables → Actions, and add the following secrets:

### AWS Secrets
- **AWS_ACCESS_KEY_ID**: Your AWS access key ID
- **AWS_SECRET_ACCESS_KEY**: Your AWS secret access key

### Docker Registry Secrets
- **DOCKER_REGISTRY_URL**: Your ECR registry URL (e.g., `123456789.dkr.ecr.us-east-1.amazonaws.com`)
- **DOCKER_USERNAME**: AWS (for ECR)
- **DOCKER_PASSWORD**: Your ECR password (get it using: `aws ecr get-login-password --region us-east-1`)

## Environment Variables to Update

Edit [.github/workflows/ci-cd.yml](.github/workflows/ci-cd.yml) and update:

```yaml
env:
  AWS_REGION: us-east-1                    # Your AWS region
  EKS_CLUSTER_NAME: my-eks-cluster         # Your EKS cluster name
  ECR_REPOSITORY: automation-design-system  # Your ECR repository name
```

## AWS EKS Setup

### 1. Create ECR Repository

```bash
aws ecr create-repository \
  --repository-name automation-design-system \
  --region us-east-1
```

### 2. Create EKS Cluster (if not exists)

```bash
eksctl create cluster \
  --name my-eks-cluster \
  --region us-east-1 \
  --nodegroup-name standard-workers \
  --node-type t3.medium \
  --nodes 2 \
  --nodes-min 1 \
  --nodes-max 4 \
  --managed
```

### 3. Configure kubectl

```bash
aws eks update-kubeconfig --name my-eks-cluster --region us-east-1
```

### 4. Create namespaces and secrets manually (first time)

```bash
# Create namespace
kubectl create namespace default

# Create ECR registry secret
kubectl create secret docker-registry ecr-registry-secret \
  --docker-server=<your-ecr-url> \
  --docker-username=AWS \
  --docker-password=$(aws ecr get-login-password --region us-east-1) \
  --namespace=default
```

## Workflow Triggers

The workflow triggers on push to:
- `main` branch
- `develop` branch

And only when changes are made to:
- `src/**` directory
- `pom.xml` file
- `Dockerfile`

## Pipeline Jobs

### 1. Build Job
- Checks out code
- Sets up JDK 21
- Builds with Maven
- Runs tests
- Uploads build artifacts

### 2. Push Job
- Downloads build artifacts
- Builds Docker image
- Pushes to ECR with commit SHA tag and `latest` tag
- Scans image for vulnerabilities

### 3. Deploy Job
- Updates kubeconfig
- Creates/updates Docker registry secret
- Applies Kubernetes deployment
- Verifies deployment rollout
- Displays service endpoint

## Local Testing

### Test Docker build locally:

```bash
# Build the image
docker build -t automation-design-system:local .

# Run the container
docker run -p 8080:8080 automation-design-system:local
```

### Test Kubernetes deployment locally:

```bash
# Update image in deployment.yaml
sed -i 's|IMAGE_TAG|your-ecr-url/automation-design-system:latest|g' deployment.yaml

# Apply to cluster
kubectl apply -f deployment.yaml

# Check deployment status
kubectl get deployments
kubectl get pods
kubectl get services
```

## Monitoring

### View logs:

```bash
# Get pod name
kubectl get pods -n default

# View logs
kubectl logs <pod-name> -n default -f
```

### Check deployment status:

```bash
kubectl rollout status deployment/automation-design-system -n default
```

### Get service endpoint:

```bash
kubectl get service automation-design-system -n default
```

## Troubleshooting

### Image pull errors:
```bash
# Recreate ECR secret
kubectl delete secret ecr-registry-secret -n default
kubectl create secret docker-registry ecr-registry-secret \
  --docker-server=<your-ecr-url> \
  --docker-username=AWS \
  --docker-password=$(aws ecr get-login-password --region us-east-1) \
  --namespace=default
```

### Deployment not updating:
```bash
# Force rollout restart
kubectl rollout restart deployment/automation-design-system -n default
```

### Check pod events:
```bash
kubectl describe pod <pod-name> -n default
```

## Security Best Practices

1. ✅ Use IAM roles for service accounts (IRSA) instead of access keys
2. ✅ Enable ECR image scanning
3. ✅ Use private subnets for EKS nodes
4. ✅ Enable EKS cluster logging
5. ✅ Use Secrets Manager for sensitive data
6. ✅ Implement network policies
7. ✅ Regular security updates for base images

## Cost Optimization

1. Use spot instances for non-production environments
2. Implement cluster autoscaler
3. Right-size your pods (adjust resource requests/limits)
4. Use ECR lifecycle policies to clean up old images

## Additional Configuration

### Update application resources:

Edit [deployment.yaml](deployment.yaml):

```yaml
resources:
  requests:
    memory: "512Mi"
    cpu: "250m"
  limits:
    memory: "2Gi"
    cpu: "1000m"
```

### Update HPA (Horizontal Pod Autoscaler):

Already configured in deployment.yaml with:
- Min replicas: 2
- Max replicas: 10
- CPU threshold: 70%
- Memory threshold: 80%

## Support

For issues or questions, refer to:
- [AWS EKS Documentation](https://docs.aws.amazon.com/eks/)
- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Kubernetes Documentation](https://kubernetes.io/docs/)
