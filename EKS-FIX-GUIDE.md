# EKS Authentication Fix Guide

## Problem
GitHub Actions cannot authenticate with your EKS cluster because the IAM user is not authorized in the cluster's aws-auth ConfigMap.

## Solution - Choose ONE of the following options:

### Option 1: Add IAM User to EKS Cluster (Quickest)

1. **Get your IAM user ARN:**
   ```bash
   aws sts get-caller-identity
   ```
   This will show your IAM user ARN (e.g., `arn:aws:iam::123456789012:user/your-username`)

2. **Edit the aws-auth ConfigMap:**
   ```bash
   kubectl edit configmap aws-auth -n kube-system
   ```

3. **Add your IAM user under `mapUsers`:**
   ```yaml
   mapUsers: |
     - userarn: arn:aws:iam::YOUR_ACCOUNT_ID:user/YOUR_IAM_USERNAME
       username: github-actions
       groups:
         - system:masters
   ```

4. **Save and exit** (`:wq` in vim or Ctrl+O in nano)

### Option 2: Create IAM Role for GitHub Actions (Recommended)

1. **Create an IAM role with these permissions:**
   - `EKSFullAccess` or custom policy with `eks:*` permissions
   - Trust relationship allowing your IAM user to assume it

2. **Add the role to aws-auth ConfigMap:**
   ```bash
   kubectl edit configmap aws-auth -n kube-system
   ```
   
   Add under `mapRoles`:
   ```yaml
   mapRoles: |
     - rolearn: arn:aws:iam::YOUR_ACCOUNT_ID:role/GitHubActionsEKSRole
       username: github-actions-role
       groups:
         - system:masters
   ```

3. **Update GitHub workflow to assume the role:**
   Add to the "Configure AWS credentials" step:
   ```yaml
   role-to-assume: arn:aws:iam::YOUR_ACCOUNT_ID:role/GitHubActionsEKSRole
   role-session-name: GitHubActionsSession
   ```

### Option 3: Use EKS Access Entries (EKS 1.23+)

If your EKS cluster version is 1.23 or higher:

```bash
aws eks create-access-entry \
  --cluster-name dev-cluster \
  --principal-arn arn:aws:iam::YOUR_ACCOUNT_ID:user/YOUR_IAM_USERNAME \
  --type STANDARD \
  --region ap-south-1

aws eks associate-access-policy \
  --cluster-name dev-cluster \
  --principal-arn arn:aws:iam::YOUR_ACCOUNT_ID:user/YOUR_IAM_USERNAME \
  --policy-arn arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy \
  --access-scope type=cluster \
  --region ap-south-1
```

## Required IAM Permissions for GitHub Actions User

Ensure your IAM user has these permissions:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "eks:DescribeCluster",
        "eks:ListClusters"
      ],
      "Resource": "*"
    }
  ]
}
```

## Verify Setup

After making changes, test from your local machine:
```bash
aws eks update-kubeconfig --name dev-cluster --region ap-south-1
kubectl get nodes
```

If this works locally, it should work in GitHub Actions with the same credentials.

## Additional Troubleshooting

1. **Check if cluster exists:**
   ```bash
   aws eks describe-cluster --name dev-cluster --region ap-south-1
   ```

2. **Verify current identity:**
   ```bash
   aws sts get-caller-identity
   ```

3. **Check aws-auth ConfigMap:**
   ```bash
   kubectl get configmap aws-auth -n kube-system -o yaml
   ```

4. **View current access entries (EKS 1.23+):**
   ```bash
   aws eks list-access-entries --cluster-name dev-cluster --region ap-south-1
   ```
