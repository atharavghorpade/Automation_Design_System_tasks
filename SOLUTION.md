# 🔧 FIX: GitHub Actions Cannot Access EKS Cluster

## ❌ The Error
```
error: error validating "deployment.yaml": error validating data: 
failed to download openapi: the server has asked for the client to provide credentials
```

## 🎯 Root Cause
Your GitHub Actions IAM user credentials **are not authorized** to access the EKS cluster. AWS authentication works, but Kubernetes doesn't recognize the IAM user.

## ✅ Solution: Add IAM User to EKS aws-auth ConfigMap

### Prerequisites
- Local access to EKS cluster with admin permissions
- AWS CLI configured
- kubectl installed

---

## 🚀 Quick Fix (Run Locally)

### **Option 1: Run PowerShell Script (Windows)**
```powershell
.\FIX-EKS-ACCESS.ps1
```

### **Option 2: Run Bash Script (Linux/Mac)**
```bash
chmod +x FIX-EKS-ACCESS.sh
./FIX-EKS-ACCESS.sh
```

### **Option 3: Manual Steps** (if scripts don't work)

#### Step 1: Find Your GitHub IAM User ARN
```bash
# Run this with the same AWS credentials you added to GitHub Secrets
aws sts get-caller-identity
```
**Copy the ARN** - looks like: `arn:aws:iam::123456789012:user/github-actions-user`

#### Step 2: Update kubeconfig (from your local machine with admin access)
```bash
aws eks update-kubeconfig --name dev-cluster --region ap-south-1
```

#### Step 3: Backup current aws-auth ConfigMap
```bash
kubectl get configmap aws-auth -n kube-system -o yaml > aws-auth-backup.yaml
```

#### Step 4: Edit aws-auth ConfigMap
```bash
kubectl edit configmap aws-auth -n kube-system
```

#### Step 5: Add Your IAM User
Add this section under `data:` → `mapUsers:` (create `mapUsers:` if it doesn't exist):

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: aws-auth
  namespace: kube-system
data:
  mapUsers: |
    - userarn: arn:aws:iam::YOUR_ACCOUNT_ID:user/YOUR_IAM_USERNAME
      username: github-actions
      groups:
        - system:masters
  mapRoles: |
    # Keep existing mapRoles entries here
```

**Replace:**
- `YOUR_ACCOUNT_ID` with your AWS account ID
- `YOUR_IAM_USERNAME` with the IAM user name from GitHub Secrets

#### Step 6: Save and Exit
- In vim: Press `Esc`, then type `:wq` and press Enter
- In nano: Press `Ctrl+O`, then `Ctrl+X`

#### Step 7: Verify
```bash
kubectl get configmap aws-auth -n kube-system -o yaml
```

---

## 🧪 Test the Fix

### On Your Local Machine:
```bash
# Test with GitHub Actions credentials
export AWS_ACCESS_KEY_ID="your-github-secret-access-key"
export AWS_SECRET_ACCESS_KEY="your-github-secret-secret-key"

aws sts get-caller-identity
aws eks update-kubeconfig --name dev-cluster --region ap-south-1
kubectl get nodes
```

If `kubectl get nodes` works, your GitHub Actions will work too!

---

## 📋 Alternative: Use EKS Access Entries (EKS 1.23+)

If your EKS cluster is version 1.23 or higher, use the newer access entry API:

```bash
# Add access entry
aws eks create-access-entry \
  --cluster-name dev-cluster \
  --principal-arn arn:aws:iam::YOUR_ACCOUNT_ID:user/YOUR_IAM_USERNAME \
  --type STANDARD \
  --region ap-south-1

# Associate cluster admin policy
aws eks associate-access-policy \
  --cluster-name dev-cluster \
  --principal-arn arn:aws:iam::YOUR_ACCOUNT_ID:user/YOUR_IAM_USERNAME \
  --policy-arn arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy \
  --access-scope type=cluster \
  --region ap-south-1
```

---

## 🔍 Troubleshooting

### Issue: "configmap aws-auth not found"
The aws-auth ConfigMap doesn't exist. Create it:
```bash
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: aws-auth
  namespace: kube-system
data:
  mapUsers: |
    - userarn: arn:aws:iam::YOUR_ACCOUNT_ID:user/YOUR_USERNAME
      username: github-actions
      groups:
        - system:masters
EOF
```

### Issue: "You don't have admin access to the cluster"
You need someone with cluster admin access to run these commands, or you need to be the IAM user/role that originally created the EKS cluster.

### Issue: "kubectl: command not found"
Install kubectl:
```bash
# Windows (PowerShell)
choco install kubernetes-cli

# Mac
brew install kubectl

# Linux
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
```

### Issue: Still getting authentication error after fix
1. Wait 1-2 minutes for changes to propagate
2. Verify the ARN in aws-auth matches exactly what GitHub is using
3. Check GitHub Secrets are correct (no extra spaces)
4. Ensure IAM user has `eks:DescribeCluster` permission

---

## ✉️ GitHub Secrets Required

Make sure these are set in your repository:
- `AWS_ACCESS_KEY_ID` - IAM user access key
- `AWS_SECRET_ACCESS_KEY` - IAM user secret key
- `DOCKER_USERNAME` - Docker Hub username
- `DOCKER_PASSWORD` - Docker Hub password/token

**To add secrets:** GitHub Repo → Settings → Secrets and variables → Actions → New repository secret

---

## 📖 More Info
- [EKS User Guide: Managing aws-auth](https://docs.aws.amazon.com/eks/latest/userguide/add-user-role.html)
- [EKS Access Entries (newer method)](https://docs.aws.amazon.com/eks/latest/userguide/access-entries.html)
