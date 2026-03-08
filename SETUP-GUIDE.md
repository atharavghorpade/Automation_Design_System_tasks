# GitHub Actions CI/CD Setup - Quick Start

## What Changed

Your workflow has been restructured into **3 separate jobs**:

### 1. **Build Job**
- Builds the Maven project
- Runs compliance system
- Uploads artifacts

### 2. **Push Job** (depends on Build)
- Builds Docker image
- Pushes to Docker Hub

### 3. **Deploy Job** (depends on Push)
- Configures AWS/EKS access
- Deploys to Kubernetes cluster

## ⚠️ Important: One-Time Setup Required

Before your workflow can deploy to EKS, you need to grant the GitHub Actions IAM user access to your cluster.

### Quick Setup (5 minutes)

**Run this command from your local machine** (where you already have EKS admin access):

```powershell
.\setup-eks-access.ps1
```

This script will:
1. ✅ Verify you have EKS access
2. ✅ Prompt for the GitHub Actions IAM user ARN
3. ✅ Grant that IAM user access to your EKS cluster
4. ✅ Configure everything automatically

### Finding Your IAM User ARN

The IAM user ARN is for the user whose credentials are stored in your GitHub Secrets:
- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`

To find it:
```bash
aws sts get-caller-identity --profile YOUR_PROFILE
```

It will look like: `arn:aws:iam::123456789012:user/github-actions`

## How the Workflow Fixes the Error

The updated workflow now:

1. **Automatically attempts to grant EKS access** using AWS EKS Access Entry API
2. **Tests kubectl access** before deploying
3. **Provides helpful error messages** with exact commands to fix any issues
4. **Separates build, push, and deploy** into independent jobs for better pipeline management

## Error You Were Seeing

The error you saw:
```
couldn't get current server API group list: the server has asked for the client to provide credentials
```

This happens when the IAM user doesn't have access to the EKS cluster. The setup script and workflow updates fix this issue.

## Workflow Structure

```
Build Job
   ↓
   └→ Uploads: compliance-artifacts, build-artifacts
   
Push Job (needs: build)
   ↓
   ├→ Downloads: build-artifacts
   └→ Pushes: Docker image
   
Deploy Job (needs: push)
   ↓
   ├→ Grants EKS access (automatic)
   ├→ Tests kubectl access
   └→ Deploys to Kubernetes
```

## Testing Your Setup

After running the setup script:

1. **Commit and push your code:**
   ```bash
   git add .
   git commit -m "Update CI/CD pipeline structure"
   git push origin main
   ```

2. **Monitor the workflow:**
   - Go to your GitHub repository
   - Click on "Actions" tab
   - Watch the build → push → deploy pipeline

## Troubleshooting

If the deploy job still fails:

1. **Check the error message** - The workflow now provides detailed instructions
2. **Verify IAM permissions** - Ensure the IAM user has `eks:DescribeCluster` permission
3. **Run setup script again** - `.\setup-eks-access.ps1`
4. **Manual fix** - See instructions in `EKS-FIX-GUIDE.md`

## Files Modified

- ✏️ `.github/workflows/ci-cd.yaml` - Restructured into 3 jobs with EKS access fixes
- ➕ `setup-eks-access.ps1` - One-time setup script for EKS access
- ➕ `SETUP-GUIDE.md` - This file

## Next Steps

1. ✅ Run `.\setup-eks-access.ps1` (one-time)
2. ✅ Push your code to trigger the workflow
3. ✅ Monitor the Actions tab on GitHub
4. ✅ Verify deployment with `kubectl get pods`

---

**Need more help?** See `EKS-FIX-GUIDE.md` for detailed troubleshooting steps.
