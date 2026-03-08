# One-time setup script to grant GitHub Actions IAM user access to EKS cluster
# Run this from your LOCAL machine where you already have EKS admin access

Write-Host "=== EKS Access Setup for GitHub Actions ===" -ForegroundColor Cyan
Write-Host ""

# Configuration
$CLUSTER_NAME = "dev-cluster"
$REGION = "ap-south-1"

# Step 1: Verify you have kubectl access
Write-Host "Step 1: Verifying your EKS access..." -ForegroundColor Yellow
try {
    aws eks update-kubeconfig --name $CLUSTER_NAME --region $REGION 2>&1 | Out-Null
    $nodes = kubectl get nodes 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Cannot access cluster"
    }
    Write-Host "✓ You have access to EKS cluster" -ForegroundColor Green
    Write-Host ""
} catch {
    Write-Host "❌ ERROR: You don't have access to the EKS cluster" -ForegroundColor Red
    Write-Host "Please ensure you have admin access to the cluster first" -ForegroundColor Red
    exit 1
}

# Step 2: Get IAM user ARN from GitHub secrets
Write-Host "Step 2: Enter the IAM User ARN for GitHub Actions" -ForegroundColor Yellow
Write-Host "This is the ARN of the IAM user whose credentials are in GitHub Secrets" -ForegroundColor Gray
Write-Host ""
Write-Host "To find it, you can check your GitHub Secrets or run:" -ForegroundColor Gray
Write-Host "  aws sts get-caller-identity (using that user's credentials)" -ForegroundColor Gray
Write-Host ""
$IAM_ARN = Read-Host "IAM User ARN (e.g., arn:aws:iam::123456789:user/github-actions)"

if ([string]::IsNullOrWhiteSpace($IAM_ARN)) {
    Write-Host "❌ ERROR: IAM ARN cannot be empty" -ForegroundColor Red
    exit 1
}

# Step 3: Grant access using EKS Access Entry (modern method)
Write-Host ""
Write-Host "Step 3: Granting EKS access using Access Entry..." -ForegroundColor Yellow
try {
    # Create access entry
    aws eks create-access-entry `
        --cluster-name $CLUSTER_NAME `
        --principal-arn $IAM_ARN `
        --type STANDARD `
        --region $REGION 2>&1 | Out-Null
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ Access entry created" -ForegroundColor Green
    } else {
        Write-Host "⚠ Access entry may already exist, continuing..." -ForegroundColor Yellow
    }
    
    # Associate admin policy
    aws eks associate-access-policy `
        --cluster-name $CLUSTER_NAME `
        --principal-arn $IAM_ARN `
        --policy-arn arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy `
        --access-scope type=cluster `
        --region $REGION 2>&1 | Out-Null
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ Admin policy associated" -ForegroundColor Green
    } else {
        Write-Host "⚠ Policy may already be associated, continuing..." -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Green
    Write-Host "✓ SUCCESS! GitHub Actions IAM user now has EKS access" -ForegroundColor Green
    Write-Host "================================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "You can now run your GitHub Actions workflow!" -ForegroundColor Green
    
} catch {
    Write-Host ""
    Write-Host "❌ Failed to use Access Entry method" -ForegroundColor Red
    Write-Host "Trying alternative method using aws-auth ConfigMap..." -ForegroundColor Yellow
    Write-Host ""
    
    # Fallback: Use aws-auth ConfigMap
    Write-Host "Step 3 (Alternative): Adding to aws-auth ConfigMap..." -ForegroundColor Yellow
    
    # Get current aws-auth
    kubectl get configmap aws-auth -n kube-system -o yaml > aws-auth-backup.yaml
    Write-Host "✓ Backed up current aws-auth to aws-auth-backup.yaml" -ForegroundColor Green
    
    # Create new aws-auth with the IAM user
    $awsAuthYaml = @"
apiVersion: v1
kind: ConfigMap
metadata:
  name: aws-auth
  namespace: kube-system
data:
  mapUsers: |
    - userarn: $IAM_ARN
      username: github-actions
      groups:
        - system:masters
"@
    
    $awsAuthYaml | kubectl apply -f - 2>&1 | Out-Null
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ IAM user added to aws-auth ConfigMap" -ForegroundColor Green
        Write-Host ""
        Write-Host "================================================================" -ForegroundColor Green
        Write-Host "✓ SUCCESS! GitHub Actions IAM user now has EKS access" -ForegroundColor Green
        Write-Host "================================================================" -ForegroundColor Green
    } else {
        Write-Host "❌ Failed to update aws-auth ConfigMap" -ForegroundColor Red
        Write-Host "Please manually edit it with: kubectl edit configmap aws-auth -n kube-system" -ForegroundColor Yellow
        exit 1
    }
}

Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "1. Commit and push your code to trigger the GitHub Actions workflow" -ForegroundColor White
Write-Host "2. Monitor the workflow at: https://github.com/YOUR_REPO/actions" -ForegroundColor White
Write-Host ""
