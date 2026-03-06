# PowerShell script to configure EKS access for GitHub Actions
# Run this from your LOCAL machine where you have EKS admin access

Write-Host "=== EKS Access Configuration Script ===" -ForegroundColor Cyan
Write-Host ""

# Step 1: Get current IAM identity
Write-Host "Step 1: Finding your current IAM identity..." -ForegroundColor Yellow
$currentIdentity = aws sts get-caller-identity | ConvertFrom-Json
Write-Host "Current IAM identity: $($currentIdentity.Arn)" -ForegroundColor Green
Write-Host ""

# Step 2: Check if EKS cluster exists
Write-Host "Step 2: Checking EKS cluster..." -ForegroundColor Yellow
try {
    aws eks describe-cluster --name dev-cluster --region ap-south-1 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Cannot access cluster"
    }
    Write-Host "✓ Cluster 'dev-cluster' found" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Cannot access EKS cluster 'dev-cluster' in ap-south-1" -ForegroundColor Red
    Write-Host "Please verify the cluster name and region" -ForegroundColor Red
    exit 1
}
Write-Host ""

# Step 3: Update kubeconfig
Write-Host "Step 3: Updating kubeconfig..." -ForegroundColor Yellow
aws eks update-kubeconfig --name dev-cluster --region ap-south-1
Write-Host ""

# Step 4: Get the IAM user ARN from GitHub Secrets
Write-Host "Step 4: Enter the IAM User ARN from your GitHub Secrets:" -ForegroundColor Yellow
Write-Host "This is the ARN of the user whose AWS_ACCESS_KEY_ID you added to GitHub" -ForegroundColor Gray
$githubIamArn = Read-Host "IAM User ARN"

if ([string]::IsNullOrWhiteSpace($githubIamArn)) {
    Write-Host "ERROR: IAM ARN cannot be empty" -ForegroundColor Red
    exit 1
}

# Step 5: Backup current aws-auth
Write-Host ""
Write-Host "Step 5: Backing up current aws-auth ConfigMap..." -ForegroundColor Yellow
kubectl get configmap aws-auth -n kube-system -o yaml > aws-auth-backup.yaml 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Backup created: aws-auth-backup.yaml" -ForegroundColor Green
}

# Step 6: Update aws-auth ConfigMap
Write-Host ""
Write-Host "Step 6: Adding IAM user to aws-auth ConfigMap..." -ForegroundColor Yellow

# Create the mapUsers entry
$mapUsersEntry = @"
  - userarn: $githubIamArn
    username: github-actions
    groups:
      - system:masters
"@

Write-Host ""
Write-Host "Add this to your aws-auth ConfigMap:" -ForegroundColor Cyan
Write-Host "-----------------------------------" -ForegroundColor Gray
Write-Host $mapUsersEntry -ForegroundColor White
Write-Host "-----------------------------------" -ForegroundColor Gray
Write-Host ""
Write-Host "Opening aws-auth ConfigMap for editing..." -ForegroundColor Yellow
Write-Host "Add the above entry under 'mapUsers:' section" -ForegroundColor Yellow
Write-Host ""

Start-Sleep -Seconds 2
kubectl edit configmap aws-auth -n kube-system

Write-Host ""
Write-Host "=== Configuration Complete! ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "✓ IAM user should now have access to the cluster" -ForegroundColor Green
Write-Host ""
Write-Host "Test the configuration:" -ForegroundColor Yellow
Write-Host "  aws sts get-caller-identity" -ForegroundColor Gray
Write-Host "  kubectl get nodes" -ForegroundColor Gray
Write-Host ""
Write-Host "Your GitHub Actions workflow should now work!" -ForegroundColor Green
