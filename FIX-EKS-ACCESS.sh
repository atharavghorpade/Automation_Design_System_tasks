#!/bin/bash
# Run this script from your LOCAL machine where you have EKS admin access
# This will grant your GitHub Actions IAM user access to the cluster

echo "=== EKS Access Configuration Script ==="
echo ""

# Step 1: Get your GitHub Actions IAM User ARN
echo "Step 1: Finding your IAM user ARN..."
IAM_ARN=$(aws sts get-caller-identity --query Arn --output text)
echo "Current IAM identity: $IAM_ARN"
echo ""

# Step 2: Check if EKS cluster exists
echo "Step 2: Checking EKS cluster..."
aws eks describe-cluster --name dev-cluster --region ap-south-1 > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "ERROR: Cannot access EKS cluster 'dev-cluster' in ap-south-1"
    echo "Please verify the cluster name and region"
    exit 1
fi
echo "✓ Cluster 'dev-cluster' found"
echo ""

# Step 3: Update kubeconfig
echo "Step 3: Updating kubeconfig..."
aws eks update-kubeconfig --name dev-cluster --region ap-south-1
echo ""

# Step 4: Get the IAM user ARN that needs access (from GitHub Secrets)
echo "Step 4: Enter the IAM User ARN from your GitHub Secrets:"
echo "This is the ARN of the user whose AWS_ACCESS_KEY_ID you added to GitHub"
read -p "IAM User ARN: " GITHUB_IAM_ARN

if [ -z "$GITHUB_IAM_ARN" ]; then
    echo "ERROR: IAM ARN cannot be empty"
    exit 1
fi

# Step 5: Add user to aws-auth ConfigMap
echo ""
echo "Step 5: Adding IAM user to aws-auth ConfigMap..."

# Backup current aws-auth
kubectl get configmap aws-auth -n kube-system -o yaml > aws-auth-backup.yaml
echo "✓ Backup created: aws-auth-backup.yaml"

# Check if aws-auth exists
kubectl get configmap aws-auth -n kube-system > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "Creating new aws-auth ConfigMap..."
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: aws-auth
  namespace: kube-system
data:
  mapUsers: |
    - userarn: $GITHUB_IAM_ARN
      username: github-actions
      groups:
        - system:masters
EOF
else
    # Patch existing ConfigMap
    echo "Updating existing aws-auth ConfigMap..."
    
    # Get current mapUsers
    CURRENT_MAP_USERS=$(kubectl get configmap aws-auth -n kube-system -o jsonpath='{.data.mapUsers}')
    
    # Create updated mapUsers
    cat <<EOF > /tmp/new-mapusers.yaml
- userarn: $GITHUB_IAM_ARN
  username: github-actions
  groups:
    - system:masters
EOF
    
    # Add to existing mapUsers
    kubectl patch configmap aws-auth -n kube-system --type merge -p "{\"data\":{\"mapUsers\":\"$CURRENT_MAP_USERS\n$(cat /tmp/new-mapusers.yaml)\"}}"
fi

echo ""
echo "=== Configuration Complete! ==="
echo ""
echo "✓ IAM user $GITHUB_IAM_ARN now has access to the cluster"
echo ""
echo "Test the configuration:"
echo "  aws sts get-caller-identity"
echo "  kubectl get nodes"
echo ""
echo "Your GitHub Actions workflow should now work!"
