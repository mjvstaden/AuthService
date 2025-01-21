#!/bin/bash

# Exit on any error
set -e

echo "🔄 Starting Kubernetes deployment process..."

# Function to check if kubectl is available
check_kubectl() {
    if ! command -v kubectl &> /dev/null; then
        echo "❌ kubectl is not installed or not in PATH"
        exit 1
    fi
}

# Function to check if Docker Desktop Kubernetes is running
check_kubernetes() {
    if ! kubectl cluster-info &> /dev/null; then
        echo "❌ Kubernetes is not running. Please start Docker Desktop and enable Kubernetes"
        exit 1
    fi
}

# Function to show pod status
show_pod_status() {
    local deployment=$1
    local app_label
    
    # Convert deployment name to app label
    case $deployment in
        "mssql-deployment")
            app_label="mssql"
            ;;
        "auth-api-deployment")
            app_label="auth-api"
            ;;
        *)
            app_label=$deployment
            ;;
    esac
    
    echo "📊 Pod status for $deployment:"
    kubectl get pods -l app=$app_label -o wide
    
    echo "📝 Pod logs for $deployment:"
    POD=$(kubectl get pods -l app=$app_label -o jsonpath="{.items[0].metadata.name}" 2>/dev/null)
    if [ ! -z "$POD" ]; then
        kubectl logs $POD --tail=50
    else
        echo "No pods found for $deployment"
    fi
}

# Function to wait for a deployment to be ready
wait_for_deployment() {
    local deployment=$1
    local timeout=300
    local interval=10
    local elapsed=0
    
    echo "⏳ Waiting for deployment $deployment to be ready..."
    
    while [ $elapsed -lt $timeout ]; do
        if kubectl rollout status deployment/$deployment --timeout=10s >/dev/null 2>&1; then
            echo "✅ Deployment $deployment is ready"
            return 0
        fi
        
        echo "⏳ Still waiting for $deployment... (${elapsed}s elapsed)"
        show_pod_status $deployment
        
        sleep $interval
        elapsed=$((elapsed + interval))
    done
    
    echo "❌ Timeout waiting for deployment $deployment"
    return 1
}

# Clean up existing resources but preserve PVC
cleanup() {
    echo "🧹 Cleaning up deployments and services..."
    kubectl delete deployment mssql-deployment auth-api-deployment --ignore-not-found
    kubectl delete service mssql-service auth-api-service --ignore-not-found
    echo "✅ Cleanup completed (PVC preserved)"
}

# Complete cleanup including PVC and secrets (optional)
cleanup_all() {
    echo "🧹 Cleaning up ALL resources including PVC and secrets..."
    cleanup
    kubectl delete pvc mssql-data --ignore-not-found
    kubectl delete secret mssql-secret --ignore-not-found
    echo "✅ Complete cleanup completed"
}

# Apply new configurations
apply_configs() {
    echo "📦 Applying Kubernetes configurations..."
    kubectl apply -f k8s/
    echo "✅ Configurations applied"
}

# Function to set up port forwarding
setup_port_forwarding() {
    echo "🔌 Setting up port forwarding..."
    
    # Kill any existing kubectl port-forward processes
    pkill -f "kubectl port-forward" || true
    
    # Port forward for SQL Server (background)
    kubectl port-forward service/mssql-service 1433:1433 &
    echo "✅ SQL Server port forwarding set up on localhost:1433"
    
    # Port forward for API (background)
    kubectl port-forward service/auth-api-service 8080:8080 &
    echo "✅ API port forwarding set up on localhost:8080"
    
    # Give port forwarding a moment to establish
    sleep 2
}

rebuild_docker_images() {
    echo "🔨 Building Docker images..."

    docker build -t auth-service-api:latest .
    docker build -t auth-service-sql:latest .

    kubectl apply -f k8s/sql.yaml && kubectl apply -f k8s/api.yaml
}

# Main deployment process
main() {
    # Check for command line arguments
    if [ "$1" = "--clean-all" ]; then
        echo "🔄 Performing complete cleanup including PVC..."
        cleanup_all
        exit 0
    fi

    echo "🔍 Checking prerequisites..."
    check_kubectl
    check_kubernetes

    echo "🔨 Rebuilding Docker images..."
    rebuild_docker_images

    echo "🚀 Starting deployment process..."
    cleanup
    apply_configs

    echo "⏳ Waiting for SQL Server to be ready..."
    wait_for_deployment mssql-deployment

    echo "⏳ Waiting for API to be ready..."
    wait_for_deployment auth-api-deployment

    echo "📊 Current pod status:"
    kubectl get pods

    echo "🌐 Service endpoints:"
    kubectl get services

    # Set up port forwarding after services are ready
    setup_port_forwarding

    echo "✅ Deployment completed successfully!"
    echo "🔗 API is accessible at http://localhost:8080"
    echo "🔗 SQL Server is accessible at localhost:1433"
    echo "ℹ️  Port forwarding is running in the background"
    echo "ℹ️  To stop port forwarding, run: pkill -f 'kubectl port-forward'"
}

# Run the main function with all command line arguments
main "$@" 