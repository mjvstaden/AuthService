#!/bin/bash

# Exit on any error
set -e

echo "🔄 Starting database migration process..."

# Store the script's directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
# Store the root directory (one level up from scripts)
ROOT_DIR="$( cd "$SCRIPT_DIR/.." && pwd )"

# Function to check if dotnet ef tools are installed
check_ef_tools() {
    if ! dotnet ef --version &> /dev/null; then
        echo "❌ dotnet ef tools are not installed"
        echo "💡 Install them with: dotnet tool install --global dotnet-ef"
        exit 1
    fi
}

# Function to check if SQL Server is accessible
check_sql_connection() {
    echo "🔍 Checking SQL Server connection..."
    # Try to connect to SQL Server using the port-forward
    if ! nc -z localhost 1433 &> /dev/null; then
        echo "❌ Cannot connect to SQL Server on localhost:1433"
        echo "💡 Make sure the Kubernetes deployment is running and port forwarding is active"
        echo "💡 Run ./scripts/start-k8s.sh first"
        exit 1
    fi
    echo "✅ SQL Server is accessible"
}

# Function to apply migrations
apply_migrations() {
    echo "📦 Applying database migrations..."
    
    # Navigate to the Infrastructure project directory
    cd "$ROOT_DIR/src/AuthService.Infrastructure"
    
    # Apply migrations
    dotnet ef database update \
        --startup-project ../AuthService.API \
        --verbose
    
    echo "✅ Database migrations applied successfully"
}

# Main process
main() {
    echo "🔍 Checking prerequisites..."
    check_ef_tools
    check_sql_connection
    
    apply_migrations
    
    echo "✅ Migration process completed successfully!"
}

# Run the main function
main 