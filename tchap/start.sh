#!/bin/bash

# start the MAS

set -e

echo "Starting MAS initialization process..."

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export MAS_HOME="$(dirname "$SCRIPT_DIR")"
export MAS_TCHAP_HOME=$SCRIPT_DIR
export RUST_LOG=info

# start the postgres service if not running already
echo "Step 1/7: Checking PostgreSQL service status..."

# Check if postgres container is running
if ! docker compose ps postgres | grep -q "Up"; then
    echo "PostgreSQL is not running. Starting docker-compose services..."
    docker compose up -d postgres
    
    # Wait for PostgreSQL to be ready
    echo "Waiting for PostgreSQL to be ready..."
    docker compose exec postgres pg_isready -U postgres
    while [ $? -ne 0 ]; do
        sleep 10
        docker compose exec postgres pg_isready -U postgres
    done
    echo "PostgreSQL is ready!"
else
    echo "PostgreSQL is already running."
fi

echo "Step 2/7: Checking policy.wasm..."
#if policy.wasm does not exists create it 
if [ -f $MAS_HOME/policies/policy.wasm ]; then
    echo "policy.wasm found" 
else
    cd $MAS_HOME/policies
    echo "Creating policy.wasm..."
    make DOCKER=1
fi

cd "$MAS_HOME/frontend"
echo "Step 3/7: Installing npm dependencies..."
npm install 
echo "Step 4/7: Building frontend and static resources..."
npm run build-tchap 

echo "Step 5/7: Building configuration..."
$MAS_TCHAP_HOME/build_conf.sh

cd "$MAS_HOME"

echo "Step 6/7: Checking templates..."
cargo run -- templates check -c $MAS_TCHAP_HOME/tmp/config.local.dev.yaml 

echo "Step 7/7: Starting server..."
cargo run -- server -c $MAS_TCHAP_HOME/tmp/config.local.dev.yaml

echo "MAS initialization completed successfully!"
