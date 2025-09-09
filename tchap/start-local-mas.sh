#!/bin/bash
# runs the MAS at the path : $MAS_HOME
# before running the server :
# - build the config
# - build the template
# - runs sanity check on the templates

set -e

# Source the .env file to load environment variables
# if [ -f .env ]; then
#   source .env
# else
#   echo "Error: .env file not found. Please create a .env file with the required environment variables."
#   exit 1
# fi

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export MAS_HOME="$(dirname "$SCRIPT_DIR")"
export MAS_TCHAP_HOME=$SCRIPT_DIR
export RUST_LOG=info

# start the postgres service if not running already
echo "Checking PostgreSQL service status..."

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

#if policy.wasm does not exists create it 
if [ -f $MAS_HOME/policies/policy.wasm ]; then
    echo "policy.wasm found" 
else
    cd $MAS_HOME/policies
    echo "Create policy.wasm"
    make DOCKER=1
fi

cd $MAS_HOME

# Build conf from conf.template.yaml
$MAS_TCHAP_HOME/build_conf.sh


echo "Start server..."
cargo run -- server -c $MAS_TCHAP_HOME/tmp/config.local.dev.yaml 
#cargo run -- server -c /Users/olivier/workspace/beta/Tchap/element-docker-demo/data/mas/config.yaml
