#!/bin/bash

echo "Starting cleanup process..."

echo "Step 1/6: Stopping Docker containers..."
docker compose down

echo "Step 2/6: Removing policy WASM file..."
rm -rf ../policies/policy.wasm

#echo "Step 3/6: Removing Rust build artifacts..."
#rm -rf ../target/

echo "Step 4/6: Removing temporary files..."
rm -rf tmp/

echo "Step 5/6: Removing frontend dependencies..."
rm -rf ../frontend/node_modules/

echo "Step 6/6: Removing frontend build files..."
rm -rf ../frontend/dist/

echo "Cleanup completed successfully!"
