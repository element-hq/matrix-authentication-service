#!/bin/bash

echo "Starting cleanup process..."

echo "Step 1/6: Stopping Docker containers..."
docker compose down

echo "Step 2/6: Removing data in postgres..."
rm -rf tmp/postgres

echo "Cleanup data completed successfully!"
