#!/bin/bash

# runs the MAS with a hot reload when a template is modified


set -e

# Source the .env file to load environment variables
if [ -f .env ]; then
  source .env
else
  echo "Error: .env file not found. Please create a .env file with the required environment variables."
  exit 1
fi

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Set MAS_HOME to the parent directory (project root)
export MAS_HOME="$(dirname "$SCRIPT_DIR")"

export TEMPLATE_WATCH="$MAS_HOME/tchap/resources/templates"

echo "Template watching on : " + $TEMPLATE_WATCH

# Function to send SIGHUP to the server process
send_sighup() {
    # Find the server process
    SERVER_PID=$(pgrep -f "mas-cli server -c")
    if [ -n "$SERVER_PID" ]; then
        echo "Sending SIGHUP to server process $SERVER_PID"
        kill -HUP $SERVER_PID
    else
        echo "Server process not found"
    fi
}

# Function to watch for template changes
watch_templates() {
    echo "Watching for changes in $TEMPLATE_WATCH..."
    
    # Use fswatch to monitor the templates directory
    fswatch -o "$TEMPLATE_WATCH" | while read; do
        echo "Template change detected..."
        $MAS_TCHAP_HOME/build_conf.sh
        send_sighup
    done
}

# Check if fswatch is installed
if ! command -v fswatch &> /dev/null; then
    echo "fswatch is not installed. Please install it first:"
    echo "brew install fswatch"
    exit 1
fi

export MAS_TCHAP_HOME=$SCRIPT_DIR

# Build conf from conf.template.yaml
# $MAS_TCHAP_HOME/tools/build_conf.sh

# Start watching for changes in the background
watch_templates &

# Store the watcher's PID
WATCHER_PID=$!

# Function to clean up on exit
cleanup() {
    echo "Stopping template watcher..."
    kill $WATCHER_PID 2>/dev/null
    exit 0
}

# Set up trap for cleanup
trap cleanup EXIT INT TERM

./start-local-mas.sh
