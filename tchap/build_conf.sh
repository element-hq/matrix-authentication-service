#!/bin/sh

set -e 



# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Set MAS_HOME to the parent directory (project root)
export MAS_HOME="$(dirname "$SCRIPT_DIR")"
export MAS_TCHAP_HOME=$SCRIPT_DIR

# Source the .env file to load environment variables
if [ -f $MAS_TCHAP_HOME/.env ]; then
  source $MAS_TCHAP_HOME/.env
else
  echo "Error: .env file not found. Please create a $MAS_TCHAP_HOME/.env file with the required environment variables."
  exit 1
fi

echo "Building templates..."

# New template directory
MAS_TCHAP_DATA="$MAS_TCHAP_HOME/tmp"

# Create data directory
if [ ! -d "$MAS_TCHAP_DATA" ]; then
  echo "Create MAS tchap temp folder..."
  mkdir -p "$MAS_TCHAP_DATA"
fi

# Copy all MAS templates to a new template directory
cp -r "$MAS_HOME/templates" "$MAS_TCHAP_DATA"

# Override MAS template with custom tchap template
cp -r "$MAS_HOME/tchap/resources/templates" "$MAS_TCHAP_DATA"

echo "Building MAS config..."

# Create MAS conf file
template_yaml_file="$MAS_TCHAP_HOME/conf/config.template.yaml"
yaml_file="$MAS_TCHAP_DATA/config.local.dev.yaml"
cp $template_yaml_file $yaml_file

MAS_TCHAP_TEMPLATES="$MAS_TCHAP_DATA/templates"
sed -i '' -E "/^templates:/,/^[^[:space:]]/ s|^[[:space:]]*path:.*|  path: \"$MAS_TCHAP_TEMPLATES\"|" "$yaml_file"

echo "Updating translations..."
MAS_TCHAP_TRANSLATIONS="$MAS_HOME/tchap/resources/translations"

cargo run -p mas-i18n-scan  -- --update "${MAS_TCHAP_TEMPLATES}" "${MAS_TCHAP_TRANSLATIONS}/en.json"

sed -i '' -E "/^templates:/,/^[^[:space:]]/ s|^[[:space:]]*translations_path:.*|  translations_path: \"$MAS_TCHAP_TRANSLATIONS\"|" "$yaml_file"

# Replace the placeholder secret value with the environment variable or warning message
echo "Updating matrix secret..."
if [ -n "${HOMESERVER_SECRET+x}" ] && [ -n "$HOMESERVER_SECRET" ]; then
  # HOMESERVER_SECRET is defined and not empty
  sed -i '' -E "s|secret: 'TO BE COPY'|secret: '$HOMESERVER_SECRET'|" "$yaml_file"
else
  # HOMESERVER_SECRET is not defined or empty
  sed -i '' -E "s|secret: 'TO BE COPY'|secret: 'WARNING NO HOMESERVER SECRET DEFINED'|" "$yaml_file"
  echo "WARNING: HOMESERVER_SECRET is not defined or empty. Using warning message instead."
fi
