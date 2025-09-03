#!/bin/sh

set -e 

echo "Install tchap @vector-im/compound-design-tokens ..."

cd "$MAS_HOME/frontend"
npm install 

# uncomment if needed : 
# echo "Building frontend and static resources with yarn build-tchap ..."
npm run build-tchap 


echo "Building templates..."

# New template directory
MAS_TCHAP_DATA="$MAS_TCHAP_HOME/tmp"
# Create data directory
if [ ! -d "$MAS_TCHAP_DATA" ]; then
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
