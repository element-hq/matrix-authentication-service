// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Generates `docs/reference/configuration.md` from the config JSON schema.
//!
//! The renderer walks the JSON schema (as a [`serde_json::Value`], not the
//! typed schemars API) and emits one annotated YAML example block per config
//! section, in the style of the hand-written reference document.

use schemars::generate::SchemaSettings;
use serde_json::{Map, Value};

/// Order in which sections are rendered. Sections present in the schema but
/// missing from this list are appended at the end and produce a warning.
const SECTION_ORDER: &[&str] = &[
    "http",
    "database",
    "matrix",
    "templates",
    "clients",
    "secrets",
    "passwords",
    "account",
    "captcha",
    "policy",
    "rate_limiting",
    "telemetry",
    "email",
    "upstream_oauth2",
    "branding",
    "oauth",
    "experimental",
];

/// Fields that are pulled out of their parent's YAML block and rendered as
/// their own `### ` subsection. Each entry is `section.field`.
const HOISTED: &[&str] = &["http.listeners", "upstream_oauth2.providers"];

fn main() {
    let generator = SchemaSettings::draft07().into_generator();
    let schema = generator.into_root_schema_for::<mas_config::RootConfig>();
    let schema: Value =
        serde_json::to_value(&schema).expect("Failed to convert schema to serde_json::Value");

    let mut renderer = Renderer::new(&schema);
    let output = renderer.render();

    print!("{output}");

    for warning in &renderer.warnings {
        eprintln!("{warning}");
    }
}

struct Renderer {
    /// Top-level properties of the schema (the sections).
    properties: Map<String, Value>,
    /// The `definitions` map, used to resolve `$ref`s.
    definitions: Map<String, Value>,
    /// Warnings collected while rendering, printed to stderr at the end.
    warnings: Vec<String>,
}

/// A key/value union variant that carries a `const` tag, i.e. a string enum.
struct EnumInfo {
    /// The list of `(value, description)` pairs.
    values: Vec<(String, Option<String>)>,
    /// Whether at least one variant carries a description.
    has_descriptions: bool,
}

impl Renderer {
    fn new(schema: &Value) -> Self {
        let properties = schema
            .get("properties")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let definitions = schema
            .get("definitions")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        Self {
            properties,
            definitions,
            warnings: Vec::new(),
        }
    }

    fn warn(&mut self, message: String) {
        self.warnings.push(message);
    }

    // --- Schema resolution -------------------------------------------------

    /// Follow `$ref`s and unwrap single-element `allOf`s until a fixed point
    /// is reached. Keys on the referring site override the target's.
    fn resolve(&self, node: &Value) -> Value {
        let mut node = node.clone();
        loop {
            let Some(obj) = node.as_object() else {
                return node;
            };

            // Unwrap single-element `allOf`, merging sibling keys (ref-site wins).
            if let Some(all_of) = obj.get("allOf").and_then(Value::as_array)
                && all_of.len() == 1
            {
                let mut merged = all_of[0].as_object().cloned().unwrap_or_default();
                for (key, value) in obj {
                    if key != "allOf" {
                        merged.insert(key.clone(), value.clone());
                    }
                }
                node = Value::Object(merged);
                continue;
            }

            // Resolve `$ref` into `definitions`, letting ref-site keys win.
            if let Some(reference) = obj.get("$ref").and_then(Value::as_str) {
                let name = reference.rsplit('/').next().unwrap_or(reference);
                let mut merged = self
                    .definitions
                    .get(name)
                    .and_then(Value::as_object)
                    .cloned()
                    .unwrap_or_default();
                for (key, value) in obj {
                    if key != "$ref" {
                        merged.insert(key.clone(), value.clone());
                    }
                }
                node = Value::Object(merged);
                continue;
            }

            return node;
        }
    }

    /// The description of the *definition* a node refers to, ignoring any
    /// description on the referring site. `None` when the node is not a
    /// reference or the target has no description.
    fn definition_description(&self, node: &Value) -> Option<String> {
        let mut node = node;
        // Look through single-element `allOf` wrappers.
        while let Some(all_of) = node.get("allOf").and_then(Value::as_array)
            && let [inner] = all_of.as_slice()
        {
            node = inner;
        }
        let reference = node.get("$ref")?.as_str()?;
        let name = reference.rsplit('/').next().unwrap_or(reference);
        let description = self.definitions.get(name)?.get("description")?.as_str()?;
        Some(clean_description(description)).filter(|d| !d.is_empty())
    }

    /// Resolve a node and, if it represents an `Option<T>`, unwrap it to `T`.
    ///
    /// Handles both `type: ["X", "null"]` and `anyOf: [T, {type: "null"}]`.
    fn strip_null(&self, node: &Value) -> Value {
        let node = self.resolve(node);
        let Some(obj) = node.as_object() else {
            return node;
        };

        // `type: ["X", "null"]` → `type: "X"`
        if let Some(types) = obj.get("type").and_then(Value::as_array)
            && types.iter().any(|t| t == "null")
        {
            let rest: Vec<Value> = types.iter().filter(|t| *t != "null").cloned().collect();
            let mut merged = obj.clone();
            match rest.as_slice() {
                [single] => merged.insert("type".to_owned(), single.clone()),
                _ => merged.insert("type".to_owned(), Value::Array(rest)),
            };
            return Value::Object(merged);
        }

        // `anyOf: [T, {type: "null"}]` → `T` (with ref-site keys merged in)
        let null = serde_json::json!({ "type": "null" });
        if let Some(variants) = obj.get("anyOf").and_then(Value::as_array)
            && variants.len() == 2
            && variants[1] == null
        {
            let inner = self.resolve(&variants[0]);
            let mut merged = inner.as_object().cloned().unwrap_or_default();
            for (key, value) in obj {
                if key != "anyOf" {
                    merged.insert(key.clone(), value.clone());
                }
            }
            return Value::Object(merged);
        }

        node
    }

    // --- `x-doc` extension --------------------------------------------------

    fn x_doc(node: &Value) -> Option<&Map<String, Value>> {
        node.get("x-doc").and_then(Value::as_object)
    }

    fn x_doc_commented(node: &Value) -> bool {
        Self::x_doc(node)
            .and_then(|d| d.get("commented"))
            .and_then(Value::as_bool)
            .unwrap_or(false)
    }

    fn x_doc_yaml(node: &Value) -> Option<String> {
        Self::x_doc(node)
            .and_then(|d| d.get("yaml"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    }

    fn x_doc_skip(node: &Value) -> bool {
        Self::x_doc(node)
            .and_then(|d| d.get("skip"))
            .and_then(Value::as_bool)
            .unwrap_or(false)
    }

    // --- Rendering ---------------------------------------------------------

    fn render(&mut self) -> String {
        let mut lines: Vec<String> = vec![
            "# Configuration file reference".to_owned(),
            String::new(),
            "<!-- This file is generated by `cargo run -p mas-config --bin docs`. Do not edit manually. -->"
                .to_owned(),
            String::new(),
        ];

        // Figure out the section order: known sections first, then any extra.
        let mut order: Vec<String> = SECTION_ORDER
            .iter()
            .filter(|name| self.properties.contains_key(**name))
            .map(|name| (*name).to_owned())
            .collect();
        let mut extra: Vec<String> = self
            .properties
            .keys()
            .filter(|name| !SECTION_ORDER.contains(&name.as_str()))
            .cloned()
            .collect();
        extra.sort();
        for name in &extra {
            self.warn(format!(
                "section not in SECTION_ORDER, appended at the end: {name}"
            ));
        }
        order.extend(extra);

        for name in order {
            self.render_section(&mut lines, &name);
        }

        finalize(&lines)
    }

    fn render_section(&mut self, lines: &mut Vec<String>, name: &str) {
        let raw_node = self.properties.get(name).cloned().unwrap_or(Value::Null);
        let node = self.strip_null(&raw_node);

        lines.push(format!("## `{name}`"));
        lines.push(String::new());

        // Section description, split around an optional `<!-- more -->` marker.
        //
        // Prefer the section *struct*'s own doc comment over the `RootConfig`
        // field's: the resolver lets ref-site keys win (which is right for
        // fields), but section structs carry the full reference prose while
        // the `RootConfig` field docs are one-line summaries.
        let description = self
            .definition_description(&raw_node)
            .or_else(|| {
                node.get("description")
                    .and_then(Value::as_str)
                    .map(clean_description)
            })
            .unwrap_or_default();
        let (before, after) = split_more(&description);
        if !before.is_empty() {
            lines.push(before);
            lines.push(String::new());
        }

        // Which of this section's fields are hoisted into their own subsection.
        let hoisted: Vec<String> = HOISTED
            .iter()
            .filter_map(|h| h.strip_prefix(&format!("{name}.")))
            .map(ToOwned::to_owned)
            .collect();
        let hoisted_refs: Vec<&str> = hoisted.iter().map(String::as_str).collect();

        // Emit the section's own YAML block, unless everything is hoisted.
        let has_body = section_has_body(&node, &hoisted_refs);
        if has_body {
            lines.push("```yaml".to_owned());
            let body = self.emit_value(name, &node, 0, name, &hoisted_refs, None);
            lines.extend(body);
            lines.push("```".to_owned());
            lines.push(String::new());
        }

        if !after.is_empty() {
            lines.push(after);
            lines.push(String::new());
        }

        // Emit hoisted subsections.
        for field in &hoisted {
            self.render_hoisted(lines, name, &node, field);
        }
    }

    fn render_hoisted(
        &mut self,
        lines: &mut Vec<String>,
        section: &str,
        node: &Value,
        field: &str,
    ) {
        let Some(field_node) = node
            .get("properties")
            .and_then(Value::as_object)
            .and_then(|props| props.get(field))
        else {
            return;
        };
        let field_node = self.strip_null(field_node);

        lines.push(format!("### `{section}.{field}`"));
        lines.push(String::new());

        // Field description, split around an optional `<!-- more -->` marker.
        let (before, after) = split_more(
            field_node
                .get("description")
                .and_then(Value::as_str)
                .map(clean_description)
                .as_deref()
                .unwrap_or_default(),
        );
        if !before.is_empty() {
            lines.push(before);
            lines.push(String::new());
        }

        lines.push("```yaml".to_owned());
        lines.push(format!("{section}:"));
        let path = format!("{section}.{field}");
        let body = self.emit_value(field, &field_node, 2, &path, &[], None);
        lines.extend(body);
        lines.push("```".to_owned());
        lines.push(String::new());

        if !after.is_empty() {
            lines.push(after);
            lines.push(String::new());
        }
    }

    /// Emit a single field: its comment lines followed by its value.
    ///
    /// A field marked with `x-doc.skip` emits nothing (its content is
    /// hand-authored in a sibling's `x-doc.yaml` block). A field with
    /// `x-doc.yaml` is entirely hand-authored: the raw YAML (comments and key
    /// line included) replaces the whole emission.
    fn emit_field(
        &mut self,
        name: &str,
        node: &Value,
        indent: usize,
        path: &str,
        inherited: Option<&Value>,
    ) -> Vec<String> {
        let resolved = self.strip_null(node);
        if Self::x_doc_skip(&resolved) {
            return Vec::new();
        }
        if let Some(yaml) = Self::x_doc_yaml(&resolved) {
            return reindent(&yaml, indent);
        }
        let commented = Self::x_doc_commented(&resolved);

        let mut out = comment_lines(&resolved, indent);
        let value = self.emit_value(name, &resolved, indent, path, &[], inherited);
        if commented {
            out.extend(value.into_iter().map(|line| comment_out(&line)));
        } else {
            out.extend(value);
        }
        out
    }

    /// Emit the value of a field: `name:` and everything below it, unindented
    /// by `indent` spaces. `skip` names direct children to omit (used to hoist
    /// subsections out of a section's body).
    fn emit_value(
        &mut self,
        name: &str,
        resolved: &Value,
        indent: usize,
        path: &str,
        skip: &[&str],
        inherited: Option<&Value>,
    ) -> Vec<String> {
        let pad = " ".repeat(indent);

        // An explicit example wins over recursing into the value's structure:
        // it renders as one YAML block and short-circuits descending into
        // (potentially huge) sub-schemas like the JSON Web Key types.
        if resolved
            .get("examples")
            .and_then(Value::as_array)
            .is_some_and(|examples| !examples.is_empty())
        {
            return self.emit_leaf(name, resolved, indent, path, inherited);
        }

        // Object with properties → recurse into each child, handing each the
        // matching part of this object's `default` so that leaves without
        // their own example/default can still show a value (e.g. the rate
        // limiters, whose defaults are whole-object defaults on the parent).
        if let Some(props) = resolved.get("properties").and_then(Value::as_object)
            && !props.is_empty()
        {
            let defaults = resolved.get("default").or(inherited);
            let mut out = vec![format!("{pad}{name}:")];
            let mut first = true;
            for (key, child) in props {
                if skip.contains(&key.as_str()) {
                    continue;
                }
                let child_path = format!("{path}.{key}");
                let child_inherited = defaults.and_then(|d| d.get(key));
                let emitted = self.emit_field(key, child, indent + 2, &child_path, child_inherited);
                if emitted.is_empty() {
                    continue;
                }
                if !first {
                    out.push(String::new());
                }
                first = false;
                out.extend(emitted);
            }
            return out;
        }

        // Arrays with structured items.
        if resolved.get("type").and_then(Value::as_str) == Some("array")
            && let Some(items) = resolved.get("items")
        {
            let items = self.strip_null(items);
            let item_path = format!("{path}[]");

            let has_props = items
                .get("properties")
                .and_then(Value::as_object)
                .is_some_and(|p| !p.is_empty());
            if has_props {
                let mut out = vec![format!("{pad}{name}:")];
                out.extend(self.render_list_item(&items, indent + 2, &item_path));
                return out;
            }

            if let Some(variants) = variants_of(&items) {
                let mut out = vec![format!("{pad}{name}:")];
                out.extend(self.render_variants(&variants, indent + 2, &item_path));
                return out;
            }
        }

        // Leaf value: example, then default, then a commented placeholder.
        self.emit_leaf(name, resolved, indent, path, inherited)
    }

    /// Emit a leaf value using the first example, then the default (own or
    /// inherited from a parent object's default), then a commented
    /// placeholder (which also records a warning).
    fn emit_leaf(
        &mut self,
        name: &str,
        resolved: &Value,
        indent: usize,
        path: &str,
        inherited: Option<&Value>,
    ) -> Vec<String> {
        // A `const` is a fixed value: render it directly.
        if let Some(constant) = resolved.get("const") {
            return render_scalar(name, constant, resolved, indent);
        }

        if let Some(example) = resolved
            .get("examples")
            .and_then(Value::as_array)
            .and_then(|a| a.first())
        {
            return render_scalar(name, example, resolved, indent);
        }

        if let Some(default) = resolved.get("default")
            && !default.is_null()
        {
            return render_scalar(name, default, resolved, indent);
        }

        if let Some(inherited) = inherited
            && !inherited.is_null()
        {
            return render_scalar(name, inherited, resolved, indent);
        }

        let pad = " ".repeat(indent);

        // A field explicitly marked `commented` with no value to show renders
        // as a bare commented-out key, without a placeholder or a warning.
        if Self::x_doc_commented(resolved) {
            return vec![format!("{pad}{name}:")];
        }

        self.warn(format!("missing example: {path}"));
        vec![format!("{pad}#{name}: <{}>", placeholder_type(resolved))]
    }

    /// Render a single list item (`- …`) whose type is an object with
    /// properties, splicing the `- ` marker into the first emitted line.
    fn render_list_item(&mut self, item: &Value, dash_indent: usize, path: &str) -> Vec<String> {
        let mut lines = Vec::new();
        if let Some(props) = item.get("properties").and_then(Value::as_object) {
            // Emit `const` properties (an internally-tagged enum's tag, e.g. a
            // resource's `name`) before the variant's other fields: the tag is
            // what identifies the item, so it reads best first.
            let (tags, fields): (Vec<_>, Vec<_>) = props
                .iter()
                .partition(|(_, child)| child.get("const").is_some());
            let mut first = true;
            for (key, child) in tags.into_iter().chain(fields) {
                let child_path = format!("{path}.{key}");
                let emitted = self.emit_field(key, child, dash_indent + 2, &child_path, None);
                if emitted.is_empty() {
                    continue;
                }
                if !first {
                    lines.push(String::new());
                }
                first = false;
                lines.extend(emitted);
            }
        }
        splice_dash(&mut lines, dash_indent);
        lines
    }

    /// Render one list item per variant of an `anyOf`/`oneOf`, each preceded by
    /// its variant description as a comment.
    fn render_variants(
        &mut self,
        variants: &[Value],
        dash_indent: usize,
        path: &str,
    ) -> Vec<String> {
        let pad = " ".repeat(dash_indent);
        let mut out = Vec::new();

        for (index, variant) in variants.iter().enumerate() {
            if index > 0 {
                out.push(String::new());
            }
            let resolved = self.strip_null(variant);

            if let Some(desc) = resolved.get("description").and_then(Value::as_str) {
                out.extend(comment_block(&clean_description(desc), dash_indent));
            }

            let has_props = resolved
                .get("properties")
                .and_then(Value::as_object)
                .is_some_and(|p| !p.is_empty());

            if has_props {
                out.extend(self.render_list_item(&resolved, dash_indent, path));
            } else if let Some(constant) = resolved.get("const").and_then(Value::as_str) {
                out.push(format!("{pad}- {constant}"));
            } else {
                self.warn(format!("missing example: {path}"));
                out.push(format!("{pad}- <{}>", placeholder_type(&resolved)));
            }
        }

        out
    }
}

// --- Free functions --------------------------------------------------------

/// Collapse runs of blank lines and ensure a single trailing newline.
fn finalize(lines: &[String]) -> String {
    let mut output = String::new();
    let mut previous_blank = true; // suppresses a leading blank line
    for line in lines {
        let blank = line.is_empty();
        if blank && previous_blank {
            continue;
        }
        previous_blank = blank;
        output.push_str(line);
        output.push('\n');
    }
    while output.ends_with("\n\n") {
        output.pop();
    }
    output
}

/// Strip the single leading space schemars keeps on each doc-comment line.
fn clean_description(desc: &str) -> String {
    desc.lines()
        .map(|line| line.strip_prefix(' ').unwrap_or(line))
        .collect::<Vec<_>>()
        .join("\n")
        .trim_end()
        .to_owned()
}

/// Split a section description around a `<!-- more -->` marker line.
fn split_more(desc: &str) -> (String, String) {
    let mut before = Vec::new();
    let mut after = Vec::new();
    let mut seen = false;
    for line in desc.lines() {
        if line.trim() == "<!-- more -->" {
            seen = true;
            continue;
        }
        if seen {
            after.push(line);
        } else {
            before.push(line);
        }
    }
    (
        before.join("\n").trim_end().to_owned(),
        after.join("\n").trim().to_owned(),
    )
}

/// Build the comment lines for a field: its description, wrapped, plus a
/// "Possible values" block for described string enums.
fn comment_lines(resolved: &Value, indent: usize) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(desc) = resolved.get("description").and_then(Value::as_str) {
        out.extend(comment_block(&clean_description(desc), indent));
    }

    if let Some(info) = enum_info(resolved)
        && info.has_descriptions
    {
        let pad = " ".repeat(indent);
        out.push(format!("{pad}# Possible values are:"));
        for (value, desc) in &info.values {
            let first = format!("{pad}#  - `{value}`: ");
            let cont = format!("{pad}#     ");
            let text = desc.as_deref().map(clean_description).unwrap_or_default();
            let words: Vec<&str> = text.split_whitespace().collect();
            out.extend(wrap_prefixed(&words, &first, &cont, 80));
        }
    }

    out
}

/// Turn a description into `# `-prefixed comment lines, wrapped to ~80 columns.
///
/// Blank lines become a bare `#`. Lines that look like list items or are
/// indented are emitted verbatim (their markers/indentation preserved) rather
/// than being reflowed.
fn comment_block(desc: &str, indent: usize) -> Vec<String> {
    let pad = " ".repeat(indent);
    let prefix = format!("{pad}# ");
    let mut out = Vec::new();
    let mut paragraph: Vec<&str> = Vec::new();

    let flush = |paragraph: &mut Vec<&str>, out: &mut Vec<String>| {
        if !paragraph.is_empty() {
            let words: Vec<&str> = paragraph
                .iter()
                .flat_map(|l| l.split_whitespace())
                .collect();
            out.extend(wrap_prefixed(&words, &prefix, &prefix, 80));
            paragraph.clear();
        }
    };

    for line in desc.lines() {
        if line.trim().is_empty() {
            flush(&mut paragraph, &mut out);
            out.push(format!("{pad}#"));
        } else if is_structured(line) {
            flush(&mut paragraph, &mut out);
            out.push(format!("{pad}# {line}"));
        } else {
            paragraph.push(line);
        }
    }
    flush(&mut paragraph, &mut out);

    out
}

/// Whether a description line should be preserved verbatim (list item or
/// indented) rather than reflowed with its neighbours.
fn is_structured(line: &str) -> bool {
    if line.starts_with(char::is_whitespace) {
        return true;
    }
    let trimmed = line.trim_start();
    trimmed.starts_with("- ") || trimmed.starts_with("* ")
}

/// Greedy word wrap into lines that start with `first`, continuing with `cont`,
/// aiming to keep each line at most `width` columns wide.
fn wrap_prefixed(words: &[&str], first: &str, cont: &str, width: usize) -> Vec<String> {
    if words.is_empty() {
        return vec![first.trim_end().to_owned()];
    }

    let mut lines = Vec::new();
    let mut current = first.to_owned();
    let mut has_word = false;

    for word in words {
        let projected = current.len() + usize::from(has_word) + word.len();
        if has_word && projected > width {
            lines.push(std::mem::take(&mut current));
            current.push_str(cont);
            current.push_str(word);
        } else {
            if has_word {
                current.push(' ');
            }
            current.push_str(word);
        }
        has_word = true;
    }
    lines.push(current);
    lines
}

/// Comment out a rendered value line by inserting `#` at the line's own
/// indentation.
///
/// Lines that are already comments (or already commented) are
/// left untouched, to avoid doubling up `#`s under a commented parent.
fn comment_out(line: &str) -> String {
    if line.trim().is_empty() {
        return line.to_owned();
    }
    // Insert the `#` at the line's own indentation level, so that nested
    // structures stay readable (`#key:` on the parent, `  #child: x` below).
    let pos = line.len() - line.trim_start().len();
    let (lead, rest) = line.split_at(pos);
    if rest.starts_with('#') {
        return line.to_owned();
    }
    format!("{lead}#{rest}")
}

/// Splice a `- ` list marker into the first non-blank line of an item block.
fn splice_dash(lines: &mut [String], dash_indent: usize) {
    if let Some(line) = lines.iter_mut().find(|l| !l.trim().is_empty()) {
        let content = line.get(dash_indent + 2..).unwrap_or("").to_owned();
        *line = format!("{}- {content}", " ".repeat(dash_indent));
    }
}

/// Re-indent a raw multi-line string so that its least-indented line sits at
/// `indent` columns.
fn reindent(text: &str, indent: usize) -> Vec<String> {
    let pad = " ".repeat(indent);
    let min = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.len() - l.trim_start().len())
        .min()
        .unwrap_or(0);
    text.lines()
        .map(|line| {
            if line.trim().is_empty() {
                String::new()
            } else {
                format!("{pad}{}", &line[min..])
            }
        })
        .collect()
}

/// Extract the `anyOf`/`oneOf` variants of a node, if any.
fn variants_of(node: &Value) -> Option<Vec<Value>> {
    node.get("oneOf")
        .or_else(|| node.get("anyOf"))
        .and_then(Value::as_array)
        .cloned()
}

/// Detect a string enum, either as a plain `enum` list or a `oneOf` of `const`
/// string variants, collecting per-variant descriptions where present.
fn enum_info(node: &Value) -> Option<EnumInfo> {
    if let Some(values) = node.get("enum").and_then(Value::as_array) {
        let values: Vec<(String, Option<String>)> = values
            .iter()
            .filter_map(|v| v.as_str().map(|s| (s.to_owned(), None)))
            .collect();
        if values.is_empty() {
            return None;
        }
        return Some(EnumInfo {
            values,
            has_descriptions: false,
        });
    }

    let variants = node.get("oneOf").and_then(Value::as_array)?;
    let mut values = Vec::new();
    for variant in variants {
        let constant = variant.get("const").and_then(Value::as_str)?;
        let desc = variant
            .get("description")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        values.push((constant.to_owned(), desc));
    }
    if values.is_empty() {
        return None;
    }
    let has_descriptions = values.iter().any(|(_, d)| d.is_some());
    Some(EnumInfo {
        values,
        has_descriptions,
    })
}

/// Render a scalar/inline/block leaf value as `name: <value>` lines.
fn render_scalar(name: &str, value: &Value, resolved: &Value, indent: usize) -> Vec<String> {
    let pad = " ".repeat(indent);
    match value {
        Value::Array(items) if items.is_empty() => vec![format!("{pad}{name}: []")],
        // Strings containing a colon (URLs, mostly) are not valid plain
        // scalars in a flow sequence — render those lists in block style.
        Value::Array(items)
            if items.iter().all(is_scalar)
                && inline_len(items) <= 60
                && !items
                    .iter()
                    .any(|i| i.as_str().is_some_and(|s| s.contains(':'))) =>
        {
            vec![format!("{pad}{name}: {}", inline_array(items))]
        }
        Value::Object(_) | Value::Array(_) => {
            let mut out = vec![format!("{pad}{name}:")];
            out.extend(yaml_block(value, indent + 2));
            out
        }
        Value::String(text) if text.contains('\n') => {
            let mut out = vec![format!("{pad}{name}: |")];
            let inner = " ".repeat(indent + 2);
            for line in text.lines() {
                out.push(format!("{inner}{line}"));
            }
            out
        }
        _ => {
            let mut line = format!("{pad}{name}: {}", yaml_scalar(value));
            if let Some(trailing) = enum_trailing(resolved, value) {
                line.push_str(&trailing);
            }
            vec![line]
        }
    }
}

/// A trailing `# or a, b, c` comment listing the other values of an
/// undescribed enum, or `None` when it does not apply.
fn enum_trailing(resolved: &Value, value: &Value) -> Option<String> {
    let info = enum_info(resolved)?;
    if info.has_descriptions {
        return None;
    }
    let shown = value.as_str()?;
    let others: Vec<&str> = info
        .values
        .iter()
        .map(|(v, _)| v.as_str())
        .filter(|v| *v != shown)
        .collect();
    // A trailing list only reads well for small enums; huge ones (e.g. the
    // JSON Web Signature algorithms) are better left to the field's docs.
    if others.is_empty() || others.len() > 6 {
        return None;
    }
    Some(format!(" # or {}", others.join(", ")))
}

fn is_scalar(value: &Value) -> bool {
    !matches!(value, Value::Array(_) | Value::Object(_))
}

fn inline_len(items: &[Value]) -> usize {
    inline_array(items).len()
}

fn inline_array(items: &[Value]) -> String {
    let rendered: Vec<String> = items.iter().map(yaml_scalar).collect();
    format!("[{}]", rendered.join(", "))
}

/// Render a scalar JSON value as a single-line YAML token.
fn yaml_scalar(value: &Value) -> String {
    match value {
        Value::Null => "~".to_owned(),
        Value::Bool(b) => b.to_string(),
        // Display floats with at most 6 decimal places: whole-object defaults
        // carry values like 1/1200 whose full f64 expansion is unreadable.
        Value::Number(n) if n.as_f64().is_some_and(|f| f.fract() != 0.0) => {
            let formatted = format!("{:.6}", n.as_f64().unwrap_or_default());
            formatted.trim_end_matches('0').to_owned()
        }
        Value::Number(n) => n.to_string(),
        _ => serde_yaml::to_string(value)
            .unwrap_or_default()
            .trim_end()
            .to_owned(),
    }
}

/// Render a JSON value as a block of YAML lines indented to `indent` columns.
fn yaml_block(value: &Value, indent: usize) -> Vec<String> {
    let yaml = serde_yaml::to_string(value).unwrap_or_default();
    reindent(&yaml, indent)
}

/// A placeholder type name for a field with no example or default.
fn placeholder_type(resolved: &Value) -> &'static str {
    let type_name = match resolved.get("type") {
        Some(Value::String(t)) => Some(t.as_str()),
        Some(Value::Array(types)) => types
            .iter()
            .filter_map(Value::as_str)
            .find(|t| *t != "null"),
        _ => None,
    };

    match type_name {
        Some("integer") => "integer",
        Some("number") => "number",
        Some("boolean") => "boolean",
        Some("array") => "array",
        Some("object") => "object",
        Some("string") => "string",
        _ => {
            if resolved.get("oneOf").is_some()
                || resolved.get("anyOf").is_some()
                || resolved.get("enum").is_some()
            {
                "string"
            } else {
                "value"
            }
        }
    }
}

/// Whether a section has any fields left to render once hoisted fields and
/// the like are removed.
fn section_has_body(node: &Value, skip: &[&str]) -> bool {
    // Non-object sections (e.g. the `clients` array) always have a body.
    let Some(props) = node.get("properties").and_then(Value::as_object) else {
        return true;
    };
    props.keys().any(|key| !skip.contains(&key.as_str()))
}
