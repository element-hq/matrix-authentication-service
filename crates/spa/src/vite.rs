// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::collections::{BTreeSet, HashMap};

use camino::{Utf8Path, Utf8PathBuf};
use thiserror::Error;

#[derive(serde::Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManifestEntry {
    #[expect(dead_code)]
    name: Option<String>,

    #[expect(dead_code)]
    names: Option<Vec<String>>,

    #[expect(dead_code)]
    src: Option<Utf8PathBuf>,

    file: Utf8PathBuf,

    css: Option<Vec<Utf8PathBuf>>,

    assets: Option<Vec<Utf8PathBuf>>,

    #[expect(dead_code)]
    is_entry: Option<bool>,

    #[expect(dead_code)]
    is_dynamic_entry: Option<bool>,

    imports: Option<Vec<Utf8PathBuf>>,

    #[expect(dead_code)]
    dynamic_imports: Option<Vec<Utf8PathBuf>>,

    integrity: Option<String>,
}

#[derive(serde::Deserialize, Debug, Clone)]
pub struct Manifest {
    #[serde(flatten)]
    inner: HashMap<Utf8PathBuf, ManifestEntry>,
}

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
enum FileType {
    Script,
    Stylesheet,
    Woff,
    Woff2,
    Json,
    Png,
}

impl FileType {
    fn from_name(name: &Utf8Path) -> Option<Self> {
        match name.extension() {
            Some("css") => Some(Self::Stylesheet),
            Some("js") => Some(Self::Script),
            Some("woff") => Some(Self::Woff),
            Some("woff2") => Some(Self::Woff2),
            Some("json") => Some(Self::Json),
            Some("png") => Some(Self::Png),
            _ => None,
        }
    }
}

#[derive(Debug, Error)]
#[error("Invalid Vite manifest")]
pub enum InvalidManifest<'a> {
    #[error("Can't find asset for name {name:?}")]
    CantFindAssetByName { name: &'a Utf8Path },

    #[error("Can't find asset for file {file:?}")]
    CantFindAssetByFile { file: &'a Utf8Path },

    #[error("Invalid file type")]
    InvalidFileType,
}

/// Represents an entry which should be preloaded and included
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Asset<'a> {
    file_type: FileType,
    name: &'a Utf8Path,
    integrity: Option<&'a str>,
}

impl<'a> Asset<'a> {
    fn new(entry: &'a ManifestEntry) -> Result<Self, InvalidManifest<'a>> {
        let name = &entry.file;
        let integrity = entry.integrity.as_deref();
        let file_type = FileType::from_name(name).ok_or(InvalidManifest::InvalidFileType)?;
        Ok(Self {
            file_type,
            name,
            integrity,
        })
    }

    fn src(&self, assets_base: &Utf8Path) -> Utf8PathBuf {
        assets_base.join(self.name)
    }

    /// Generate a `<link rel="preload">` tag to preload this entry
    pub fn preload_tag(&self, assets_base: &Utf8Path) -> String {
        let href = self.src(assets_base);
        let integrity = self
            .integrity
            .map(|i| format!(r#"integrity="{i}" "#))
            .unwrap_or_default();
        match self.file_type {
            FileType::Stylesheet => {
                format!(r#"<link rel="preload" href="{href}" as="style" crossorigin {integrity}/>"#)
            }
            FileType::Script => {
                format!(r#"<link rel="modulepreload" href="{href}" crossorigin {integrity}/>"#)
            }
            FileType::Woff | FileType::Woff2 => {
                format!(r#"<link rel="preload" href="{href}" as="font" crossorigin {integrity}/>"#,)
            }
            FileType::Json => {
                format!(r#"<link rel="preload" href="{href}" as="fetch" crossorigin {integrity}/>"#,)
            }
            FileType::Png => {
                format!(r#"<link rel="preload" href="{href}" as="image" crossorigin {integrity}/>"#,)
            }
        }
    }

    /// Generate a `<link>` or `<script>` tag to include this entry
    pub fn include_tag(&self, assets_base: &Utf8Path) -> Option<String> {
        let src = self.src(assets_base);
        let integrity = self
            .integrity
            .map(|i| format!(r#"integrity="{i}" "#))
            .unwrap_or_default();

        match self.file_type {
            FileType::Stylesheet => Some(format!(
                r#"<link rel="stylesheet" href="{src}" crossorigin {integrity}/>"#
            )),
            FileType::Script => Some(format!(
                r#"<script type="module" src="{src}" crossorigin {integrity}></script>"#
            )),
            FileType::Woff | FileType::Woff2 | FileType::Json | FileType::Png => None,
        }
    }

    /// Returns `true` if the asset type is a script
    #[must_use]
    pub fn is_script(&self) -> bool {
        self.file_type == FileType::Script
    }

    /// Returns `true` if the asset type is a stylesheet
    #[must_use]
    pub fn is_stylesheet(&self) -> bool {
        self.file_type == FileType::Stylesheet
    }

    /// Returns `true` if the asset type is JSON
    #[must_use]
    pub fn is_json(&self) -> bool {
        self.file_type == FileType::Json
    }

    /// Returns `true` if the asset type is a font
    #[must_use]
    pub fn is_font(&self) -> bool {
        self.file_type == FileType::Woff || self.file_type == FileType::Woff2
    }

    /// Returns `true` if the asset type is image
    #[must_use]
    pub fn is_image(&self) -> bool {
        self.file_type == FileType::Png
    }
}

impl Manifest {
    /// Find all assets which should be loaded for a given entrypoint
    ///
    /// Returns the main asset and all the assets it imports
    ///
    /// # Errors
    ///
    /// Returns an error if the entrypoint is invalid for this manifest
    pub fn find_assets<'a>(
        &'a self,
        entrypoint: &'a Utf8Path,
    ) -> Result<(Asset<'a>, BTreeSet<Asset<'a>>), InvalidManifest<'a>> {
        let entry = self.lookup_by_name(entrypoint)?;
        let mut entries = BTreeSet::new();
        let main_asset = self.find_imported_chunks(entry, &mut entries)?;

        // Remove the main asset from the set of imported entries. We had it mainly to
        // deduplicate the list of assets, but we don't want to include it twice
        entries.remove(&main_asset);

        Ok((main_asset, entries))
    }

    /// Lookup an entry in the manifest by its original name
    fn lookup_by_name<'a>(
        &self,
        name: &'a Utf8Path,
    ) -> Result<&ManifestEntry, InvalidManifest<'a>> {
        self.inner
            .get(name)
            .ok_or(InvalidManifest::CantFindAssetByName { name })
    }

    /// Lookup an entry in the manifest by its output name
    fn lookup_by_file<'a>(
        &self,
        file: &'a Utf8Path,
    ) -> Result<&ManifestEntry, InvalidManifest<'a>> {
        self.inner
            .values()
            .find(|e| e.file == file)
            .ok_or(InvalidManifest::CantFindAssetByFile { file })
    }

    fn find_imported_chunks<'a>(
        &'a self,
        current_entry: &'a ManifestEntry,
        entries: &mut BTreeSet<Asset<'a>>,
    ) -> Result<Asset<'a>, InvalidManifest<'a>> {
        let asset = Asset::new(current_entry)?;
        let inserted = entries.insert(asset);

        // If we inserted the entry, we need to find its dependencies
        if inserted {
            if let Some(css) = &current_entry.css {
                for file in css {
                    let entry = self.lookup_by_file(file)?;
                    self.find_imported_chunks(entry, entries)?;
                }
            }

            if let Some(assets) = &current_entry.assets {
                for file in assets {
                    let entry = self.lookup_by_file(file)?;
                    self.find_imported_chunks(entry, entries)?;
                }
            }

            if let Some(imports) = &current_entry.imports {
                for import in imports {
                    let entry = self.lookup_by_name(import)?;
                    self.find_imported_chunks(entry, entries)?;
                }
            }
        }

        Ok(asset)
    }
}
