// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::sync::LazyLock;

use serde::Serialize;
use woothee::{parser::Parser, woothee::VALUE_UNKNOWN};

static CUSTOM_USER_AGENT_REGEX: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"^(?P<name>[^/]+)/(?P<version>[^ ]+) \((?P<segments>.+)\)$").unwrap()
});

static ELECTRON_USER_AGENT_REGEX: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"(?m)\w+/[\w.]+").unwrap());

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeviceType {
    Pc,
    Mobile,
    Tablet,
    Unknown,
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct UserAgent {
    pub name: Option<String>,
    pub version: Option<String>,
    pub os: Option<String>,
    pub os_version: Option<String>,
    pub model: Option<String>,
    pub device_type: DeviceType,
    pub raw: String,
}

impl std::ops::Deref for UserAgent {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.raw
    }
}

impl UserAgent {
    fn parse_custom(user_agent: &str) -> Option<(&str, &str, &str, &str, Option<&str>)> {
        let captures = CUSTOM_USER_AGENT_REGEX.captures(user_agent)?;
        let name = captures.name("name")?.as_str();
        let version = captures.name("version")?.as_str();
        let segments: Vec<&str> = captures
            .name("segments")?
            .as_str()
            .split(';')
            .map(str::trim)
            .collect();

        match segments[..] {
            ["Linux", "U", os, model, ..] | [model, os, ..] => {
                // Most android model have a `/[build version]` suffix we don't care about
                let model = model.split_once('/').map_or(model, |(model, _)| model);
                // Some android version also have `Build/[build version]` suffix we don't care
                // about
                let model = model.strip_suffix("Build").unwrap_or(model);
                // And let's trim any leftovers
                let model = model.trim();

                let (os, os_version) = if let Some((os, version)) = os.split_once(' ') {
                    (os, Some(version))
                } else {
                    (os, None)
                };

                Some((name, version, model, os, os_version))
            }
            _ => None,
        }
    }

    fn parse_electron(user_agent: &str) -> Option<(&str, &str)> {
        let omit_keys = ["Mozilla", "AppleWebKit", "Chrome", "Electron", "Safari"];
        return ELECTRON_USER_AGENT_REGEX
            .find_iter(user_agent)
            .map(|caps| caps.as_str().split_once('/').unwrap())
            .find(|pair| !omit_keys.contains(&pair.0));
    }

    #[must_use]
    pub fn parse(user_agent: String) -> Self {
        if !user_agent.contains("Mozilla/")
            && let Some((name, version, model, os, os_version)) =
                UserAgent::parse_custom(&user_agent)
        {
            let mut device_type = DeviceType::Unknown;

            // Handle mobile simple mobile devices
            if os == "Android" || os == "iOS" {
                device_type = DeviceType::Mobile;
            }

            // Handle iPads
            if model.contains("iPad") {
                device_type = DeviceType::Tablet;
            }

            return Self {
                name: Some(name.to_owned()),
                version: Some(version.to_owned()),
                os: Some(os.to_owned()),
                os_version: os_version.map(std::borrow::ToOwned::to_owned),
                model: Some(model.to_owned()),
                device_type,
                raw: user_agent,
            };
        }

        let mut model = None;
        let Some(mut result) = Parser::new().parse(&user_agent) else {
            return Self {
                raw: user_agent,
                name: None,
                version: None,
                os: None,
                os_version: None,
                model: None,
                device_type: DeviceType::Unknown,
            };
        };

        let mut device_type = match result.category {
            "pc" => DeviceType::Pc,
            "smartphone" | "mobilephone" => DeviceType::Mobile,
            _ => DeviceType::Unknown,
        };

        // Special handling for Chrome user-agent reduction cases
        // https://www.chromium.org/updates/ua-reduction/
        match (result.os, &*result.os_version) {
            // Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/533.88 (KHTML, like Gecko)
            // Chrome/109.1.2342.76 Safari/533.88
            ("Windows 10", "NT 10.0") if user_agent.contains("Windows NT 10.0; Win64; x64") => {
                result.os = "Windows";
                result.os_version = VALUE_UNKNOWN.into();
            }

            // Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko)
            // Chrome/100.0.0.0 Safari/537.36
            ("Linux", _) if user_agent.contains("X11; Linux x86_64") => {
                result.os = "Linux";
                result.os_version = VALUE_UNKNOWN.into();
            }

            // Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko)
            // Chrome/107.0.0.0 Safari/537.36
            ("ChromeOS", _) if user_agent.contains("X11; CrOS x86_64 14541.0.0") => {
                result.os = "Chrome OS";
                result.os_version = VALUE_UNKNOWN.into();
            }

            // Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko)
            // Chrome/100.0.0.0 Mobile Safari/537.36
            ("Android", "10") if user_agent.contains("Linux; Android 10; K") => {
                result.os = "Android";
                result.os_version = VALUE_UNKNOWN.into();
            }

            // Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like
            // Gecko) Chrome/100.0.4896.133 Safari/537.36
            // Safari also freezes the OS version
            // Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like
            // Gecko) Version/17.3.1 Safari/605.1.15
            ("Mac OSX", "10.15.7") if user_agent.contains("Macintosh; Intel Mac OS X 10_15_7") => {
                result.os = "macOS";
                result.os_version = VALUE_UNKNOWN.into();
            }

            // Woothee identifies iPhone and iPod in the OS, but we want to map them to iOS and use
            // them as model
            ("iPhone" | "iPod", _) => {
                model = Some(result.os.to_owned());
                result.os = "iOS";
            }

            ("iPad", _) => {
                model = Some(result.os.to_owned());
                device_type = DeviceType::Tablet;
                result.os = "iPadOS";
            }

            // Also map `Mac OSX` to `macOS`
            ("Mac OSX", _) => {
                result.os = "macOS";
            }

            _ => {}
        }

        // For some reason, the version on Windows is on the OS field
        // This transforms `Windows 10` into `Windows` and `10`
        if let Some(version) = result.os.strip_prefix("Windows ") {
            result.os = "Windows";
            result.os_version = version.into();
        }

        // Special handling for Electron applications e.g. Element Desktop
        if user_agent.contains("Electron/")
            && let Some(app) = UserAgent::parse_electron(&user_agent)
        {
            result.name = app.0;
            result.version = app.1;
        }

        Self {
            name: (result.name != VALUE_UNKNOWN).then(|| result.name.to_owned()),
            version: (result.version != VALUE_UNKNOWN).then(|| result.version.to_owned()),
            os: (result.os != VALUE_UNKNOWN).then(|| result.os.to_owned()),
            os_version: (result.os_version != VALUE_UNKNOWN)
                .then(|| result.os_version.into_owned()),
            device_type,
            model,
            raw: user_agent,
        }
    }
}
