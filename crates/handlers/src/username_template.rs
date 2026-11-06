// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use minijinja::{UndefinedBehavior, context};

use crate::upstream_oauth2::template::environment;

/// 36^32 is about 2^165 values, so two rendered names never collide
const RANDOM_LENGTH: usize = 32;
/// A `random` with letters and digits in turn, so a policy that refuses
/// either refuses the sample too
const SAMPLE_RANDOM: &str = "a0b1c2d3e4f5g6h7i8j9k0l1m2n3o4p5";
const _: () = assert!(SAMPLE_RANDOM.len() == RANDOM_LENGTH);

/// Render a registration token's username template, with a sample `random`
pub(crate) fn render_sample(template: &str) -> Result<String, minijinja::Error> {
    render_with(template, SAMPLE_RANDOM)
}

fn render_with(template: &str, random: &str) -> Result<String, minijinja::Error> {
    let mut env = environment();
    // A misspelt variable fails rather than rendering empty
    env.set_undefined_behavior(UndefinedBehavior::Strict);
    env.render_str(template, context! { random })
}
