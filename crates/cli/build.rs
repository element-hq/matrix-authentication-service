// Copyright 2024 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use vergen_gitcl::{Emitter, GitclBuilder, RustcBuilder};

fn main() -> anyhow::Result<()> {
    let gitcl = GitclBuilder::default().describe(true, true, None).build()?;
    let rustc = RustcBuilder::default().semver(true).build()?;

    Emitter::default()
        .add_instructions(&gitcl)?
        .add_instructions(&rustc)?
        .emit()?;

    Ok(())
}
