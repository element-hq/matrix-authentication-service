// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use minijinja::{UndefinedBehavior, context};
use rand::RngExt;

use crate::upstream_oauth2::template::environment;

/// The lowercase letters and digits of the localpart grammar
const RANDOM_CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
/// 36^32 is about 2^165 values, so two rendered names never collide
const RANDOM_LENGTH: usize = 32;

/// Render a registration token's username template, with `random` set to
/// random lowercase letters and digits
pub(crate) fn render(
    template: &str,
    rng: &mut (impl RngExt + ?Sized),
) -> Result<String, minijinja::Error> {
    let random: String = (0..RANDOM_LENGTH)
        .map(|_| char::from(RANDOM_CHARSET[rng.random_range(0..RANDOM_CHARSET.len())]))
        .collect();

    let mut env = environment();
    // A misspelt variable fails rather than rendering empty
    env.set_undefined_behavior(UndefinedBehavior::Strict);
    env.render_str(template, context! { random })
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng as _;
    use rand_chacha::ChaChaRng;

    use super::render;

    #[test]
    fn test_render() {
        let mut rng = ChaChaRng::seed_from_u64(42);

        let first = render("user-{{ random }}", &mut rng).unwrap();
        let second = render("user-{{ random }}", &mut rng).unwrap();
        assert_ne!(first, second);
        for name in [&first, &second] {
            let random = name.strip_prefix("user-").unwrap();
            assert_eq!(random.len(), 32, "{name}");
            assert!(
                random
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
                "{name}"
            );
        }

        // Single braces are literal
        assert_eq!(render("user-{random}", &mut rng).unwrap(), "user-{random}");
    }
}
