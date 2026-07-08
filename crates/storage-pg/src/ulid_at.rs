// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Helpers to translate "created before/after a timestamp" filters into
//! ULID-based primary key comparisons.
//!
//! ULIDs encode their creation timestamp (in milliseconds) in their high 48
//! bits. Because session tables use ULIDs as their primary key, we can filter
//! on a creation time by comparing the primary key against a synthetic ULID
//! with the same timestamp and either the smallest or largest possible random
//! component. This lets the existing primary key B-tree index serve the query
//! without adding a separate `created_at` index.

use chrono::{DateTime, Utc};
use ulid::Ulid;
use uuid::Uuid;

/// Build the smallest possible [`Uuid`] for a ULID generated at the given time.
///
/// Use this as the upper bound when filtering rows created strictly *before*
/// `t`: `id < min_ulid_at(t)`.
pub(crate) fn min_ulid_at(t: DateTime<Utc>) -> Uuid {
    let timestamp = u64::try_from(t.timestamp_millis()).unwrap_or(u64::MIN);
    Ulid::from_parts(timestamp, 0).into()
}

/// Build the largest possible [`Uuid`] for a ULID generated at the given time.
///
/// Use this as the lower bound when filtering rows created strictly *after*
/// `t`: `id > max_ulid_at(t)`.
pub(crate) fn max_ulid_at(t: DateTime<Utc>) -> Uuid {
    let timestamp = u64::try_from(t.timestamp_millis()).unwrap_or(u64::MIN);
    Ulid::from_parts(timestamp, u128::MAX).into()
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use ulid::Ulid;

    use super::{max_ulid_at, min_ulid_at};

    #[test]
    fn min_is_less_than_max_at_same_time() {
        let t = chrono::Utc
            .with_ymd_and_hms(2024, 6, 1, 12, 34, 56)
            .unwrap();
        let min = min_ulid_at(t);
        let max = max_ulid_at(t);
        assert!(min < max, "min ({min}) should be less than max ({max})");
    }

    #[test]
    fn timestamp_roundtrips() {
        let t = chrono::Utc
            .with_ymd_and_hms(2024, 6, 1, 12, 34, 56)
            .unwrap()
            + chrono::Duration::milliseconds(789);
        let expected_ms = u64::try_from(t.timestamp_millis()).unwrap();

        let min_ulid: Ulid = min_ulid_at(t).into();
        let max_ulid: Ulid = max_ulid_at(t).into();

        assert_eq!(min_ulid.timestamp_ms(), expected_ms);
        assert_eq!(max_ulid.timestamp_ms(), expected_ms);
        // The random component of a ULID is 80 bits wide, so `u128::MAX` is
        // truncated to the largest 80-bit value.
        assert_eq!(min_ulid.random(), 0);
        assert_eq!(max_ulid.random(), (1u128 << 80) - 1);
    }

    #[test]
    fn distinct_times_produce_distinct_bounds() {
        let earlier = chrono::Utc.with_ymd_and_hms(2024, 6, 1, 12, 0, 0).unwrap();
        let later = chrono::Utc.with_ymd_and_hms(2024, 6, 1, 13, 0, 0).unwrap();
        assert!(max_ulid_at(earlier) < min_ulid_at(later));
    }
}
