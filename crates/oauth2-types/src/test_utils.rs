// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::fmt::Debug;

use serde::{Serialize, de::DeserializeOwned};

#[track_caller]
pub(crate) fn assert_serde_json<T: Serialize + DeserializeOwned + PartialEq + Debug>(
    got: &T,
    expected_value: serde_json::Value,
) {
    let got_value = serde_json::to_value(got).expect("could not serialize object as JSON value");
    assert_eq!(got_value, expected_value);

    let expected: T = serde_json::from_value(expected_value)
        .expect("could not deserialize object from JSON value");
    assert_eq!(got, &expected);
}
