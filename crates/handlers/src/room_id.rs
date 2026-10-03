// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use ruma_common::RoomId;

/// Whether `c` is a control character, including the bidirectional controls
/// which `char::is_control` doesn't cover
pub(crate) fn is_control_or_bidi(c: char) -> bool {
    c.is_control() || matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// Whether `room_id` is a room ID, without control or bidirectional
/// characters
pub(crate) fn is_valid_room_id(room_id: &str) -> bool {
    <&RoomId>::try_from(room_id).is_ok() && !room_id.chars().any(is_control_or_bidi)
}
