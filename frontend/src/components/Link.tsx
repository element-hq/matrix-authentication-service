// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import { createLink } from "@tanstack/react-router";
import { Link as CompoundLink } from "@vector-im/compound-web";

export const Link = createLink(CompoundLink);
