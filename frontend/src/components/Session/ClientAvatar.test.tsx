// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

// @vitest-environment happy-dom

import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import ClientAvatar from "./ClientAvatar";

describe("<ClientAvatar />", () => {
  const name = "Test Client";
  const logoUri = "https://www.testclient.com/logo.png";
  const size = "10px";

  it("renders client logo", () => {
    const { container } = render(
      <ClientAvatar name={name} logoUri={logoUri} size={size} />,
    );
    expect(container).toMatchSnapshot();
  });

  it("renders nothing when no logoUri is falsy", () => {
    const { container } = render(<ClientAvatar name={name} size={size} />);
    expect(container).toMatchInlineSnapshot("<div />");
  });
});
