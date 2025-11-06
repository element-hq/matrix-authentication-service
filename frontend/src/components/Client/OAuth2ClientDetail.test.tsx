// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

// @vitest-environment happy-dom

import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { makeFragmentData } from "../../gql/fragment-masking";

import OAuth2ClientDetail, {
  OAUTH2_CLIENT_FRAGMENT,
} from "./OAuth2ClientDetail";

describe("<OAuth2ClientDetail>", () => {
  const baseClient = {
    id: "test-id",
    clientId: "client-id",
    clientName: "Test Client",
    clientUri: "https://client.org/logo.png",
    tosUri: "https://client.org/tos",
    policyUri: "https://client.org/policy",
    redirectUris: ["https://client.org/"],
  };

  it("renders client details", () => {
    const data = makeFragmentData(baseClient, OAUTH2_CLIENT_FRAGMENT);

    const { container } = render(<OAuth2ClientDetail client={data} />);

    expect(container).toMatchSnapshot();
  });

  it("does not render terms of service when falsy", () => {
    const data = makeFragmentData(
      {
        ...baseClient,
        tosUri: undefined,
      },
      OAUTH2_CLIENT_FRAGMENT,
    );

    const { queryByText } = render(<OAuth2ClientDetail client={data} />);

    expect(queryByText("Terms of service")).toBeFalsy();
  });

  it("does not render logo when logoUri is falsy", () => {
    const data = makeFragmentData(
      {
        ...baseClient,
        logoUri: undefined,
      },
      OAUTH2_CLIENT_FRAGMENT,
    );

    const { queryByAltText } = render(<OAuth2ClientDetail client={data} />);

    expect(queryByAltText(baseClient.clientName)).toBeFalsy();
  });
});
