// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

// @vitest-environment happy-dom

import { fireEvent, render } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { makeFragmentData } from "../../gql/fragment-masking";
import { DummyRouter } from "../../test-utils/router";

import UnverifiedEmailAlert, {
  UNVERIFIED_EMAILS_FRAGMENT,
} from "./UnverifiedEmailAlert";

describe("<UnverifiedEmailAlert />", () => {
  it("does not render a warning when there are no unverified emails", () => {
    const data = makeFragmentData(
      {
        id: "abc123",
        unverifiedEmails: {
          totalCount: 0,
        },
      },
      UNVERIFIED_EMAILS_FRAGMENT,
    );

    const { container } = render(
      <DummyRouter>
        <UnverifiedEmailAlert user={data} />
      </DummyRouter>,
    );

    expect(container).toMatchInlineSnapshot("<div />");
  });

  it("renders a warning when there are unverified emails", () => {
    const data = makeFragmentData(
      {
        id: "abc123",
        unverifiedEmails: {
          totalCount: 2,
        },
      },
      UNVERIFIED_EMAILS_FRAGMENT,
    );

    const { container } = render(
      <DummyRouter>
        <UnverifiedEmailAlert user={data} />
      </DummyRouter>,
    );

    expect(container).toMatchSnapshot();
  });

  it("hides warning after it has been dismissed", () => {
    const data = makeFragmentData(
      {
        id: "abc123",
        unverifiedEmails: {
          totalCount: 2,
        },
      },
      UNVERIFIED_EMAILS_FRAGMENT,
    );

    const { container, getByText, getByLabelText } = render(
      <DummyRouter>
        <UnverifiedEmailAlert user={data} />
      </DummyRouter>,
    );

    // warning is rendered
    expect(getByText("Unverified email")).toBeTruthy();

    fireEvent.click(getByLabelText("Close"));

    // no more warning
    expect(container).toMatchInlineSnapshot("<div />");
  });

  it("hides warning when count of unverified emails becomes 0", () => {
    const data = makeFragmentData(
      {
        id: "abc123",
        unverifiedEmails: {
          totalCount: 2,
        },
      },
      UNVERIFIED_EMAILS_FRAGMENT,
    );

    const { container, getByText, rerender } = render(
      <DummyRouter>
        <UnverifiedEmailAlert user={data} />
      </DummyRouter>,
    );

    // warning is rendered
    expect(getByText("Unverified email")).toBeTruthy();

    const newData = makeFragmentData(
      {
        id: "abc123",
        unverifiedEmails: {
          totalCount: 0,
        },
      },
      UNVERIFIED_EMAILS_FRAGMENT,
    );
    rerender(
      <DummyRouter>
        <UnverifiedEmailAlert user={newData} />
      </DummyRouter>,
    );

    // warning removed
    expect(container).toMatchInlineSnapshot("<div />");
  });

  it("shows a dismissed warning again when there are new unverified emails", () => {
    const data = makeFragmentData(
      {
        id: "abc123",
        unverifiedEmails: {
          totalCount: 2,
        },
      },
      UNVERIFIED_EMAILS_FRAGMENT,
    );

    const { container, getByText, getByLabelText, rerender } = render(
      <DummyRouter>
        <UnverifiedEmailAlert user={data} />
      </DummyRouter>,
    );

    // warning is rendered
    expect(getByText("Unverified email")).toBeTruthy();

    fireEvent.click(getByLabelText("Close"));

    // no more warning
    expect(container).toMatchInlineSnapshot("<div />");

    const newData = makeFragmentData(
      {
        id: "abc123",
        unverifiedEmails: {
          totalCount: 3,
        },
      },
      UNVERIFIED_EMAILS_FRAGMENT,
    );
    rerender(
      <DummyRouter>
        <UnverifiedEmailAlert user={newData} />
      </DummyRouter>,
    );

    // warning is rendered
    expect(getByText("Unverified email")).toBeTruthy();
  });
});
