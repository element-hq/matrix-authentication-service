// Copyright 2024, 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

// @vitest-environment happy-dom

import { waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { HttpResponse } from "msw";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  mockAllowCrossSigningResetMutation,
  mockCurrentViewerQuery,
} from "../../src/gql/graphql";
import { renderPage, server } from "./render";

afterEach(() => {
  window.onAuthDone = undefined;
});

describe("Reset cross signing", () => {
  it("renders the page", async () => {
    const { asFragment } = await renderPage("/reset-cross-signing");
    expect(asFragment()).toMatchSnapshot();
  });

  it("renders the deep link page", async () => {
    const { asFragment } = await renderPage(
      "/reset-cross-signing?deepLink=true",
    );
    expect(asFragment()).toMatchSnapshot();
  });

  it("calls the callback on success", async () => {
    // TODO: a better way to wait on delays
    let advance: () => void = () => {};
    const wait = new Promise((resolve) => {
      advance = () => resolve(void 0);
    });

    window.onAuthDone = vi.fn();

    server.use(
      mockAllowCrossSigningResetMutation(async () => {
        await wait;
        return HttpResponse.json({
          data: {
            allowUserCrossSigningReset: {
              user: {
                id: "user-id",
              },
            },
          },
        });
      }),
    );

    const user = userEvent.setup();
    const { getByRole } = await renderPage(
      "/reset-cross-signing?deepLink=true",
    );

    const finishButton = getByRole("button", { name: "Finish reset" });

    expect(finishButton).not.toHaveAttribute("aria-disabled", "true");
    await user.click(finishButton);
    // The button is in a loading state
    await waitFor(() =>
      expect(finishButton).toHaveAttribute("aria-disabled", "true"),
    );

    expect(window.onAuthDone).not.toHaveBeenCalled();
    advance();
    await waitFor(() => expect(finishButton).not.toBeInTheDocument());
    expect(window.onAuthDone).toHaveBeenCalled();
  });

  it("renders the success page", async () => {
    const { asFragment } = await renderPage("/reset-cross-signing/success");
    expect(asFragment()).toMatchSnapshot();
  });

  it("renders the success page", async () => {
    const { asFragment } = await renderPage("/reset-cross-signing/success");
    expect(asFragment()).toMatchSnapshot();
  });

  it("renders the cancelled page", async () => {
    const { asFragment } = await renderPage("/reset-cross-signing/cancelled");
    expect(asFragment()).toMatchSnapshot();
  });

  it("renders the errored page", async () => {
    server.use(
      mockCurrentViewerQuery(() =>
        HttpResponse.json(
          {
            errors: [{ message: "Request failed" }],
          },
          { status: 400 },
        ),
      ),
    );

    const { asFragment } = await renderPage("/reset-cross-signing/");
    expect(asFragment()).toMatchSnapshot();
  });
});
