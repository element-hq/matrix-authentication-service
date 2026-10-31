// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

// @vitest-environment happy-dom

import { act, waitFor } from "@testing-library/react";
import { HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import {
  mockCurrentUserGreetingQuery,
  mockUserProfileQuery,
} from "../../src/gql/graphql";
import { renderPage, server } from "./render";

describe("Document title", () => {
  it.each([
    ["/", "Your account – example.com"],
    ["/password/change/success", "Change your password – example.com"],
    ["/reset-cross-signing", "Reset identity – example.com"],
    // Inherits the title of the parent route
    ["/reset-cross-signing/success", "Reset identity – example.com"],
    ["/this-route-does-not-exist", "Page not found – example.com"],
  ])("sets the title for %s", async (route, title) => {
    await renderPage(route);
    await waitFor(() => expect(document.title).toBe(title));
  });

  it("uses the error title when the route fails to load", async () => {
    server.use(
      mockCurrentUserGreetingQuery(() =>
        HttpResponse.json({ errors: [{ message: "Boom" }] }),
      ),
    );

    await renderPage("/");
    await waitFor(() =>
      expect(document.title).toBe("Something went wrong – example.com"),
    );
  });

  it("uses the error title when a child of a titled route fails", async () => {
    server.use(
      mockUserProfileQuery(() =>
        HttpResponse.json({ errors: [{ message: "Boom" }] }),
      ),
    );

    await renderPage("/");
    await waitFor(() =>
      expect(document.title).toBe("Something went wrong – example.com"),
    );
  });

  it("updates the title on navigation", async () => {
    const { router } = await renderPage("/");
    await waitFor(() =>
      expect(document.title).toBe("Your account – example.com"),
    );

    await act(() => router.navigate({ to: "/reset-cross-signing" }));
    await waitFor(() =>
      expect(document.title).toBe("Reset identity – example.com"),
    );
    expect(document.head.querySelectorAll("title")).toHaveLength(1);

    await act(() => router.history.back());
    await waitFor(() =>
      expect(document.title).toBe("Your account – example.com"),
    );
    expect(document.head.querySelectorAll("title")).toHaveLength(1);
  });
});
