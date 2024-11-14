// Copyright 2024 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

// @vitest-environment happy-dom

import { act, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import { UNVERIFIED_EMAILS_FRAGMENT } from "../../../src/components/UnverifiedEmailAlert/UnverifiedEmailAlert";
import {
  CONFIG_FRAGMENT as USER_GREETING_CONFIG_FRAGMENT,
  FRAGMENT as USER_GREETING_FRAGMENT,
} from "../../../src/components/UserGreeting/UserGreeting";
import { makeFragmentData } from "../../../src/gql";
import {
  mockCurrentUserGreetingQuery,
  mockSetDisplayNameMutation,
  mockUserEmailListQuery,
  mockUserProfileQuery,
} from "../../../src/gql/graphql";
import { renderPage, server } from "../render";

const handlers = [
  mockCurrentUserGreetingQuery(() =>
    HttpResponse.json({
      data: {
        viewerSession: {
          __typename: "BrowserSession",

          id: "session-id",
          user: Object.assign(
            makeFragmentData(
              {
                id: "user-id",
                matrix: {
                  mxid: "@user:example.com",
                  displayName: "User",
                },
              },
              USER_GREETING_FRAGMENT,
            ),

            makeFragmentData(
              {
                unverifiedEmails: {
                  totalCount: 0,
                },
              },
              UNVERIFIED_EMAILS_FRAGMENT,
            ),
          ),
        },

        siteConfig: makeFragmentData(
          {
            displayNameChangeAllowed: true,
          },
          USER_GREETING_CONFIG_FRAGMENT,
        ),
      },
    }),
  ),

  mockUserProfileQuery(() =>
    HttpResponse.json({
      data: {
        viewer: {
          __typename: "User",
          id: "user-id",
          primaryEmail: {
            id: "primary-email-id",
          },
        },

        siteConfig: {
          emailChangeAllowed: true,
          passwordLoginEnabled: true,
        },
      },
    }),
  ),

  mockUserEmailListQuery(() =>
    HttpResponse.json({
      data: {
        user: {
          id: "user-id",
          emails: {
            edges: [],
            totalCount: 0,
            pageInfo: {
              hasNextPage: false,
              hasPreviousPage: false,
              startCursor: null,
              endCursor: null,
            },
          },
        },
      },
    }),
  ),
];

describe("Account home page", () => {
  it("renders the page", async () => {
    server.use(...handlers);

    const { asFragment } = await renderPage("/");
    expect(asFragment()).toMatchSnapshot();
  });

  describe("display name edit box", () => {
    it("lets edit the display name", async () => {
      // TODO: a better way to wait on delays
      let advance: () => void;
      const wait = new Promise((resolve) => {
        advance = () => resolve(void 0);
      });

      server.use(
        mockSetDisplayNameMutation(async ({ variables: { displayName } }) => {
          await wait;
          // Double check that the display name posted is the one we expect
          if (displayName !== "New display name") {
            throw new Error("Invalid display name");
          }

          return HttpResponse.json({
            data: {
              setDisplayName: {
                __typename: "SetDisplayNamePayload",
                status: "SET",
              },
            },
          });
        }),
        ...handlers,
      );

      const user = userEvent.setup();
      await renderPage("/");

      // TODO: there is only one 'Edit' button, but we should have better labels
      const editButton = screen.getByLabelText("Edit");
      await user.click(editButton);

      const dialog = screen.getByRole("dialog", { name: "Edit profile" });
      expect(dialog).toBeInTheDocument();
      expect(dialog).toMatchSnapshot();

      const displayNameInput = screen.getByLabelText("Display name");
      const newDisplayName = "New display name";
      await user.clear(displayNameInput);
      await user.type(displayNameInput, newDisplayName);
      const saveButton = screen.getByRole("button", { name: "Save" });
      expect(saveButton).not.toHaveAttribute("aria-disabled", "true");
      await user.click(saveButton);
      expect(saveButton).toHaveAttribute("aria-disabled", "true");
      act(() => advance());
      waitFor(() => expect(dialog).not.toBeInTheDocument());
    });

    it("closes with escape", async () => {
      server.use(...handlers);

      const user = userEvent.setup();
      await renderPage("/");

      // TODO: there is only one 'Edit' button, but we should have better labels
      const editButton = screen.getByLabelText("Edit");
      await user.click(editButton);

      const dialog = screen.getByRole("dialog", { name: "Edit profile" });
      expect(dialog).toBeInTheDocument();

      await user.keyboard("{esc}");
      waitFor(() => expect(dialog).not.toBeInTheDocument());
    });

    it("closes with cancel", async () => {
      server.use(...handlers);

      const user = userEvent.setup();
      await renderPage("/");

      // TODO: there is only one 'Edit' button, but we should have better labels
      const editButton = screen.getByLabelText("Edit");
      await user.click(editButton);

      const dialog = screen.getByRole("dialog", { name: "Edit profile" });
      expect(dialog).toBeInTheDocument();

      const cancelButton = screen.getByRole("button", { name: "Cancel" });
      await user.click(cancelButton);
      waitFor(() => expect(dialog).not.toBeInTheDocument());
    });

    it("displays an error if the display name is invalid", async () => {
      server.use(
        mockSetDisplayNameMutation(() =>
          HttpResponse.json({
            data: {
              setDisplayName: {
                __typename: "SetDisplayNamePayload",
                status: "INVALID",
              },
            },
          }),
        ),
        ...handlers,
      );

      const user = userEvent.setup();
      await renderPage("/");

      // TODO: there is only one 'Edit' button, but we should have better labels
      const editButton = screen.getByLabelText("Edit");
      await user.click(editButton);

      const dialog = screen.getByRole("dialog", { name: "Edit profile" });
      expect(dialog).toBeInTheDocument();

      const displayNameInput = screen.getByRole("textbox", {
        name: "Display name",
      });
      await user.clear(displayNameInput);
      await user.type(displayNameInput, "Something");
      const saveButton = screen.getByRole("button", { name: "Save" });
      await user.click(saveButton);

      expect(displayNameInput).toBeInvalid();
      expect(dialog).toMatchSnapshot();
    });
  });
});
