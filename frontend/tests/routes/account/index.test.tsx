// Copyright 2024, 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

// @vitest-environment happy-dom

import { act, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import { mockSetDisplayNameMutation } from "../../../src/gql/graphql";
import { renderPage, server } from "../render";

describe("Account home page", () => {
  it("renders the page", async () => {
    const { asFragment } = await renderPage("/");
    expect(asFragment()).toMatchSnapshot();
  });

  describe("display name edit box", () => {
    it("lets edit the display name", async () => {
      // TODO: a better way to wait on delays
      let advance: () => void = () => {};
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
