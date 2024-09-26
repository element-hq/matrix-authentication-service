// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import IconSignOut from "@vector-im/compound-design-tokens/assets/web/icons/sign-out";
import { Button } from "@vector-im/compound-web";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { FragmentType, graphql, useFragment } from "../../gql";
import * as Dialog from "../Dialog";
import LoadingSpinner from "../LoadingSpinner/LoadingSpinner";

const FRAGMENT = graphql(/* GraphQL */ `
  fragment UnlinkUpstreamProvider_provider on UpstreamOAuth2Provider {
    id
    createdAt
    humanName
    upstreamOauth2LinksForUser {
      id
      provider {
        id
      }
    }
  }
`);

const UnlinkUpstreamButton: React.FC<
  React.PropsWithChildren<{
    upstreamProvider: FragmentType<typeof FRAGMENT>;
  }>
> = ({ children, upstreamProvider }) => {
  const [inProgress, setInProgress] = useState(false);
  const [open, setOpen] = useState(false);
  const { t } = useTranslation();
  const data = useFragment(FRAGMENT, upstreamProvider);

  const onConfirm = async (
    e: React.MouseEvent<HTMLButtonElement>,
  ): Promise<void> => {
    e.preventDefault();

    setInProgress(true);
    // TODO: Unlink
    setInProgress(false);
  };

  return (
    <Dialog.Dialog
      open={open}
      onOpenChange={setOpen}
      trigger={
        <Button kind="secondary" destructive size="sm" Icon={IconSignOut}>
          {t("frontend.unlink_upstream_button.text", {
            provider: data.humanName,
          })}
        </Button>
      }
    >
      <Dialog.Title>
        {t("frontend.unlink_upstream_button.confirmation_modal_title", {
          provider: data.humanName,
        })}
      </Dialog.Title>

      {children && <Dialog.Description>{children}</Dialog.Description>}

      <Button
        type="button"
        kind="primary"
        destructive
        onClick={onConfirm}
        disabled={inProgress}
        Icon={inProgress ? undefined : IconSignOut}
      >
        {inProgress && <LoadingSpinner inline />}
        {t("frontend.unlink_upstream_button.text", {
          provider: data.humanName,
        })}
      </Button>

      <Dialog.Close asChild>
        <Button kind="tertiary">{t("action.cancel")}</Button>
      </Dialog.Close>
    </Dialog.Dialog>
  );
};

export default UnlinkUpstreamButton;
