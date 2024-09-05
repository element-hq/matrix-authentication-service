// Copyright 2024 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { createLazyFileRoute } from "@tanstack/react-router";
import IconCheckCircle from "@vector-im/compound-design-tokens/assets/web/icons/check-circle-solid";
import { useTranslation } from "react-i18next";

import BlockList from "../components/BlockList";
import { ButtonLink } from "../components/ButtonLink";
import Layout from "../components/Layout";
import PageHeading from "../components/PageHeading";

export const Route = createLazyFileRoute("/password/change/success")({
  component: ChangePasswordSuccess,
});

function ChangePasswordSuccess(): React.ReactNode {
  const { t } = useTranslation();

  return (
    <Layout>
      <BlockList>
        <PageHeading
          Icon={IconCheckCircle}
          title={t("frontend.password_change.success.title")}
          subtitle={t("frontend.password_change.success.description")}
          success
        />

        <ButtonLink to="/" kind="tertiary">
          {t("action.back")}
        </ButtonLink>
      </BlockList>
    </Layout>
  );
}
