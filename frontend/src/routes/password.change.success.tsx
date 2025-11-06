// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import IconCheckCircle from "@vector-im/compound-design-tokens/assets/web/icons/check-circle-solid";
import { useTranslation } from "react-i18next";
import { ButtonLink } from "../components/ButtonLink";
import Layout from "../components/Layout";
import PageHeading from "../components/PageHeading";

export const Route = createFileRoute({
  component: ChangePasswordSuccess,
});

function ChangePasswordSuccess(): React.ReactNode {
  const { t } = useTranslation();

  return (
    <Layout>
      <div className="flex flex-col gap-10">
        <PageHeading
          Icon={IconCheckCircle}
          title={t("frontend.password_change.success.title")}
          subtitle={t("frontend.password_change.success.description")}
          success
        />

        <ButtonLink to="/" kind="tertiary">
          {t("action.back")}
        </ButtonLink>
      </div>
    </Layout>
  );
}
