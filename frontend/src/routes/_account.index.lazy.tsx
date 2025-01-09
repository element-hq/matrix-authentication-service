// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { useSuspenseQuery } from "@tanstack/react-query";
import {
  createLazyFileRoute,
  notFound,
  useNavigate,
} from "@tanstack/react-router";
import { Separator, Text } from "@vector-im/compound-web";
import { useTranslation } from "react-i18next";

import AccountManagementPasswordPreview from "../components/AccountManagementPasswordPreview";
import { ButtonLink } from "../components/ButtonLink";
import * as Collapsible from "../components/Collapsible";
import AddEmailForm from "../components/UserProfile/AddEmailForm";
import UserEmailList from "../components/UserProfile/UserEmailList";

import { query } from "./_account.index";

export const Route = createLazyFileRoute("/_account/")({
  component: Index,
});

function Index(): React.ReactElement {
  const navigate = useNavigate();
  const { t } = useTranslation();
  const {
    data: { viewer, siteConfig },
  } = useSuspenseQuery(query);
  if (viewer?.__typename !== "User") throw notFound();

  // When adding an email, we want to go to the email verification form
  const onAdd = async (id: string): Promise<void> => {
    await navigate({ to: "/emails/$id/verify", params: { id } });
  };

  return (
    <div className="flex flex-col gap-4 mb-4">
      {/* Only display this section if the user can add email addresses to their
          account *or* if they have any existing email addresses */}
      {(siteConfig.emailChangeAllowed || viewer.emails.totalCount > 0) && (
        <>
          <Collapsible.Section
            defaultOpen
            title={t("frontend.account.contact_info")}
          >
            <UserEmailList siteConfig={siteConfig} />

            {siteConfig.emailChangeAllowed && (
              <AddEmailForm userId={viewer.id} onAdd={onAdd} />
            )}
          </Collapsible.Section>

          <Separator kind="section" />
        </>
      )}

      {siteConfig.passwordLoginEnabled && (
        <>
          <Collapsible.Section
            defaultOpen
            title={t("frontend.account.account_password")}
          >
            <AccountManagementPasswordPreview siteConfig={siteConfig} />
          </Collapsible.Section>

          <Separator kind="section" />
        </>
      )}

      <Collapsible.Section title={t("common.e2ee")}>
        <Text className="text-secondary" size="md">
          {t("frontend.reset_cross_signing.description")}
        </Text>
        <ButtonLink to="/reset-cross-signing" kind="secondary" destructive>
          {t("frontend.reset_cross_signing.start_reset")}
        </ButtonLink>
      </Collapsible.Section>
    </div>
  );
}
