// Copyright 2024 New Vector Ltd.
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
import { Alert, Heading, Separator, Text } from "@vector-im/compound-web";
import { Suspense } from "react";
import { useTranslation } from "react-i18next";

import AccountManagementPasswordPreview from "../components/AccountManagementPasswordPreview";
import BlockList from "../components/BlockList";
import { ButtonLink } from "../components/ButtonLink";
import * as Collapsible from "../components/Collapsible";
import LoadingSpinner from "../components/LoadingSpinner";
import UserEmail from "../components/UserEmail";
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
    <>
      <BlockList>
        {/* This wrapper is only needed for the anchor link */}
        <div className="flex flex-col gap-4" id="emails">
          {viewer.primaryEmail ? (
            <UserEmail
              email={viewer.primaryEmail}
              isPrimary
              siteConfig={siteConfig}
            />
          ) : (
            <Alert
              type="critical"
              title={t("frontend.user_email_list.no_primary_email_alert")}
            />
          )}

          <Suspense fallback={<LoadingSpinner mini className="self-center" />}>
            <UserEmailList siteConfig={siteConfig} user={viewer} />
          </Suspense>

          {siteConfig.emailChangeAllowed && (
            <AddEmailForm userId={viewer.id} onAdd={onAdd} />
          )}
        </div>

        {siteConfig.passwordLoginEnabled && (
          <>
            <Separator />

            <AccountManagementPasswordPreview siteConfig={siteConfig} />
          </>
        )}

        <Separator />

        <Collapsible.Root>
          <Collapsible.Trigger>
            <Heading size="sm" weight="semibold">
              {t("common.e2ee")}
            </Heading>
          </Collapsible.Trigger>
          <Collapsible.Content>
            <BlockList>
              <Text className="text-secondary" size="md">
                {t("frontend.reset_cross_signing.description")}
              </Text>
              <ButtonLink
                to="/reset-cross-signing"
                kind="secondary"
                destructive
              >
                {t("frontend.reset_cross_signing.start_reset")}
              </ButtonLink>
            </BlockList>
          </Collapsible.Content>
        </Collapsible.Root>
      </BlockList>
    </>
  );
}
