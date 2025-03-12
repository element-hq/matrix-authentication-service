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
import IconSignOut from "@vector-im/compound-design-tokens/assets/web/icons/sign-out";
import { Button, Text } from "@vector-im/compound-web";
import { useTranslation } from "react-i18next";
import AccountManagementPasswordPreview from "../components/AccountManagementPasswordPreview";
import { ButtonLink } from "../components/ButtonLink";
import * as Collapsible from "../components/Collapsible";
import * as Dialog from "../components/Dialog";
import LoadingSpinner from "../components/LoadingSpinner";
import Separator from "../components/Separator";
import { useEndBrowserSession } from "../components/Session/EndBrowserSessionButton";
import AddEmailForm from "../components/UserProfile/AddEmailForm";
import UserEmailList from "../components/UserProfile/UserEmailList";
import { query } from "./_account.index";

export const Route = createLazyFileRoute("/_account/")({
  component: Index,
});

const SignOutButton: React.FC<{ id: string }> = ({ id }) => {
  const { t } = useTranslation();
  const mutation = useEndBrowserSession(id, true);

  return (
    <Dialog.Dialog
      trigger={
        <Button kind="primary" destructive size="lg" Icon={IconSignOut}>
          {t("frontend.account.sign_out.button")}
        </Button>
      }
    >
      <Dialog.Title>{t("frontend.account.sign_out.dialog")}</Dialog.Title>

      <Button
        type="button"
        kind="primary"
        destructive
        onClick={() => mutation.mutate()}
        disabled={mutation.isPending}
        Icon={mutation.isPending ? undefined : IconSignOut}
      >
        {mutation.isPending && <LoadingSpinner inline />}
        {t("action.sign_out")}
      </Button>

      <Dialog.Close asChild>
        <Button kind="tertiary">{t("action.cancel")}</Button>
      </Dialog.Close>
    </Dialog.Dialog>
  );
};

function Index(): React.ReactElement {
  const navigate = useNavigate();
  const { t } = useTranslation();
  const {
    data: { viewerSession, siteConfig },
  } = useSuspenseQuery(query);
  if (viewerSession?.__typename !== "BrowserSession") throw notFound();

  // When adding an email, we want to go to the email verification form
  const onAdd = async (id: string): Promise<void> => {
    await navigate({ to: "/emails/$id/verify", params: { id } });
  };

  return (
    <>
      <div className="flex flex-col gap-6">
        {/* Only display this section if the user can add email addresses to their
          account *or* if they have any existing email addresses */}
        {(siteConfig.emailChangeAllowed ||
          viewerSession.user.emails.totalCount > 0) && (
          <>
            <Collapsible.Section
              defaultOpen
              title={t("frontend.account.contact_info")}
            >
              <UserEmailList
                user={viewerSession.user}
                siteConfig={siteConfig}
              />

              {siteConfig.emailChangeAllowed && (
                <AddEmailForm
                  user={viewerSession.user}
                  siteConfig={siteConfig}
                  onAdd={onAdd}
                />
              )}
            </Collapsible.Section>

            <Separator kind="section" />
          </>
        )}

        {siteConfig.passwordLoginEnabled && viewerSession.user.hasPassword && (
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

        <Separator kind="section" />
      </div>

      <SignOutButton id={viewerSession.id} />
    </>
  );
}
