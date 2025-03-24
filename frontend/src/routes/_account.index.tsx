// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { queryOptions, useSuspenseQuery } from "@tanstack/react-query";
import {
  createFileRoute,
  notFound,
  redirect,
  useNavigate,
} from "@tanstack/react-router";
import IconSignOut from "@vector-im/compound-design-tokens/assets/web/icons/sign-out";
import { Button, Text } from "@vector-im/compound-web";
import { useTranslation } from "react-i18next";
import * as v from "valibot";
import AccountDeleteButton from "../components/AccountDeleteButton";
import AccountManagementPasswordPreview from "../components/AccountManagementPasswordPreview";
import { ButtonLink } from "../components/ButtonLink";
import * as Collapsible from "../components/Collapsible";
import * as Dialog from "../components/Dialog";
import LoadingSpinner from "../components/LoadingSpinner";
import Separator from "../components/Separator";
import { useEndBrowserSession } from "../components/Session/EndBrowserSessionButton";
import AddEmailForm from "../components/UserProfile/AddEmailForm";
import UserEmailList, {
  query as userEmailListQuery,
} from "../components/UserProfile/UserEmailList";
import { graphql } from "../gql";
import { graphqlRequest } from "../graphql";

const QUERY = graphql(/* GraphQL */ `
  query UserProfile {
    viewerSession {
      __typename
      ... on BrowserSession {
        id
        user {
          ...AddEmailForm_user
          ...UserEmailList_user
          ...AccountDeleteButton_user
          hasPassword
          emails(first: 0) {
            totalCount
          }
        }
      }
    }

    siteConfig {
      emailChangeAllowed
      passwordLoginEnabled
      accountDeactivationAllowed
      ...AddEmailForm_siteConfig
      ...UserEmailList_siteConfig
      ...PasswordChange_siteConfig
      ...AccountDeleteButton_siteConfig
    }
  }
`);

const query = queryOptions({
  queryKey: ["userProfile"],
  queryFn: ({ signal }) => graphqlRequest({ query: QUERY, signal }),
});

const actionSchema = v.variant("action", [
  v.object({
    action: v.picklist(["profile", "org.matrix.profile"]),
  }),
  v.object({
    action: v.picklist(["sessions_list", "org.matrix.sessions_list"]),
  }),
  v.object({
    action: v.picklist(["session_view", "org.matrix.session_view"]),
    device_id: v.optional(v.string()),
  }),
  v.object({
    action: v.picklist(["session_end", "org.matrix.session_end"]),
    device_id: v.optional(v.string()),
  }),
  v.object({
    action: v.literal("org.matrix.cross_signing_reset"),
  }),
  v.partial(
    v.looseObject({
      action: v.never(),
    }),
  ),
]);

export const Route = createFileRoute("/_account/")({
  validateSearch: actionSchema,

  beforeLoad({ search }) {
    switch (search.action) {
      case "profile":
      case "org.matrix.profile":
        throw redirect({ to: "/", search: {} });

      case "sessions_list":
      case "org.matrix.sessions_list":
        throw redirect({ to: "/sessions" });

      case "session_view":
      case "org.matrix.session_view":
        if (search.device_id)
          throw redirect({
            to: "/devices/$",
            params: { _splat: search.device_id },
          });
        throw redirect({ to: "/sessions" });

      case "session_end":
      case "org.matrix.session_end":
        if (search.device_id)
          throw redirect({
            to: "/devices/$",
            params: { _splat: search.device_id },
          });
        throw redirect({ to: "/sessions" });

      case "org.matrix.cross_signing_reset":
        throw redirect({
          to: "/reset-cross-signing",
          search: { deepLink: true },
        });
    }
  },

  loader: ({ context }) =>
    Promise.all([
      context.queryClient.ensureQueryData(userEmailListQuery()),
      context.queryClient.ensureQueryData(query),
    ]),

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

        <SignOutButton id={viewerSession.id} />

        {siteConfig.accountDeactivationAllowed && (
          <>
            <Separator />
            <AccountDeleteButton
              user={viewerSession.user}
              siteConfig={siteConfig}
            />
          </>
        )}

        <Separator />
      </div>
    </>
  );
}
