// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import { queryOptions, useSuspenseQuery } from "@tanstack/react-query";
import { notFound, redirect, useNavigate } from "@tanstack/react-router";
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
import {
  HCaptchaWidget,
  ReCaptchaWidget,
  TurnstileWidget,
} from "../components/Captcha";

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
    action: v.picklist(["org.matrix.profile", "profile"]),
  }),
  v.object({
    action: v.picklist([
      "org.matrix.devices_list",
      "sessions_list",
      "org.matrix.sessions_list",
    ]),
  }),
  v.object({
    action: v.picklist([
      "org.matrix.device_view",
      "session_view",
      "org.matrix.session_view",
    ]),
    device_id: v.optional(v.string()),
  }),
  v.object({
    action: v.picklist([
      "org.matrix.device_delete",
      "session_end",
      "org.matrix.session_end",
    ]),
    device_id: v.optional(v.string()),
  }),
  v.object({
    action: v.literal("org.matrix.cross_signing_reset"),
  }),
  v.object({
    action: v.literal("org.matrix.plan_management"),
  }),
  v.partial(
    v.looseObject({
      action: v.never(),
    }),
  ),
]);

export const Route = createFileRoute({
  validateSearch: actionSchema,

  beforeLoad({ search }) {
    switch (search.action) {
      case "org.matrix.profile":
      case "profile": // This is an unspecced alias that can be removed
        throw redirect({ to: "/", search: {} });

      case "org.matrix.devices_list":
      case "sessions_list": // This is an unspecced alias that can be removed
      case "org.matrix.sessions_list": // This is an unstable value from MSC4191 that can be removed once we have enough client adoption of the stable value
        throw redirect({ to: "/sessions" });

      case "org.matrix.device_view":
      case "session_view": // This is an unspecced alias that can be removed
      case "org.matrix.session_view": // This is an unstable value from MSC4191 that can be removed once we have enough client adoption of the stable value
        if (search.device_id)
          throw redirect({
            to: "/devices/$",
            params: { _splat: search.device_id },
          });
        throw redirect({ to: "/sessions" });

      case "org.matrix.device_delete":
      case "session_end": // This is the unstable MSC3824 alias for org.matrix.session_end
      case "org.matrix.session_end": // This is an unstable value from MSC4191 that can be removed once we have enough client adoption of the stable value
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
      case "org.matrix.plan_management": {
        // This is an unspecced experimental value
        // We don't bother checking if the plan management iframe is actually available and
        // instead rely on the plan tab handling it.
        throw redirect({ to: "/plan" });
      }
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

      <Dialog.Description asChild>
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
      </Dialog.Description>

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
            <UserEmailList user={viewerSession.user} siteConfig={siteConfig} />

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

      <form
        onSubmit={(e) => {
          e.preventDefault();
          const data = new FormData(e.currentTarget);
          const str = new URLSearchParams(data);
          console.log(str.toString());
        }}
      >
        <ReCaptchaWidget />
        <TurnstileWidget />
        <HCaptchaWidget />
        <input type="submit" />
      </form>

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
  );
}
