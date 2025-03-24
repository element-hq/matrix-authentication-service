// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { useMutation, useSuspenseQuery } from "@tanstack/react-query";
import { queryOptions } from "@tanstack/react-query";
import { useNavigate, useSearch } from "@tanstack/react-router";
import { createFileRoute, notFound } from "@tanstack/react-router";
import IconErrorSolid from "@vector-im/compound-design-tokens/assets/web/icons/error-solid";
import IconLockSolid from "@vector-im/compound-design-tokens/assets/web/icons/lock-solid";
import { Alert, Button, Form } from "@vector-im/compound-web";
import type { FormEvent } from "react";
import { useTranslation } from "react-i18next";
import * as v from "valibot";
import { ButtonLink } from "../components/ButtonLink";
import Layout from "../components/Layout";
import LoadingSpinner from "../components/LoadingSpinner";
import PageHeading from "../components/PageHeading";
import PasswordCreationDoubleInput from "../components/PasswordCreationDoubleInput";
import { type FragmentType, useFragment } from "../gql";
import { graphql } from "../gql";
import { graphqlRequest } from "../graphql";
import { translateSetPasswordError } from "../i18n/password_changes";

const RECOVER_PASSWORD_MUTATION = graphql(/* GraphQL */ `
  mutation RecoverPassword($ticket: String!, $newPassword: String!) {
    setPasswordByRecovery(
      input: { ticket: $ticket, newPassword: $newPassword }
    ) {
      status
    }
  }
`);

const RESEND_EMAIL_MUTATION = graphql(/* GraphQL */ `
  mutation ResendRecoveryEmail($ticket: String!) {
    resendRecoveryEmail(input: { ticket: $ticket }) {
      status
      progressUrl
    }
  }
`);

const FRAGMENT = graphql(/* GraphQL */ `
  fragment RecoverPassword_userRecoveryTicket on UserRecoveryTicket {
    username
    email
  }
`);

const SITE_CONFIG_FRAGMENT = graphql(/* GraphQL */ `
  fragment RecoverPassword_siteConfig on SiteConfig {
    ...PasswordCreationDoubleInput_siteConfig
  }
`);

const QUERY = graphql(/* GraphQL */ `
  query PasswordRecovery($ticket: String!) {
    siteConfig {
      ...RecoverPassword_siteConfig
    }

    userRecoveryTicket(ticket: $ticket) {
      status
      ...RecoverPassword_userRecoveryTicket
    }
  }
`);

const query = (ticket: string) =>
  queryOptions({
    queryKey: ["passwordRecovery", ticket],
    queryFn: ({ signal }) =>
      graphqlRequest({ query: QUERY, signal, variables: { ticket } }),
  });

const schema = v.object({
  ticket: v.string(),
});

export const Route = createFileRoute("/password/recovery/")({
  validateSearch: schema,

  loaderDeps: ({ search: { ticket } }) => ({ ticket }),

  async loader({ context, deps: { ticket } }): Promise<void> {
    const { userRecoveryTicket } = await context.queryClient.ensureQueryData(
      query(ticket),
    );

    if (!userRecoveryTicket) {
      throw notFound();
    }
  },

  component: RecoverPassword,
});

const EmailConsumed: React.FC = () => {
  const { t } = useTranslation();
  return (
    <Layout>
      <PageHeading
        Icon={IconErrorSolid}
        title={t("frontend.password_reset.consumed.title")}
        subtitle={t("frontend.password_reset.consumed.subtitle")}
        invalid
      />

      <ButtonLink kind="secondary" to="/" reloadDocument>
        {t("action.start_over")}
      </ButtonLink>
    </Layout>
  );
};

const EmailExpired: React.FC<{
  userRecoveryTicket: FragmentType<typeof FRAGMENT>;
  ticket: string;
}> = (props) => {
  const { t } = useTranslation();
  const userRecoveryTicket = useFragment(FRAGMENT, props.userRecoveryTicket);

  const mutation = useMutation({
    mutationFn: async ({ ticket }: { ticket: string }) => {
      const response = await graphqlRequest({
        query: RESEND_EMAIL_MUTATION,
        variables: {
          ticket,
        },
      });

      if (response.resendRecoveryEmail.status === "SENT") {
        if (!response.resendRecoveryEmail.progressUrl) {
          throw new Error("Unexpected response, missing progress URL");
        }

        // Redirect to the URL which confirms that the email was sent
        window.location.href = response.resendRecoveryEmail.progressUrl;

        // We await an infinite promise here, so that the mutation
        // doesn't resolve
        await new Promise(() => undefined);
      }

      return response.resendRecoveryEmail;
    },
  });

  const onClick = (event: React.MouseEvent<HTMLButtonElement>): void => {
    event.preventDefault();
    mutation.mutate({ ticket: props.ticket });
  };

  return (
    <Layout>
      <PageHeading
        Icon={IconErrorSolid}
        title={t("frontend.password_reset.expired.title")}
        subtitle={t("frontend.password_reset.expired.subtitle", {
          email: userRecoveryTicket.email,
        })}
        invalid
      />

      {mutation.data?.status === "RATE_LIMITED" && (
        <Alert
          type="critical"
          title={t("frontend.errors.rate_limit_exceeded")}
        />
      )}

      <Button kind="primary" disabled={mutation.isPending} onClick={onClick}>
        {!!mutation.isPending && <LoadingSpinner inline />}
        {t("frontend.password_reset.expired.resend_email")}
      </Button>

      <ButtonLink kind="secondary" to="/" reloadDocument>
        {t("action.start_over")}
      </ButtonLink>
    </Layout>
  );
};

const EmailRecovery: React.FC<{
  siteConfig: FragmentType<typeof SITE_CONFIG_FRAGMENT>;
  userRecoveryTicket: FragmentType<typeof FRAGMENT>;
  ticket: string;
}> = (props) => {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const siteConfig = useFragment(SITE_CONFIG_FRAGMENT, props.siteConfig);
  const userRecoveryTicket = useFragment(FRAGMENT, props.userRecoveryTicket);

  const mutation = useMutation({
    mutationFn: async ({
      ticket,
      form,
    }: {
      ticket: string;
      form: FormData;
    }) => {
      const newPassword = form.get("new_password") as string;
      const newPasswordAgain = form.get("new_password_again") as string;

      if (newPassword !== newPasswordAgain) {
        throw new Error(
          "passwords mismatch; this should be checked by the form",
        );
      }

      const response = await graphqlRequest({
        query: RECOVER_PASSWORD_MUTATION,
        variables: {
          ticket,
          newPassword,
        },
      });

      if (response.setPasswordByRecovery.status === "ALLOWED") {
        // Redirect to the application root using a full page load
        // The MAS backend will then redirect to the login page
        // Unfortunately this won't work in dev mode (`npm run dev`)
        // as the backend isn't involved there.
        await navigate({ to: "/", reloadDocument: true });
      }

      return response.setPasswordByRecovery;
    },
  });

  const onSubmit = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault();

    const form = new FormData(event.currentTarget);
    mutation.mutate({ ticket: props.ticket, form });
  };

  const unhandleableError = mutation.error !== null;

  const errorMsg: string | undefined = translateSetPasswordError(
    t,
    mutation.data?.status,
  );

  return (
    <Layout>
      <div className="flex flex-col gap-10">
        <PageHeading
          Icon={IconLockSolid}
          title={t("frontend.password_reset.title")}
          subtitle={t("frontend.password_reset.subtitle")}
        />

        <Form.Root onSubmit={onSubmit} method="POST">
          {/*
            In normal operation, the submit event should be `preventDefault()`ed.
            method = POST just prevents sending passwords in the query string,
            which could be logged, if for some reason the event handler fails.
          */}
          {unhandleableError && (
            <Alert
              type="critical"
              title={t("frontend.password_change.failure.title")}
            >
              {t("frontend.password_change.failure.description.unspecified")}
            </Alert>
          )}

          {errorMsg !== undefined && (
            <Alert
              type="critical"
              title={t("frontend.password_change.failure.title")}
            >
              {errorMsg}
            </Alert>
          )}

          <input
            type="hidden"
            name="username"
            autoComplete="username"
            value={userRecoveryTicket.username}
          />

          <PasswordCreationDoubleInput
            siteConfig={siteConfig}
            forceShowNewPasswordInvalid={
              mutation.data?.status === "INVALID_NEW_PASSWORD" || false
            }
          />

          <Form.Submit kind="primary" disabled={mutation.isPending}>
            {!!mutation.isPending && <LoadingSpinner inline />}
            {t("action.save_and_continue")}
          </Form.Submit>
        </Form.Root>
      </div>
    </Layout>
  );
};

function RecoverPassword(): React.ReactNode {
  const { ticket } = useSearch({
    from: "/password/recovery/",
  });
  const {
    data: { siteConfig, userRecoveryTicket },
  } = useSuspenseQuery(query(ticket));

  if (!userRecoveryTicket) {
    throw notFound();
  }

  switch (userRecoveryTicket.status) {
    case "EXPIRED":
      return (
        <EmailExpired ticket={ticket} userRecoveryTicket={userRecoveryTicket} />
      );
    case "CONSUMED":
      return <EmailConsumed />;
    case "VALID":
      return (
        <EmailRecovery
          ticket={ticket}
          siteConfig={siteConfig}
          userRecoveryTicket={userRecoveryTicket}
        />
      );
    default: {
      const exhaustiveCheck: never = userRecoveryTicket.status;
      throw new Error(`Unhandled case: ${exhaustiveCheck}`);
    }
  }
}
