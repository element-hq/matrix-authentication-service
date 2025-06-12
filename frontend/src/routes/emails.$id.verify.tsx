// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import {
  queryOptions,
  useMutation,
  useQueryClient,
  useSuspenseQuery,
} from "@tanstack/react-query";
import { notFound, redirect, useNavigate } from "@tanstack/react-router";
import IconArrowLeft from "@vector-im/compound-design-tokens/assets/web/icons/arrow-left";
import IconSend from "@vector-im/compound-design-tokens/assets/web/icons/send-solid";
import { Alert, Button, Form } from "@vector-im/compound-web";
import { useRef } from "react";
import { Trans, useTranslation } from "react-i18next";
import { ButtonLink } from "../components/ButtonLink";
import Layout from "../components/Layout";
import LoadingSpinner from "../components/LoadingSpinner";
import PageHeading from "../components/PageHeading";
import { graphql } from "../gql";
import { graphqlRequest } from "../graphql";

const QUERY = graphql(/* GraphQL */ `
  query VerifyEmail($id: ID!) {
    userEmailAuthentication(id: $id) {
      id
      email
      completedAt
    }
  }
`);

const VERIFY_EMAIL_MUTATION = graphql(/* GraphQL */ `
  mutation DoVerifyEmail($id: ID!, $code: String!) {
    completeEmailAuthentication(input: { id: $id, code: $code }) {
      status
    }
  }
`);

const RESEND_EMAIL_AUTHENTICATION_CODE_MUTATION = graphql(/* GraphQL */ `
  mutation ResendEmailAuthenticationCode($id: ID!, $language: String!) {
    resendEmailAuthenticationCode(input: { id: $id, language: $language }) {
      status
    }
  }
`);

export const query = (id: string) =>
  queryOptions({
    queryKey: ["verifyEmail", id],
    queryFn: ({ signal }) =>
      graphqlRequest({ query: QUERY, signal, variables: { id } }),
  });

export const Route = createFileRoute({
  async loader({ context, params }): Promise<void> {
    const data = await context.queryClient.ensureQueryData(query(params.id));
    if (!data.userEmailAuthentication) {
      throw notFound();
    }

    if (data.userEmailAuthentication.completedAt) {
      throw redirect({ to: "/" });
    }
  },

  component: EmailVerify,
});

function EmailVerify(): React.ReactElement {
  const { id } = Route.useParams();
  const {
    data: { userEmailAuthentication },
  } = useSuspenseQuery(query(id));
  if (!userEmailAuthentication) throw notFound();

  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const verifyEmail = useMutation({
    mutationFn: ({ id, code }: { id: string; code: string }) =>
      graphqlRequest({ query: VERIFY_EMAIL_MUTATION, variables: { id, code } }),
    async onSuccess(data): Promise<void> {
      await queryClient.invalidateQueries({ queryKey: ["userEmails"] });
      await queryClient.invalidateQueries({ queryKey: ["verifyEmail", id] });

      if (data.completeEmailAuthentication.status === "COMPLETED") {
        await navigate({ to: "/" });
      } else if (data.completeEmailAuthentication.status === "IN_USE") {
        await navigate({ to: "/emails/$id/in-use", params: { id } });
      }
    },
  });

  const resendEmailAuthenticationCode = useMutation({
    mutationFn: ({ id, language }: { id: string; language: string }) =>
      graphqlRequest({
        query: RESEND_EMAIL_AUTHENTICATION_CODE_MUTATION,
        variables: { id, language },
      }),
    onSuccess() {
      fieldRef.current?.focus();
    },
  });

  const fieldRef = useRef<HTMLInputElement>(null);
  const { t, i18n } = useTranslation();

  const onFormSubmit = (e: React.FormEvent<HTMLFormElement>): void => {
    e.preventDefault();
    const form = e.currentTarget;
    const formData = new FormData(form);
    const code = formData.get("code") as string;
    verifyEmail
      .mutateAsync({ id: userEmailAuthentication.id, code })
      .finally(() => form.reset());
  };

  const onResendClick = (): void => {
    resendEmailAuthenticationCode.mutate({
      id: userEmailAuthentication.id,
      language: i18n.languages[0],
    });
  };

  const emailSent =
    resendEmailAuthenticationCode.data?.resendEmailAuthenticationCode.status ===
    "RESENT";
  const invalidCode =
    verifyEmail.data?.completeEmailAuthentication.status === "INVALID_CODE";
  const codeExpired =
    verifyEmail.data?.completeEmailAuthentication.status === "CODE_EXPIRED";
  const rateLimited =
    verifyEmail.data?.completeEmailAuthentication.status === "RATE_LIMITED";

  return (
    <Layout>
      <PageHeading
        Icon={IconSend}
        title={t("frontend.verify_email.heading")}
        subtitle={
          <Trans
            i18nKey="frontend.verify_email.enter_code_prompt"
            values={{ email: userEmailAuthentication.email }}
            components={{ email: <span className="text-primary" /> }}
          />
        }
      />

      <Form.Root onSubmit={onFormSubmit}>
        {emailSent && (
          <Alert
            type="success"
            title={t("frontend.verify_email.email_sent_alert.title")}
          >
            {t("frontend.verify_email.email_sent_alert.description")}
          </Alert>
        )}

        {invalidCode && (
          <Alert
            type="critical"
            title={t("frontend.verify_email.invalid_code_alert.title")}
          >
            {t("frontend.verify_email.invalid_code_alert.description")}
          </Alert>
        )}

        {codeExpired && (
          <Alert
            type="critical"
            title={t("frontend.verify_email.code_expired_alert.title")}
          >
            {t("frontend.verify_email.code_expired_alert.description")}
          </Alert>
        )}

        {rateLimited && (
          <Alert
            type="critical"
            title={t("frontend.errors.rate_limit_exceeded")}
          />
        )}

        <Form.Field
          name="code"
          serverInvalid={invalidCode || rateLimited}
          className="self-center mb-4"
        >
          <Form.Label>{t("frontend.verify_email.code_field_label")}</Form.Label>
          <Form.MFAControl ref={fieldRef} />

          {invalidCode && (
            <Form.ErrorMessage>
              {t("frontend.verify_email.code_field_error")}
            </Form.ErrorMessage>
          )}

          <Form.ErrorMessage match="patternMismatch">
            {t("frontend.verify_email.code_field_wrong_shape")}
          </Form.ErrorMessage>
        </Form.Field>

        <Form.Submit type="submit" disabled={verifyEmail.isPending}>
          {verifyEmail.isPending && <LoadingSpinner inline />}
          {t("action.continue")}
        </Form.Submit>

        <Button
          type="button"
          kind="secondary"
          disabled={resendEmailAuthenticationCode.isPending}
          onClick={onResendClick}
        >
          {resendEmailAuthenticationCode.isPending && <LoadingSpinner inline />}
          {t("frontend.verify_email.resend_code")}
        </Button>

        <ButtonLink Icon={IconArrowLeft} kind="tertiary" to="/">
          {t("action.back")}
        </ButtonLink>
      </Form.Root>
    </Layout>
  );
}
