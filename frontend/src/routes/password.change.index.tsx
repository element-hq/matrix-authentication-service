// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import {
  queryOptions,
  useMutation,
  useSuspenseQuery,
} from "@tanstack/react-query";
import { notFound, useRouter } from "@tanstack/react-router";
import IconLockSolid from "@vector-im/compound-design-tokens/assets/web/icons/lock-solid";
import { Alert, Form } from "@vector-im/compound-web";
import { type FormEvent, useRef } from "react";
import { useTranslation } from "react-i18next";
import { ButtonLink } from "../components/ButtonLink";
import Layout from "../components/Layout";
import LoadingSpinner from "../components/LoadingSpinner";
import PageHeading from "../components/PageHeading";
import PasswordCreationDoubleInput from "../components/PasswordCreationDoubleInput";
import Separator from "../components/Separator";
import { graphql } from "../gql";
import { graphqlRequest } from "../graphql";
import { translateSetPasswordError } from "../i18n/password_changes";

const CHANGE_PASSWORD_MUTATION = graphql(/* GraphQL */ `
  mutation ChangePassword(
    $userId: ID!
    $oldPassword: String!
    $newPassword: String!
  ) {
    setPassword(
      input: {
        userId: $userId
        currentPassword: $oldPassword
        newPassword: $newPassword
      }
    ) {
      status
    }
  }
`);

const QUERY = graphql(/* GraphQL */ `
  query PasswordChange {
    viewer {
      __typename
      ... on Node {
        id
      }
    }

    siteConfig {
      ...PasswordCreationDoubleInput_siteConfig
    }
  }
`);

const query = queryOptions({
  queryKey: ["passwordChange"],
  queryFn: ({ signal }) => graphqlRequest({ query: QUERY, signal }),
});

export const Route = createFileRoute({
  loader: ({ context }) => context.queryClient.ensureQueryData(query),
  component: ChangePassword,
});

function ChangePassword(): React.ReactNode {
  const { t } = useTranslation();
  const {
    data: { viewer, siteConfig },
  } = useSuspenseQuery(query);
  const router = useRouter();
  if (viewer.__typename !== "User") throw notFound();
  const userId = viewer.id;

  const currentPasswordRef = useRef<HTMLInputElement>(null);

  const mutation = useMutation({
    async mutationFn(formData: FormData) {
      const oldPassword = formData.get("current_password") as string;
      const newPassword = formData.get("new_password") as string;
      const newPasswordAgain = formData.get("new_password_again") as string;

      if (newPassword !== newPasswordAgain) {
        throw new Error(
          "passwords mismatch; this should be checked by the form",
        );
      }

      const response = await graphqlRequest({
        query: CHANGE_PASSWORD_MUTATION,
        variables: {
          userId,
          oldPassword,
          newPassword,
        },
      });

      if (response.setPassword.status === "ALLOWED") {
        router.navigate({ to: "/password/change/success" });
      }

      return response.setPassword;
    },
  });

  const onSubmit = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault();
    const formData = new FormData(event.currentTarget);
    mutation.mutate(formData);
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
          title={t("frontend.password_change.title")}
          subtitle={t("frontend.password_change.subtitle")}
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

          <Form.Field
            name="current_password"
            serverInvalid={mutation.data?.status === "WRONG_PASSWORD"}
          >
            <Form.Label>
              {t("frontend.password_change.current_password_label")}
            </Form.Label>

            <Form.PasswordControl
              required
              autoComplete="current-password"
              ref={currentPasswordRef}
            />

            <Form.ErrorMessage match="valueMissing">
              {t("frontend.errors.field_required")}
            </Form.ErrorMessage>

            {mutation.data && mutation.data.status === "WRONG_PASSWORD" && (
              <Form.ErrorMessage>
                {t(
                  "frontend.password_change.failure.description.wrong_password",
                )}
              </Form.ErrorMessage>
            )}
          </Form.Field>

          <Separator />

          <PasswordCreationDoubleInput
            siteConfig={siteConfig}
            forceShowNewPasswordInvalid={
              (mutation.data &&
                mutation.data.status === "INVALID_NEW_PASSWORD") ||
              false
            }
          />

          <Form.Submit kind="primary" disabled={mutation.isPending}>
            {!!mutation.isPending && <LoadingSpinner inline />}
            {t("action.save")}
          </Form.Submit>

          <ButtonLink to="/" kind="tertiary">
            {t("action.cancel")}
          </ButtonLink>
        </Form.Root>
      </div>
    </Layout>
  );
}
