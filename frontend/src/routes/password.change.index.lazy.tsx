// Copyright 2024 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import {
  createLazyFileRoute,
  notFound,
  useRouter,
} from "@tanstack/react-router";
import IconLockSolid from "@vector-im/compound-design-tokens/assets/web/icons/lock-solid";
import { Alert, Form, Separator } from "@vector-im/compound-web";
import { type FormEvent, useRef } from "react";
import { useTranslation } from "react-i18next";
import { useMutation, useQuery } from "urql";

import BlockList from "../components/BlockList";
import { ButtonLink } from "../components/ButtonLink";
import Layout from "../components/Layout";
import LoadingSpinner from "../components/LoadingSpinner";
import PageHeading from "../components/PageHeading";
import PasswordCreationDoubleInput from "../components/PasswordCreationDoubleInput";
import { graphql } from "../gql";
import { SetPasswordStatus } from "../gql/graphql";
import { translateSetPasswordError } from "../i18n/password_changes";

import { QUERY } from "./password.change.index";

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

export const Route = createLazyFileRoute("/password/change/")({
  component: ChangePassword,
});

function ChangePassword(): React.ReactNode {
  const { t } = useTranslation();
  const [queryResult] = useQuery({ query: QUERY });
  const router = useRouter();
  if (queryResult.error) throw queryResult.error;
  if (queryResult.data?.viewer.__typename !== "User") throw notFound();
  const userId = queryResult.data.viewer.id;
  const siteConfig = queryResult.data?.siteConfig;
  if (!siteConfig) throw Error(); // This should never happen

  const currentPasswordRef = useRef<HTMLInputElement>(null);

  const [result, changePassword] = useMutation(CHANGE_PASSWORD_MUTATION);

  const onSubmit = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault();

    const formData = new FormData(event.currentTarget);

    const oldPassword = formData.get("current_password") as string;
    const newPassword = formData.get("new_password") as string;
    const newPasswordAgain = formData.get("new_password_again") as string;

    if (newPassword !== newPasswordAgain) {
      throw new Error("passwords mismatch; this should be checked by the form");
    }

    const response = await changePassword({ userId, oldPassword, newPassword });

    if (response.data?.setPassword.status === "ALLOWED") {
      router.navigate({ to: "/password/change/success" });
    }
  };

  const unhandleableError = result.error !== undefined;

  const errorMsg: string | undefined = translateSetPasswordError(
    t,
    result.data?.setPassword.status,
  );

  return (
    <Layout>
      <BlockList>
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
            serverInvalid={result.data?.setPassword.status === "WRONG_PASSWORD"}
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

            {result.data &&
              result.data.setPassword.status === "WRONG_PASSWORD" && (
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
              (result.data &&
                result.data.setPassword.status === "INVALID_NEW_PASSWORD") ||
              false
            }
          />

          <Form.Submit kind="primary" disabled={result.fetching}>
            {!!result.fetching && <LoadingSpinner inline />}
            {t("action.save")}
          </Form.Submit>

          <ButtonLink to="/" kind="tertiary">
            {t("action.cancel")}
          </ButtonLink>
        </Form.Root>
      </BlockList>
    </Layout>
  );
}
