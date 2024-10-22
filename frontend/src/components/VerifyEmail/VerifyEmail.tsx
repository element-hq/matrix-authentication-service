// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { useLinkProps, useNavigate } from "@tanstack/react-router";
import IconArrowLeft from "@vector-im/compound-design-tokens/assets/web/icons/arrow-left";
import IconSend from "@vector-im/compound-design-tokens/assets/web/icons/send-solid";
import { Alert, Button, Form, H1, Text } from "@vector-im/compound-web";
import { useRef } from "react";
import { Trans, useTranslation } from "react-i18next";
import { useMutation } from "urql";

import { FragmentType, graphql, useFragment } from "../../gql";

import styles from "./VerifyEmail.module.css";

const FRAGMENT = graphql(/* GraphQL */ `
  fragment UserEmail_verifyEmail on UserEmail {
    id
    email
  }
`);

const VERIFY_EMAIL_MUTATION = graphql(/* GraphQL */ `
  mutation VerifyEmail($id: ID!, $code: String!) {
    verifyEmail(input: { userEmailId: $id, code: $code }) {
      status

      user {
        id
        primaryEmail {
          id
        }
      }

      email {
        id
        ...UserEmail_email
      }
    }
  }
`);

const RESEND_VERIFICATION_EMAIL_MUTATION = graphql(/* GraphQL */ `
  mutation ResendVerificationEmail($id: ID!) {
    sendVerificationEmail(input: { userEmailId: $id }) {
      status

      user {
        id
        primaryEmail {
          id
        }
      }

      email {
        id
        ...UserEmail_email
      }
    }
  }
`);

const BackButton: React.FC = () => {
  const props = useLinkProps({ to: "/" });
  const { t } = useTranslation();

  return (
    <Button as="a" Icon={IconArrowLeft} kind="tertiary" {...props}>
      {t("action.back")}
    </Button>
  );
};

const VerifyEmail: React.FC<{
  email: FragmentType<typeof FRAGMENT>;
}> = ({ email }) => {
  const data = useFragment(FRAGMENT, email);
  const [verifyEmailResult, verifyEmail] = useMutation(VERIFY_EMAIL_MUTATION);
  const [resendVerificationEmailResult, resendVerificationEmail] = useMutation(
    RESEND_VERIFICATION_EMAIL_MUTATION,
  );
  const navigate = useNavigate();
  const fieldRef = useRef<HTMLInputElement>(null);
  const { t } = useTranslation();

  const onFormSubmit = (e: React.FormEvent<HTMLFormElement>): void => {
    e.preventDefault();
    const form = e.currentTarget;
    const formData = new FormData(form);
    const code = formData.get("code") as string;
    verifyEmail({ id: data.id, code }).then((result) => {
      // Clear the form
      form.reset();

      if (result.data?.verifyEmail.status === "VERIFIED") {
        navigate({ to: "/" });
      }
    });
  };

  const onResendClick = (): void => {
    resendVerificationEmail({ id: data.id }).then(() => {
      fieldRef.current?.focus();
    });
  };

  const emailSent =
    resendVerificationEmailResult.data?.sendVerificationEmail.status === "SENT";
  const invalidCode =
    verifyEmailResult.data?.verifyEmail.status === "INVALID_CODE";
  const { email: codeEmail } = data;

  return (
    <>
      <header className={styles.header}>
        <IconSend className={styles.icon} />
        <H1>{t("frontend.verify_email.heading")}</H1>
        <Text size="lg" className={styles.tagline}>
          <Trans
            i18nKey="frontend.verify_email.enter_code_prompt"
            values={{ email: codeEmail }}
            components={{ email: <span /> }}
          />
        </Text>
      </header>

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
        <Form.Field
          name="code"
          serverInvalid={invalidCode}
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

        <Form.Submit type="submit" disabled={verifyEmailResult.fetching}>
          {t("action.continue")}
        </Form.Submit>
        <Button
          type="button"
          kind="secondary"
          disabled={resendVerificationEmailResult.fetching}
          onClick={onResendClick}
        >
          {t("frontend.verify_email.resend_code")}
        </Button>
        <BackButton />
      </Form.Root>
    </>
  );
};

export default VerifyEmail;
