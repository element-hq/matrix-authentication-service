// Copyright 2024 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { type ErrorComponentProps, Outlet } from "@tanstack/react-router";
import IconErrorSolid from "@vector-im/compound-design-tokens/assets/web/icons/error-solid";
import { Button, Text } from "@vector-im/compound-web";
import * as v from "valibot";

import { useTranslation } from "react-i18next";
import Layout from "../components/Layout";
import PageHeading from "../components/PageHeading";

const searchSchema = v.object({
  deepLink: v.optional(v.boolean()),
});

export const Route = createFileRoute({
  validateSearch: searchSchema,
  component: () => (
    <Layout>
      <Outlet />
    </Layout>
  ),
  errorComponent: ResetCrossSigningError,
});

function ResetCrossSigningError({
  reset,
}: ErrorComponentProps): React.ReactElement {
  const { t } = useTranslation();
  return (
    <Layout>
      <PageHeading
        Icon={IconErrorSolid}
        title={t("frontend.reset_cross_signing.failure.heading")}
        invalid
      />

      <Text className="text-center text-secondary" size="md">
        {t("frontend.reset_cross_signing.failure.description")}
      </Text>

      <Button kind="tertiary" size="lg" onClick={() => reset()}>
        {t("action.back")}
      </Button>
    </Layout>
  );
}
