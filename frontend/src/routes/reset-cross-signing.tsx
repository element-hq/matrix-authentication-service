// Copyright 2024 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import {
  type ErrorComponentProps,
  Outlet,
  createFileRoute,
} from "@tanstack/react-router";
import { zodSearchValidator } from "@tanstack/router-zod-adapter";
import IconError from "@vector-im/compound-design-tokens/assets/web/icons/error";
import { Button, Text } from "@vector-im/compound-web";
import * as z from "zod";

import { useTranslation } from "react-i18next";
import BlockList from "../components/BlockList";
import Layout from "../components/Layout";
import PageHeading from "../components/PageHeading";

const searchSchema = z.object({
  deepLink: z.boolean().optional(),
});

export const Route = createFileRoute("/reset-cross-signing")({
  component: () => (
    <Layout>
      <BlockList>
        <Outlet />
      </BlockList>
    </Layout>
  ),
  errorComponent: ResetCrossSigningError,
  validateSearch: zodSearchValidator(searchSchema),
});

function ResetCrossSigningError({
  reset,
}: ErrorComponentProps): React.ReactElement {
  const { t } = useTranslation();
  return (
    <>
      <PageHeading
        Icon={IconError}
        title={t("frontend.reset_cross_signing.failure.heading")}
        invalid
      />

      <Text className="text-center text-secondary" size="md">
        {t("frontend.reset_cross_signing.failure.description")}
      </Text>

      <Button kind="tertiary" size="lg" onClick={() => reset()}>
        {t("action.back")}
      </Button>
    </>
  );
}
