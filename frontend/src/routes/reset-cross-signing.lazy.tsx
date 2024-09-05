// Copyright 2024 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { createLazyFileRoute, notFound } from "@tanstack/react-router";
import IconCheck from "@vector-im/compound-design-tokens/assets/web/icons/check";
import IconCheckCircleSolid from "@vector-im/compound-design-tokens/assets/web/icons/check-circle-solid";
import IconClose from "@vector-im/compound-design-tokens/assets/web/icons/close";
import IconError from "@vector-im/compound-design-tokens/assets/web/icons/error";
import IconKeyOffSolid from "@vector-im/compound-design-tokens/assets/web/icons/key-off-solid";
import { Button, Text } from "@vector-im/compound-web";
import {
  ForwardRefExoticComponent,
  RefAttributes,
  SVGProps,
  useState,
  MouseEvent,
} from "react";
import { useTranslation } from "react-i18next";
import { useMutation, useQuery } from "urql";

import BlockList from "../components/BlockList";
import { ButtonLink } from "../components/ButtonLink";
import Layout from "../components/Layout";
import LoadingSpinner from "../components/LoadingSpinner";
import PageHeading from "../components/PageHeading";
import {
  VisualList,
  VisualListItem,
} from "../components/VisualList/VisualList";
import { graphql } from "../gql";

import { CURRENT_VIEWER_QUERY } from "./reset-cross-signing";

declare global {
  interface Window {
    // Synapse may fling the user here via UIA fallback,
    // this is part of the API to signal completion to the calling client
    // https://spec.matrix.org/v1.11/client-server-api/#fallback
    onAuthDone?(): void;
  }
}

const ALLOW_CROSS_SIGING_RESET_MUTATION = graphql(/* GraphQL */ `
  mutation AllowCrossSigningReset($userId: ID!) {
    allowUserCrossSigningReset(input: { userId: $userId }) {
      user {
        id
      }
    }
  }
`);

export const Route = createLazyFileRoute("/reset-cross-signing")({
  component: ResetCrossSigning,
});

// This value comes from Synapse and we have no way to query it from here
// https://github.com/element-hq/synapse/blob/34b758644611721911a223814a7b35d8e14067e6/synapse/rest/admin/users.py#L1335
const CROSS_SIGNING_REPLACEMENT_PERIOD_MS = 10 * 60 * 1000; // 10 minutes

function ResetCrossSigning(): React.ReactNode {
  const { deepLink } = Route.useSearch();
  const { t } = useTranslation();
  const [viewer] = useQuery({ query: CURRENT_VIEWER_QUERY });
  if (viewer.error) throw viewer.error;
  if (viewer.data?.viewer.__typename !== "User") throw notFound();
  const userId = viewer.data.viewer.id;

  const [result, allowReset] = useMutation(ALLOW_CROSS_SIGING_RESET_MUTATION);
  const success = !!result.data && !result.error;
  const error = !success && result.error;

  const onClick = async (): Promise<void> => {
    await allowReset({ userId });
    setTimeout(() => {
      // Synapse may fling the user here via UIA fallback,
      // this is part of the API to signal completion to the calling client
      // https://spec.matrix.org/v1.11/client-server-api/#fallback
      if (window.onAuthDone) {
        window.onAuthDone();
      } else if (window.opener && window.opener.postMessage) {
        window.opener.postMessage("authDone", "*");
      }
    });
  };

  const [cancelled, setCancelled] = useState(false);

  let cancelButton;
  if (!deepLink) {
    cancelButton = (
      <ButtonLink to="/" kind="tertiary">
        {t("action.back")}
      </ButtonLink>
    );
  } else if (!success && !error && !cancelled) {
    // Only show the back button for a deep link if the user hasn't yet completed the interaction
    cancelButton = (
      <Button
        as="a"
        kind="tertiary"
        onClick={(ev: MouseEvent) => {
          ev.preventDefault();
          setCancelled(true);
        }}
      >
        {t("action.cancel")}
      </Button>
    );
  }

  let Icon: ForwardRefExoticComponent<
    Omit<SVGProps<SVGSVGElement>, "ref" | "children"> &
      RefAttributes<SVGSVGElement>
  >;
  let title: string;
  let body: JSX.Element;

  if (cancelled) {
    Icon = IconKeyOffSolid;
    title = t("frontend.reset_cross_signing.cancelled.heading");
    body = (
      <>
        <Text className="text-center text-secondary" size="lg">
          {t("frontend.reset_cross_signing.cancelled.description_1")}
        </Text>
        <Text className="text-center text-secondary" size="lg">
          {t("frontend.reset_cross_signing.cancelled.description_2")}
        </Text>
      </>
    );
  } else if (success) {
    Icon = IconCheckCircleSolid;
    title = t("frontend.reset_cross_signing.success.heading");
    body = (
      <Text className="text-center text-secondary" size="lg">
        {t("frontend.reset_cross_signing.success.description", {
          minutes: CROSS_SIGNING_REPLACEMENT_PERIOD_MS / (60 * 1000),
        })}
      </Text>
    );
  } else if (error) {
    Icon = IconError;
    title = t("frontend.reset_cross_signing.failure.heading");
    body = (
      <Text className="text-center text-secondary" size="lg">
        {t("frontend.reset_cross_signing.failure.description")}
      </Text>
    );
  } else {
    Icon = IconError;
    title = t("frontend.reset_cross_signing.heading");
    body = (
      <>
        <Text className="text-center text-secondary" size="lg">
          {t("frontend.reset_cross_signing.description")}
        </Text>
        <VisualList>
          <VisualListItem
            Icon={IconCheck}
            iconColor="var(--cpd-color-icon-success-primary)"
            label={t("frontend.reset_cross_signing.effect_list.positive_1")}
          />
          <VisualListItem
            Icon={IconClose}
            iconColor="var(--cpd-color-icon-critical-primary)"
            label={t("frontend.reset_cross_signing.effect_list.negative_1")}
          />
          <VisualListItem
            Icon={IconClose}
            iconColor="var(--cpd-color-icon-critical-primary)"
            label={t("frontend.reset_cross_signing.effect_list.negative_2")}
          />
        </VisualList>
        <Text className="text-center" size="md" weight="semibold">
          {t("frontend.reset_cross_signing.warning")}
        </Text>
        <Button
          kind="primary"
          destructive
          disabled={result.fetching}
          onClick={onClick}
        >
          {!!result.fetching && <LoadingSpinner inline />}
          {t("frontend.reset_cross_signing.button")}
        </Button>
      </>
    );
  }

  return (
    <Layout>
      <BlockList>
        <PageHeading
          Icon={Icon}
          title={title}
          invalid={!success}
          success={success}
        />

        {body}
        {cancelButton}
      </BlockList>
    </Layout>
  );
}
