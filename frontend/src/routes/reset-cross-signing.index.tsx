// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import {
  queryOptions,
  useMutation,
  useSuspenseQuery,
} from "@tanstack/react-query";
import { notFound } from "@tanstack/react-router";
import IconCheck from "@vector-im/compound-design-tokens/assets/web/icons/check";
import IconErrorSolid from "@vector-im/compound-design-tokens/assets/web/icons/error-solid";
import IconInfo from "@vector-im/compound-design-tokens/assets/web/icons/info";
import {
  Button,
  Text,
  VisualList,
  VisualListItem,
} from "@vector-im/compound-web";
import { useTranslation } from "react-i18next";
import { ButtonLink } from "../components/ButtonLink";
import LoadingSpinner from "../components/LoadingSpinner";
import PageHeading from "../components/PageHeading";
import { graphql } from "../gql";
import { graphqlRequest } from "../graphql";

const CURRENT_VIEWER_QUERY = graphql(/* GraphQL */ `
  query CurrentViewer {
    viewer {
      __typename
      ... on Node {
        id
      }
    }
  }
`);

const currentViewerQuery = queryOptions({
  queryKey: ["currentViewer"],
  queryFn: ({ signal }) =>
    graphqlRequest({
      query: CURRENT_VIEWER_QUERY,
      signal,
    }),
});

export const Route = createFileRoute({
  loader: ({ context }) =>
    context.queryClient.ensureQueryData(currentViewerQuery),

  component: ResetCrossSigning,
});

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

function ResetCrossSigning(): React.ReactNode {
  const { deepLink } = Route.useSearch();
  const navigate = Route.useNavigate();
  const { t } = useTranslation();
  const {
    data: { viewer },
  } = useSuspenseQuery(currentViewerQuery);
  if (viewer.__typename !== "User") throw notFound();
  const userId = viewer.id;

  const mutation = useMutation({
    mutationFn: async (userId: string) =>
      graphqlRequest({
        query: ALLOW_CROSS_SIGING_RESET_MUTATION,
        variables: {
          userId,
        },
      }),

    onSuccess: () => {
      setTimeout(() => {
        // Synapse may fling the user here via UIA fallback,
        // this is part of the API to signal completion to the calling client
        // https://spec.matrix.org/v1.11/client-server-api/#fallback
        if (window.onAuthDone) {
          window.onAuthDone();
        } else if (window.opener?.postMessage) {
          window.opener.postMessage("authDone", "*");
        }
      });

      navigate({ to: "/reset-cross-signing/success", replace: true });
    },
  });

  const onClick = async (): Promise<void> => {
    mutation.mutate(userId);
  };

  return (
    <>
      <PageHeading
        Icon={IconErrorSolid}
        title={t("frontend.reset_cross_signing.heading")}
        invalid
      />

      <Text className="text-center text-secondary" size="md">
        {t("frontend.reset_cross_signing.description")}
      </Text>

      <VisualList>
        <VisualListItem Icon={IconCheck} success>
          {t("frontend.reset_cross_signing.effect_list.positive_1")}
        </VisualListItem>
        <VisualListItem Icon={IconInfo}>
          {t("frontend.reset_cross_signing.effect_list.neutral_1")}
        </VisualListItem>
        <VisualListItem Icon={IconInfo}>
          {t("frontend.reset_cross_signing.effect_list.neutral_2")}
        </VisualListItem>
      </VisualList>

      <Text className="text-center" size="md" weight="semibold">
        {t("frontend.reset_cross_signing.warning")}
      </Text>

      <Button
        kind="primary"
        destructive
        disabled={mutation.isPending}
        onClick={onClick}
      >
        {!!mutation.isPending && <LoadingSpinner inline />}
        {t("frontend.reset_cross_signing.finish_reset")}
      </Button>

      {deepLink ? (
        <ButtonLink to="/reset-cross-signing/cancelled" kind="tertiary" replace>
          {t("action.cancel")}
        </ButtonLink>
      ) : (
        <ButtonLink to="/" kind="tertiary">
          {t("action.back")}
        </ButtonLink>
      )}
    </>
  );
}
