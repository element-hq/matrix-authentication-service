// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import { queryOptions } from "@tanstack/react-query";
import { notFound, redirect } from "@tanstack/react-router";
import { Alert } from "@vector-im/compound-web";
import { useTranslation } from "react-i18next";
import Layout from "../components/Layout";
import { Link } from "../components/Link";
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

const QUERY = graphql(/* GraphQL */ `
  query DeviceRedirect($deviceId: String!, $userId: ID!) {
    session(deviceId: $deviceId, userId: $userId) {
      __typename
      ... on Node {
        id
      }
    }
  }
`);

const query = (deviceId: string, userId: string) =>
  queryOptions({
    queryKey: ["deviceRedirect", deviceId, userId],
    queryFn: ({ signal }) =>
      graphqlRequest({
        query: QUERY,
        variables: { deviceId, userId },
        signal,
      }),
  });

export const Route = createFileRoute({
  async loader({ context, params }) {
    const data = await context.queryClient.fetchQuery(currentViewerQuery);
    if (data.viewer.__typename !== "User")
      throw notFound({
        global: true,
      });

    const result = await context.queryClient.fetchQuery(
      query(params._splat || "", data.viewer.id),
    );

    if (!result.session) throw notFound();

    throw redirect({
      to: "/sessions/$id",
      params: { id: result.session.id },
      replace: true,
    });
  },

  notFoundComponent: NotFound,
});

function NotFound(): React.ReactElement {
  const { t } = useTranslation();
  const { _splat: deviceId } = Route.useParams();
  return (
    <Layout>
      <Alert
        type="critical"
        title={t("frontend.session_detail.alert.title", { deviceId })}
      >
        {t("frontend.session_detail.alert.text")}
        <Link to="/sessions">{t("frontend.session_detail.alert.button")}</Link>
      </Alert>
    </Layout>
  );
}
