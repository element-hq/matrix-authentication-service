// Copyright 2024 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { createFileRoute, notFound, redirect } from "@tanstack/react-router";
import { Alert } from "@vector-im/compound-web";
import { useTranslation } from "react-i18next";

import { queryOptions } from "@tanstack/react-query";
import Layout from "../components/Layout";
import { Link } from "../components/Link";
import { graphql } from "../gql";
import { graphqlClient } from "../graphql";

const CURRENT_VIEWER_QUERY = graphql(/* GraphQL */ `
  query CurrentViewerQuery {
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
    graphqlClient.request({
      document: CURRENT_VIEWER_QUERY,
      signal,
    }),
});

const QUERY = graphql(/* GraphQL */ `
  query DeviceRedirectQuery($deviceId: String!, $userId: ID!) {
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
      graphqlClient.request({
        document: QUERY,
        variables: { deviceId, userId },
        signal,
      }),
  });

export const Route = createFileRoute("/devices/$")({
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
