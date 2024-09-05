// Copyright 2024 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { createFileRoute, notFound, redirect } from "@tanstack/react-router";
import { Alert } from "@vector-im/compound-web";
import { useTranslation } from "react-i18next";

import Layout from "../components/Layout";
import { Link } from "../components/Link";
import { graphql } from "../gql";

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

export const Route = createFileRoute("/devices/$")({
  async loader({ context, params, abortController: { signal } }) {
    const viewer = await context.client.query(
      CURRENT_VIEWER_QUERY,
      {},
      {
        fetchOptions: { signal },
      },
    );
    if (viewer.error) throw viewer.error;
    if (viewer.data?.viewer.__typename !== "User") throw notFound();

    const result = await context.client.query(
      QUERY,
      {
        deviceId: params._splat || "",
        userId: viewer.data.viewer.id,
      },
      { fetchOptions: { signal } },
    );
    if (result.error) throw result.error;
    const session = result.data?.session;
    if (!session) throw notFound();

    throw redirect({
      to: "/sessions/$id",
      params: { id: session.id },
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
        <Link to="/sessions" search={{ first: 6 }}>
          {t("frontend.session_detail.alert.button")}
        </Link>
      </Alert>
    </Layout>
  );
}
