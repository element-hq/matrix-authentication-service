// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import { queryOptions, useSuspenseQuery } from "@tanstack/react-query";
import { notFound } from "@tanstack/react-router";
import { Alert } from "@vector-im/compound-web";
import { useTranslation } from "react-i18next";
import Layout from "../components/Layout";
import { Link } from "../components/Link";
import BrowserSessionDetail from "../components/SessionDetail/BrowserSessionDetail";
import CompatSessionDetail from "../components/SessionDetail/CompatSessionDetail";
import OAuth2SessionDetail from "../components/SessionDetail/OAuth2SessionDetail";
import { graphql } from "../gql";
import { graphqlRequest } from "../graphql";

const QUERY = graphql(/* GraphQL */ `
  query SessionDetail($id: ID!) {
    viewerSession {
      ... on Node {
        id
      }
    }

    node(id: $id) {
      __typename
      id
      ...CompatSession_detail
      ...OAuth2Session_detail
      ...BrowserSession_detail
    }
  }
`);

const query = (id: string) =>
  queryOptions({
    queryKey: ["sessionDetail", id],
    queryFn: ({ signal }) =>
      graphqlRequest({ query: QUERY, signal, variables: { id } }),
  });

export const Route = createFileRoute({
  loader: ({ context, params }) =>
    context.queryClient.ensureQueryData(query(params.id)),
  notFoundComponent: NotFound,
  component: SessionDetail,
});

function NotFound(): React.ReactElement {
  const { id } = Route.useParams();
  const { t } = useTranslation();

  return (
    <Layout>
      <Alert
        type="critical"
        title={t("frontend.session_detail.alert.title", { deviceId: id })}
      >
        {t("frontend.session_detail.alert.text")}
        <Link to="/sessions">{t("frontend.session_detail.alert.button")}</Link>
      </Alert>
    </Layout>
  );
}

function SessionDetail(): React.ReactElement {
  const { id } = Route.useParams();
  const {
    data: { node, viewerSession },
  } = useSuspenseQuery(query(id));
  if (!node) throw notFound();

  switch (node.__typename) {
    case "CompatSession":
      return (
        <Layout wide>
          <CompatSessionDetail session={node} />
        </Layout>
      );
    case "Oauth2Session":
      return (
        <Layout wide>
          <OAuth2SessionDetail session={node} />
        </Layout>
      );
    case "BrowserSession":
      return (
        <Layout wide>
          <BrowserSessionDetail
            session={node}
            isCurrent={node.id === viewerSession.id}
          />
        </Layout>
      );
    default:
      throw new Error("Unknown session type");
  }
}
