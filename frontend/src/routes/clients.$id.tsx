// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import { queryOptions, useSuspenseQuery } from "@tanstack/react-query";
import { notFound } from "@tanstack/react-router";
import OAuth2ClientDetail from "../components/Client/OAuth2ClientDetail";
import Layout from "../components/Layout";
import { graphql } from "../gql";
import { graphqlRequest } from "../graphql";

const QUERY = graphql(/* GraphQL */ `
  query OAuth2Client($id: ID!) {
    oauth2Client(id: $id) {
      ...OAuth2Client_detail
    }
  }
`);

const query = (id: string) =>
  queryOptions({
    queryKey: ["oauth2Client", id],
    queryFn: ({ signal }) =>
      graphqlRequest({ query: QUERY, variables: { id }, signal }),
  });

export const Route = createFileRoute({
  loader: ({ context, params }) =>
    context.queryClient.ensureQueryData(query(params.id)),
  component: ClientDetail,
});

function ClientDetail(): React.ReactElement {
  const { id } = Route.useParams();
  const {
    data: { oauth2Client },
  } = useSuspenseQuery(query(id));
  if (!oauth2Client) throw notFound();

  return (
    <Layout>
      <OAuth2ClientDetail client={oauth2Client} />
    </Layout>
  );
}
