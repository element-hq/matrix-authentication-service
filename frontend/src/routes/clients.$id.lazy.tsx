// Copyright 2024 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { createLazyFileRoute } from "@tanstack/react-router";
import { useQuery } from "urql";

import OAuth2ClientDetail from "../components/Client/OAuth2ClientDetail";
import Layout from "../components/Layout";

import { QUERY } from "./clients.$id";

export const Route = createLazyFileRoute("/clients/$id")({
  component: ClientDetail,
});

function ClientDetail(): React.ReactElement {
  const { id } = Route.useParams();
  const [result] = useQuery({
    query: QUERY,
    variables: { id },
  });
  if (result.error) throw result.error;
  const client = result.data?.oauth2Client;
  if (!client) throw new Error(); // Should have been caught by the loader

  return (
    <Layout>
      <OAuth2ClientDetail client={client} />
    </Layout>
  );
}
