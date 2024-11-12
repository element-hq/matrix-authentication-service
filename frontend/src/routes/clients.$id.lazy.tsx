// Copyright 2024 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { createLazyFileRoute, notFound } from "@tanstack/react-router";

import OAuth2ClientDetail from "../components/Client/OAuth2ClientDetail";
import Layout from "../components/Layout";

import { useSuspenseQuery } from "@tanstack/react-query";
import { query } from "./clients.$id";

export const Route = createLazyFileRoute("/clients/$id")({
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
