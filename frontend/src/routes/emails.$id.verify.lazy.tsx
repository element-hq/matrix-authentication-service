// Copyright 2024 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { useSuspenseQuery } from "@tanstack/react-query";
import { createLazyFileRoute, notFound } from "@tanstack/react-router";

import Layout from "../components/Layout";
import VerifyEmailComponent from "../components/VerifyEmail";

import { query } from "./emails.$id.verify";

export const Route = createLazyFileRoute("/emails/$id/verify")({
  component: EmailVerify,
});

function EmailVerify(): React.ReactElement {
  const { id } = Route.useParams();
  const {
    data: { userEmail },
  } = useSuspenseQuery(query(id));
  if (!userEmail) throw notFound();

  return (
    <Layout>
      <VerifyEmailComponent email={userEmail} />
    </Layout>
  );
}
