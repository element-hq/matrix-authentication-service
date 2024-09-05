// Copyright (C) 2024 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { createLazyFileRoute, notFound } from "@tanstack/react-router";
import { useQuery } from "urql";

import Layout from "../components/Layout";
import VerifyEmailComponent from "../components/VerifyEmail";

import { QUERY } from "./emails.$id.verify";

export const Route = createLazyFileRoute("/emails/$id/verify")({
  component: EmailVerify,
});

function EmailVerify(): React.ReactElement {
  const { id } = Route.useParams();
  const [result] = useQuery({ query: QUERY, variables: { id } });

  if (result.error) throw result.error;
  const email = result.data?.userEmail;
  if (email == null) throw notFound();

  return (
    <Layout>
      <VerifyEmailComponent email={email} />
    </Layout>
  );
}
