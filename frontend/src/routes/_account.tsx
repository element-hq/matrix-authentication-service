// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import { queryOptions, useSuspenseQuery } from "@tanstack/react-query";
import { notFound, Outlet } from "@tanstack/react-router";
import { Heading } from "@vector-im/compound-web";
import { useTranslation } from "react-i18next";
import Layout from "../components/Layout";
import NavBar from "../components/NavBar";
import NavItem from "../components/NavItem";
import UserGreeting from "../components/UserGreeting";
import { graphql } from "../gql";
import { graphqlRequest } from "../graphql";

const QUERY = graphql(/* GraphQL */ `
  query CurrentUserGreeting {
    viewer {
      __typename
      ... on User {
        ...UserGreeting_user
      }
    }

    siteConfig {
      ...UserGreeting_siteConfig
      planManagementIframeUri
    }
  }
`);

const query = queryOptions({
  queryKey: ["currentUserGreeting"],
  queryFn: ({ signal }) => graphqlRequest({ query: QUERY, signal }),
});

export const Route = createFileRoute({
  loader: ({ context }) => context.queryClient.ensureQueryData(query),
  component: Account,
});

function Account(): React.ReactElement {
  const { t } = useTranslation();
  const result = useSuspenseQuery(query);
  const viewer = result.data.viewer;
  if (viewer?.__typename !== "User") throw notFound();
  const { siteConfig } = result.data;
  const { planManagementIframeUri } = siteConfig;

  return (
    <Layout wide>
      <div className="flex flex-col gap-10">
        <Heading size="md" weight="semibold">
          {t("frontend.account.title")}
        </Heading>

        <div className="flex flex-col gap-4">
          <UserGreeting user={viewer} siteConfig={siteConfig} />

          <NavBar>
            <NavItem to="/">{t("frontend.nav.settings")}</NavItem>
            <NavItem to="/sessions">{t("frontend.nav.devices")}</NavItem>
            {planManagementIframeUri && (
              <NavItem to="/plan">{t("frontend.nav.plan")}</NavItem>
            )}
          </NavBar>
        </div>
      </div>

      <Outlet />
    </Layout>
  );
}
