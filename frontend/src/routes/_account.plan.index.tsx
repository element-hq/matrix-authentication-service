// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { createFileRoute } from "@tanstack/react-router";
import { graphql, useFragment } from "../gql";
import { graphqlRequest } from "../graphql";
import { queryOptions, useSuspenseQuery } from "@tanstack/react-query";

export const CONFIG_FRAGMENT = graphql(/* GraphQL */ `
  fragment PlanManagement_siteConfig on SiteConfig {
    planManagementIframeUri
  }
`);

const QUERY = graphql(/* GraphQL */ `
  query SiteConfig {
    siteConfig {
      ...PlanManagement_siteConfig
    }
  }
`);

const query = queryOptions({
    queryKey: ["siteConfig"],
    queryFn: ({ signal }) => graphqlRequest({ query: QUERY, signal }),
});

export const Route = createFileRoute("/_account/plan/")({
    loader: ({ context }) => context.queryClient.ensureQueryData(query),
    component: Plan,
});

function Plan(): React.ReactElement {
    const result = useSuspenseQuery(query);
    const siteConfig = result.data.siteConfig;
    const { planManagementIframeUri } = useFragment(CONFIG_FRAGMENT, siteConfig);

    if (!planManagementIframeUri) {
        return (<div />);
    }

    return (
        <iframe
            src={planManagementIframeUri}
            style={{ height: "calc(100vh - 400px)" }}
        />
    );
}
