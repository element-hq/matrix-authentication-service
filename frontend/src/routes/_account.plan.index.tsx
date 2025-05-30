// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { queryOptions, useSuspenseQuery } from "@tanstack/react-query";
import { createFileRoute, redirect, useRouter } from "@tanstack/react-router";
import { useCallback, useEffect, useRef, useState } from "react";
import { graphql, useFragment } from "../gql";
import { graphqlRequest } from "../graphql";

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
    const { navigate } = useRouter();
    navigate({ to: "/", replace: true }); // Redirect if no iframe URI is configured
    return <div />;
  }

  const ref = useRef<HTMLIFrameElement>(null);
  const [height, setHeight] = useState("0px");

  // Poll the size of the iframe content and set the height
  // This will only work where the iframe is served from the same origin
  const doHeight = useCallback(() => {
    const height =
      ref.current?.contentWindow?.document.body.parentElement?.scrollHeight;
    if (height) {
      setHeight(`${height}px`);
    } else {
      setHeight("500px");
    }
  }, []);
  useEffect(() => {
    doHeight();

    const interval = setInterval(() => {
      doHeight();
    }, 1000);

    return () => clearInterval(interval);
  }, [doHeight]);

  return (
    <iframe
      title="asd"
      ref={ref}
      onLoad={doHeight}
      src={planManagementIframeUri}
      scrolling="no"
      height={height}
    />
  );
}
