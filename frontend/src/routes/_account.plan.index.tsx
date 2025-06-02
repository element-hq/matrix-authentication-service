// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { queryOptions, useSuspenseQuery } from "@tanstack/react-query";
import { Navigate, createFileRoute } from "@tanstack/react-router";
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

export const query = queryOptions({
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
    // Redirect if no iframe URI is configured
    return <Navigate to="/" replace />;
  }

  const ref = useRef<HTMLIFrameElement>(null);
  const [iframeHeight, setIframeHeight] = useState("0px");

  // Poll the size of the iframe content and set the height
  // This will only work where the iframe is served from the same origin
  const calculateHeight = useCallback(() => {
    const height =
      ref.current?.contentWindow?.document.body.parentElement?.scrollHeight;
    if (height) {
      setIframeHeight(`${height}px`);
    } else {
      setIframeHeight("500px");
    }
  }, []);
  useEffect(() => {
    calculateHeight();

    const interval = setInterval(() => {
      calculateHeight();
    }, 1000);

    return () => clearInterval(interval);
  }, [calculateHeight]);

  return (
    <iframe
      title="iframe" // no proper title as this is experimental feature
      ref={ref}
      onLoad={calculateHeight}
      src={planManagementIframeUri}
      scrolling="no"
      height={iframeHeight}
    />
  );
}
