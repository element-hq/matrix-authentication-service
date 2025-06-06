// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { queryOptions, useSuspenseQuery } from "@tanstack/react-query";
import { Navigate, createFileRoute, redirect } from "@tanstack/react-router";
import { useCallback, useEffect, useMemo, useRef } from "react";
import { preload } from "react-dom";
import { graphql } from "../gql";
import { graphqlRequest } from "../graphql";

const QUERY = graphql(/* GraphQL */ `
  query PlanManagementTab {
    siteConfig {
      planManagementIframeUri
    }
  }
`);

export const query = queryOptions({
  queryKey: ["planManagementTab"],
  queryFn: ({ signal }) => graphqlRequest({ query: QUERY, signal }),
});

export const Route = createFileRoute("/_account/plan/")({
  loader: async ({ context }) => {
    const { siteConfig: { planManagementIframeUri } } =
      await context.queryClient.ensureQueryData(query);

    if (!planManagementIframeUri)
      throw redirect({ to: "/", replace: true });

    preload(planManagementIframeUri, { as: "document" });
  },
  component: Plan,
});

function Plan(): React.ReactElement {
  const result = useSuspenseQuery(query);
  const { planManagementIframeUri } = result.data.siteConfig;

  if (!planManagementIframeUri) {
    // Redirect if no iframe URI is configured
    return <Navigate to="/" replace />;
  }

  const ref = useRef<HTMLIFrameElement>(null);

  // Query the size of the iframe content and set the height
  // This will only work where the iframe is served from the same origin
  const calculateHeight = useCallback(() => {
    const iframe = ref.current;
    if (!iframe) {
      return;
    }
    const height =
      iframe.contentWindow?.document.body.parentElement?.scrollHeight;

    if (height) {
      iframe.height = `${height}px`;
    } else {
      iframe.height = "500px";
    }
  }, []);

  const observer = useMemo(
    () =>
      new MutationObserver((_mutationsList) => {
        // we calculate the height immediately when the observer is triggered
        calculateHeight();
        // then we recalculate the height after a short timeout to allow for any rendering
        // that doesn't trigger a mutation. e.g. an iframe
        setTimeout(() => {
          calculateHeight();
        }, 1000);
        // n.b. we don't worry about the timeout happening after the component is unmounted
      }),
    [calculateHeight],
  );

  useEffect(() => {
    const iframe = ref.current;
    if (iframe) {
      attachObserver(iframe);
    }
    // Cleanup observer when the component unmounts
    return () => observer.disconnect();
  }, [observer]);

  const attachObserver = (iframe: HTMLIFrameElement) => {
    const iframeBody = iframe.contentWindow?.document.body;
    if (!iframeBody) {
      return;
    }
    // calculate the height immediately
    calculateHeight();
    // observe future changes to the body of the iframe
    observer.observe(iframeBody, {
      childList: true,
      subtree: true,
      attributes: true,
    });
  };

  return (
    <iframe
      title="iframe" // no proper title as this is experimental feature
      ref={ref}
      onLoad={(e) => attachObserver(e.target as HTMLIFrameElement)}
      src={planManagementIframeUri}
      scrolling="no"
    />
  );
}
