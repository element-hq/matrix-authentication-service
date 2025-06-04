// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { queryOptions, useSuspenseQuery } from "@tanstack/react-query";
import { Navigate, createFileRoute, redirect } from "@tanstack/react-router";
import { type Ref, useCallback } from "react";
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
    const { planManagementIframeUri } = (
      await context.queryClient.ensureQueryData(query)
    ).siteConfig;
    if (planManagementIframeUri) {
      preload(planManagementIframeUri, { as: "document" });
    } else {
      throw redirect({ to: "/" });
    }
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

  // Query the size of the iframe content and set the height
  // This will only work where the iframe is served from the same origin
  const calculateHeight = useCallback((iframe: HTMLIFrameElement) => {
    const height =
      iframe.contentWindow?.document.body.parentElement?.scrollHeight;

    if (height) {
      iframe.height = `${height}px`;
    } else {
      iframe.height = "500px";
    }
  }, []);

  const ref: Ref<HTMLIFrameElement> = useCallback(
    (iframe: HTMLIFrameElement | null) => {
      if (!iframe) return;
      calculateHeight(iframe);

      if (iframe.contentWindow) {
        const iframeDocument = iframe.contentWindow.document;

        const observer = new MutationObserver((_mutationsList) => {
          calculateHeight(iframe);
        });

        observer.observe(iframeDocument.body, {
          childList: true,
          subtree: true,
          attributes: true,
        });

        return () => observer.disconnect();
      }
    },
    [calculateHeight],
  );

  return (
    <iframe
      title="iframe" // no proper title as this is experimental feature
      ref={ref}
      onLoad={(e) => calculateHeight(e.target as HTMLIFrameElement)}
      src={planManagementIframeUri}
      scrolling="no"
    />
  );
}
