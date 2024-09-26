// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { H5 } from "@vector-im/compound-web";
import { useTransition } from "react";
import { useQuery } from "urql";

import { graphql } from "../../gql";
import { Pagination, usePages, usePagination } from "../../pagination";
import PaginationControls from "../PaginationControls";
import UpstreamProvider from "../UpstreamProvider";

const QUERY = graphql(/* GraphQL */ `
  query UpstreamProviderListQuery(
    $first: Int
    $after: String
    $last: Int
    $before: String
  ) {
    upstreamOauth2Providers(
      first: $first
      after: $after
      last: $last
      before: $before
    ) {
      edges {
        cursor
        node {
          id
          upstreamOauth2LinksForUser {
            id
            provider {
              id
            }
          }
          ...UpstreamProvider_provider
        }
      }
      totalCount
      pageInfo {
        hasNextPage
        hasPreviousPage
        startCursor
        endCursor
      }
    }
  }
`);

const UpstreamProviderList: React.FC<{}> = () => {
  const [pending, startTransition] = useTransition();

  const [pagination, setPagination] = usePagination();
  const [result] = useQuery({
    query: QUERY,
    variables: { ...pagination },
  });
  if (result.error) throw result.error;
  const links = result.data?.upstreamOauth2Providers;
  if (!links) throw new Error(); // Suspense mode is enabled

  const [prevPage, nextPage] = usePages(pagination, links.pageInfo);
  const paginate = (pagination: Pagination): void => {
    startTransition(() => {
      setPagination(pagination);
    });
  };

  return (
    <>
      <H5>Unlinked Upstream Providers</H5>
      {links.edges
        .filter(
          (edge) =>
            !edge.node.upstreamOauth2LinksForUser.some(
              (link) => link.provider.id === edge.node.id,
            ),
        )
        .map((edge) => (
          <UpstreamProvider upstreamProvider={edge.node} key={edge.cursor} />
        ))}
      <H5>Linked Upstream Providers</H5>
      {links.edges
        .filter((edge) =>
          edge.node.upstreamOauth2LinksForUser.some(
            (link) => link.provider.id === edge.node.id,
          ),
        )
        .map((edge) => (
          <UpstreamProvider
            upstreamProvider={edge.node}
            disabled
            key={edge.cursor}
          />
        ))}
      <PaginationControls
        autoHide
        count={links.totalCount ?? 0}
        onPrev={prevPage ? (): void => paginate(prevPage) : null}
        onNext={nextPage ? (): void => paginate(nextPage) : null}
        disabled={pending}
      />
    </>
  );
};

export default UpstreamProviderList;
