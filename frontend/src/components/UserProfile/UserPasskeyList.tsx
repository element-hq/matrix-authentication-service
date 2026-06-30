// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { queryOptions, useSuspenseQuery } from "@tanstack/react-query";
import { notFound } from "@tanstack/react-router";
import { useTransition } from "react";
import { graphql } from "../../gql";
import { graphqlRequest } from "../../graphql";
import {
  type AnyPagination,
  FIRST_PAGE,
  type Pagination,
  usePages,
  usePagination,
} from "../../pagination";
import PaginationControls from "../PaginationControls";
import UserPasskey from "../UserPasskey";

const QUERY = graphql(/* GraphQL */ `
  query UserPasskeyList(
    $first: Int
    $after: String
    $last: Int
    $before: String
  ) {
    viewer {
      __typename
      ... on User {
        passkeys(first: $first, after: $after, last: $last, before: $before) {
          edges {
            cursor
            node {
              ...UserPasskey_passkey
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
    }
  }
`);

export const query = (pagination: AnyPagination = { first: 6 }) =>
  queryOptions({
    queryKey: ["userPasskeys", pagination],
    queryFn: ({ signal }) =>
      graphqlRequest({
        query: QUERY,
        variables: pagination,
        signal,
      }),
  });

const UserPasskeyList: React.FC = () => {
  const [pending, startTransition] = useTransition();
  const [pagination, setPagination] = usePagination();
  const result = useSuspenseQuery(query(pagination));
  if (result.data.viewer.__typename !== "User") throw notFound();
  const passkeys = result.data.viewer.passkeys;

  const [prevPage, nextPage] = usePages(pagination, passkeys.pageInfo);

  const paginate = (pagination: Pagination): void => {
    startTransition(() => {
      setPagination(pagination);
    });
  };

  const onRemove = (): void => {
    startTransition(() => {
      setPagination(FIRST_PAGE);
    });
  };

  return (
    <>
      {passkeys.edges.map((edge) => (
        <UserPasskey
          passkey={edge.node}
          key={edge.cursor}
          onRemove={onRemove}
        />
      ))}

      <PaginationControls
        autoHide
        count={passkeys.totalCount}
        onPrev={prevPage ? (): void => paginate(prevPage) : null}
        onNext={nextPage ? (): void => paginate(nextPage) : null}
        disabled={pending}
      />
    </>
  );
};

export default UserPasskeyList;
