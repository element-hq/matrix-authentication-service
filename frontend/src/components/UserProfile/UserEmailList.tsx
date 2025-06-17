// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import { queryOptions, useSuspenseQuery } from "@tanstack/react-query";
import { notFound } from "@tanstack/react-router";
import { useTransition } from "react";
import { type FragmentType, graphql, useFragment } from "../../gql";
import { graphqlRequest } from "../../graphql";
import {
  type AnyPagination,
  FIRST_PAGE,
  type Pagination,
  usePages,
  usePagination,
} from "../../pagination";
import PaginationControls from "../PaginationControls";
import UserEmail from "../UserEmail";

const QUERY = graphql(/* GraphQL */ `
  query UserEmailList(
    $first: Int
    $after: String
    $last: Int
    $before: String
  ) {
    viewer {
      __typename
      ... on User {
        emails(first: $first, after: $after, last: $last, before: $before) {
          edges {
            cursor
            node {
              ...UserEmail_email
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
    queryKey: ["userEmails", pagination],
    queryFn: ({ signal }) =>
      graphqlRequest({
        query: QUERY,
        variables: pagination,
        signal,
      }),
  });

export const USER_FRAGMENT = graphql(/* GraphQL */ `
  fragment UserEmailList_user on User {
    hasPassword
  }
`);

export const CONFIG_FRAGMENT = graphql(/* GraphQL */ `
  fragment UserEmailList_siteConfig on SiteConfig {
    emailChangeAllowed
    passwordLoginEnabled
  }
`);

const UserEmailList: React.FC<{
  siteConfig: FragmentType<typeof CONFIG_FRAGMENT>;
  user: FragmentType<typeof USER_FRAGMENT>;
}> = ({ siteConfig, user }) => {
  const { emailChangeAllowed, passwordLoginEnabled } = useFragment(
    CONFIG_FRAGMENT,
    siteConfig,
  );
  const { hasPassword } = useFragment(USER_FRAGMENT, user);
  const shouldPromptPassword = hasPassword && passwordLoginEnabled;

  const [pending, startTransition] = useTransition();

  const [pagination, setPagination] = usePagination();
  const result = useSuspenseQuery(query(pagination));
  if (result.data.viewer.__typename !== "User") throw notFound();
  const emails = result.data.viewer.emails;

  const [prevPage, nextPage] = usePages(pagination, emails.pageInfo);

  const paginate = (pagination: Pagination): void => {
    startTransition(() => {
      setPagination(pagination);
    });
  };

  // When removing an email, we want to go back to the first page
  const onRemove = (): void => {
    startTransition(() => {
      setPagination(FIRST_PAGE);
    });
  };

  // Is it allowed to remove an email? If there's only one, we can't
  const canRemove = emailChangeAllowed && emails.totalCount > 1;

  return (
    <>
      {emails.edges.map((edge) => (
        <UserEmail
          email={edge.node}
          key={edge.cursor}
          canRemove={canRemove}
          shouldPromptPassword={shouldPromptPassword}
          onRemove={onRemove}
        />
      ))}

      <PaginationControls
        autoHide
        count={emails.totalCount}
        onPrev={prevPage ? (): void => paginate(prevPage) : null}
        onNext={nextPage ? (): void => paginate(nextPage) : null}
        disabled={pending}
      />
    </>
  );
};

export default UserEmailList;
