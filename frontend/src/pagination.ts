// Copyright (C) 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { useState } from "react";
import * as z from "zod";

import { PageInfo } from "./gql/graphql";

export const FIRST_PAGE = Symbol("FIRST_PAGE");
export const LAST_PAGE = Symbol("LAST_PAGE");

export const forwardPaginationSchema = z.object({
  first: z.number(),
  after: z.string().optional(),
});

export const backwardPaginationSchema = z.object({
  last: z.number(),
  before: z.string().optional(),
});

export const paginationSchema = z.union([
  forwardPaginationSchema,
  backwardPaginationSchema,
]);

export type ForwardPagination = z.infer<typeof forwardPaginationSchema>;
export type BackwardPagination = z.infer<typeof backwardPaginationSchema>;
export type Pagination = z.infer<typeof paginationSchema>;

// Check if the pagination is forward pagination.
export const isForwardPagination = (
  pagination: Pagination,
): pagination is ForwardPagination => {
  return Object.hasOwn(pagination, "first");
};

// Check if the pagination is backward pagination.
export const isBackwardPagination = (
  pagination: Pagination,
): pagination is BackwardPagination => {
  return Object.hasOwn(pagination, "last");
};

type Action = typeof FIRST_PAGE | typeof LAST_PAGE | Pagination;

// Hook to handle pagination state.
export const usePagination = (
  pageSize = 6,
): [Pagination, (action: Action) => void] => {
  const [pagination, setPagination] = useState<Pagination>({
    first: pageSize,
    after: undefined,
  });

  const handlePagination = (action: Action): void => {
    if (action === FIRST_PAGE) {
      setPagination({
        first: pageSize,
        after: undefined,
      });
    } else if (action === LAST_PAGE) {
      setPagination({
        last: pageSize,
        before: undefined,
      });
    } else {
      setPagination(action);
    }
  };

  return [pagination, handlePagination];
};

// Compute the next backward and forward pagination parameters based on the current pagination and the page info.
export const usePages = (
  currentPagination: Pagination,
  pageInfo: PageInfo | null,
  pageSize = 6,
): [BackwardPagination | null, ForwardPagination | null] => {
  const hasProbablyPreviousPage =
    isForwardPagination(currentPagination) &&
    currentPagination.after !== undefined;
  const hasProbablyNextPage =
    isBackwardPagination(currentPagination) &&
    currentPagination.before !== undefined;

  let previousPagination: BackwardPagination | null = null;
  let nextPagination: ForwardPagination | null = null;
  if (pageInfo?.hasPreviousPage || hasProbablyPreviousPage) {
    previousPagination = {
      last: pageSize,
      before: pageInfo?.startCursor ?? undefined,
    };
  }

  if (pageInfo?.hasNextPage || hasProbablyNextPage) {
    nextPagination = {
      first: pageSize,
      after: pageInfo?.endCursor ?? undefined,
    };
  }

  return [previousPagination, nextPagination];
};
