// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { useState } from "react";
import * as z from "zod";

// PageInfo we get on connections from the GraphQL API
type PageInfo = {
  hasNextPage: boolean;
  hasPreviousPage: boolean;
  startCursor?: string | null;
  endCursor?: string | null;
};

export const FIRST_PAGE = Symbol("FIRST_PAGE");
export const LAST_PAGE = Symbol("LAST_PAGE");

export const anyPaginationSchema = z.object({
  first: z.number().nullish(),
  after: z.string().nullish(),
  last: z.number().nullish(),
  before: z.string().nullish(),
});

export const forwardPaginationSchema = z.object({
  first: z.number(),
  after: z.string().nullish(),
});

const backwardPaginationSchema = z.object({
  last: z.number(),
  before: z.string().nullish(),
});

const paginationSchema = z.union([
  forwardPaginationSchema,
  backwardPaginationSchema,
]);

type ForwardPagination = z.infer<typeof forwardPaginationSchema>;
type BackwardPagination = z.infer<typeof backwardPaginationSchema>;
export type Pagination = z.infer<typeof paginationSchema>;
export type AnyPagination = z.infer<typeof anyPaginationSchema>;

// Check if the pagination is a valid pagination
export const isValidPagination = (
  pagination: AnyPagination,
): pagination is Pagination =>
  typeof pagination.first === "number" || typeof pagination.last === "number";

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

// Normalize pagination parameters to a valid pagination object
export const normalizePagination = (
  pagination: AnyPagination,
  pageSize = 6,
  type: "forward" | "backward" = "forward",
): Pagination => {
  if (isValidPagination(pagination)) {
    return pagination;
  }

  if (type === "forward") {
    return { first: pageSize } satisfies ForwardPagination;
  }

  return { last: pageSize } satisfies BackwardPagination;
};

// Hook to handle pagination state.
export const usePagination = (
  pageSize = 6,
): [Pagination, (action: Action) => void] => {
  const [pagination, setPagination] = useState<Pagination>({
    first: pageSize,
  });

  const handlePagination = (action: Action): void => {
    if (action === FIRST_PAGE) {
      setPagination({
        first: pageSize,
      } satisfies ForwardPagination);
    } else if (action === LAST_PAGE) {
      setPagination({
        last: pageSize,
      } satisfies BackwardPagination);
    } else {
      setPagination(action);
    }
  };

  return [pagination, handlePagination];
};

// Compute the next backward and forward pagination parameters based on the current pagination and the page info.
export const usePages = (
  currentPagination: Pagination,
  pageInfo: PageInfo,
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
  if (pageInfo.hasPreviousPage || hasProbablyPreviousPage) {
    previousPagination = {
      last: pageSize,
      before: pageInfo.startCursor ?? undefined,
    };
  }

  if (pageInfo.hasNextPage || hasProbablyNextPage) {
    nextPagination = {
      first: pageSize,
      after: pageInfo.endCursor ?? undefined,
    };
  }

  return [previousPagination, nextPagination];
};
