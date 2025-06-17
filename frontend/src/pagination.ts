// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import { useState } from "react";
import * as v from "valibot";

// PageInfo we get on connections from the GraphQL API
type PageInfo = {
  hasNextPage: boolean;
  hasPreviousPage: boolean;
  startCursor?: string | null;
  endCursor?: string | null;
};

export const FIRST_PAGE = Symbol("FIRST_PAGE");
const LAST_PAGE = Symbol("LAST_PAGE");

export const anyPaginationSchema = v.object({
  first: v.nullish(v.number()),
  after: v.nullish(v.string()),
  last: v.nullish(v.number()),
  before: v.nullish(v.string()),
});

const forwardPaginationSchema = v.object({
  first: v.number(),
  after: v.nullish(v.string()),
});

const backwardPaginationSchema = v.object({
  last: v.number(),
  before: v.nullish(v.string()),
});

const paginationSchema = v.union([
  forwardPaginationSchema,
  backwardPaginationSchema,
]);

type ForwardPagination = v.InferOutput<typeof forwardPaginationSchema>;
type BackwardPagination = v.InferOutput<typeof backwardPaginationSchema>;
export type Pagination = v.InferOutput<typeof paginationSchema>;
export type AnyPagination = v.InferOutput<typeof anyPaginationSchema>;

// Check if the pagination is a valid pagination
const isValidPagination = (
  pagination: AnyPagination,
): pagination is Pagination =>
  typeof pagination.first === "number" || typeof pagination.last === "number";

// Check if the pagination is forward pagination.
const isForwardPagination = (
  pagination: Pagination,
): pagination is ForwardPagination => {
  return Object.hasOwn(pagination, "first");
};

// Check if the pagination is backward pagination.
const isBackwardPagination = (
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
