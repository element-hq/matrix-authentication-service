// Copyright (C) 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

const RESULT = Symbol("Result");
const ERR = Symbol("Err");
const OK = Symbol("Ok");

/**
 * An `Ok` is a type that represents a successful result.
 */
export type Ok<T> = {
  [RESULT]: typeof OK;
  [OK]: T;
};

/**
 * An `Err` is a type that represents an error.
 */
export type Err<E> = {
  [RESULT]: typeof ERR;
  [ERR]: E;
};

/**
 * A `Result` is a type that represents either an `Ok` or an `Err`.
 */
export type Result<T, E> = Ok<T> | Err<E>;

// Construct an `Ok`
export const ok = <T>(data: T): Ok<T> => ({ [RESULT]: OK, [OK]: data });

// Construct an `Err`
export const err = <E>(error: E): Err<E> => ({
  [RESULT]: ERR,
  [ERR]: error,
});

// Check if a `Result` is an `Ok`
export const isOk = <T, E>(result: Result<T, E>): result is Ok<T> =>
  result[RESULT] === OK;

// Check if a `Result` is an `Err`
export const isErr = <T, E>(result: Result<T, E>): result is Err<E> =>
  result[RESULT] === ERR;

// Extract the data from an `Ok`
export const unwrapOk = <T>(result: Ok<T>): T => result[OK];

// Extract the error from an `Err`
export const unwrapErr = <E>(result: Err<E>): E => result[ERR];

/**
 * Check result for error and throw unwrapped error
 * Otherwise return unwrapped Ok result
 */
export const unwrap = <T, E>(result: Result<T, E>): T => {
  if (isErr(result)) {
    throw unwrapErr(result);
  }
  return unwrapOk(result);
};
