// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { queryOptions, useQuery } from "@tanstack/react-query";
import cx from "classnames";
import { Suspense } from "react";
import { graphql } from "../../gql";
import { graphqlRequest } from "../../graphql";
import Footer from "../Footer";
import styles from "./Layout.module.css";

const QUERY = graphql(/* GraphQL */ `
  query Footer {
    siteConfig {
      id
      ...Footer_siteConfig
    }
  }
`);

export const query = queryOptions({
  queryKey: ["footer"],
  queryFn: ({ signal }) => graphqlRequest({ query: QUERY, signal }),
  throwOnError: false,
});

const AsyncFooter: React.FC = () => {
  const result = useQuery(query);

  if (result.error || result.isPending) {
    // We probably prefer to render an empty footer in case of an error
    return null;
  }

  const siteConfig = result.data?.siteConfig;
  if (!siteConfig) {
    // We checked for errors, this should never happen
    throw new Error("Failed to load site config");
  }

  return <Footer siteConfig={siteConfig} />;
};

const Layout: React.FC<{
  children?: React.ReactNode;
  wide?: boolean;
}> = ({ children, wide }) => (
  <div className={cx(styles.layoutContainer, wide && styles.wide)}>
    {children}
    <Suspense fallback={null}>
      <AsyncFooter />
    </Suspense>
  </div>
);

export default Layout;
