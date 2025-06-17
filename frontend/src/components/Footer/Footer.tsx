// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import { Link } from "@vector-im/compound-web";
import { useTranslation } from "react-i18next";

import { type FragmentType, graphql, useFragment } from "../../gql";

import styles from "./Footer.module.css";

export const FRAGMENT = graphql(/* GraphQL */ `
  fragment Footer_siteConfig on SiteConfig {
    id
    imprint
    tosUri
    policyUri
  }
`);

type Props = {
  siteConfig: FragmentType<typeof FRAGMENT>;
};

const Footer: React.FC<Props> = ({ siteConfig }) => {
  const data = useFragment(FRAGMENT, siteConfig);
  const { t } = useTranslation();
  return (
    <footer className={styles.legalFooter}>
      {(data.policyUri || data.tosUri) && (
        <nav>
          {data.policyUri && (
            <Link
              href={data.policyUri}
              title={t("branding.privacy_policy.alt", {
                defaultValue: "Link to the service privacy policy",
              })}
            >
              {t("branding.privacy_policy.link", {
                defaultValue: "Privacy policy",
              })}
            </Link>
          )}

          {data.policyUri && data.tosUri && (
            <div className={styles.separator} aria-hidden="true">
              •
            </div>
          )}

          {data.tosUri && (
            <Link
              href={data.tosUri}
              title={t("branding.terms_and_conditions.alt", {
                defaultValue: "Link to the service terms and conditions",
              })}
            >
              {t("branding.terms_and_conditions.link", {
                defaultValue: "Terms and conditions",
              })}
            </Link>
          )}
        </nav>
      )}

      {data.imprint && <p className={styles.imprint}>{data.imprint}</p>}
    </footer>
  );
};

export default Footer;
