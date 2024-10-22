// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { H3 } from "@vector-im/compound-web";
import { useTranslation } from "react-i18next";

import { type FragmentType, useFragment } from "../../gql";
import { graphql } from "../../gql/gql";
import BlockList from "../BlockList/BlockList";
import ExternalLink from "../ExternalLink/ExternalLink";
import ClientAvatar from "../Session/ClientAvatar";
import SessionDetails from "../SessionDetail/SessionDetails";

import styles from "./OAuth2ClientDetail.module.css";

export const OAUTH2_CLIENT_FRAGMENT = graphql(/* GraphQL */ `
  fragment OAuth2Client_detail on Oauth2Client {
    id
    clientId
    clientName
    clientUri
    logoUri
    tosUri
    policyUri
    redirectUris
  }
`);

type Props = {
  client: FragmentType<typeof OAUTH2_CLIENT_FRAGMENT>;
};

const FriendlyExternalLink: React.FC<{ uri?: string }> = ({ uri }) => {
  if (!uri) {
    return null;
  }
  const url = new URL(uri);
  const friendlyUrl = url.host + url.pathname;

  return <ExternalLink href={uri}>{friendlyUrl}</ExternalLink>;
};

const OAuth2ClientDetail: React.FC<Props> = ({ client }) => {
  const data = useFragment(OAUTH2_CLIENT_FRAGMENT, client);
  const { t } = useTranslation();

  const details = [
    { label: t("frontend.oauth2_client_detail.name"), value: data.clientName },
    {
      label: t("frontend.oauth2_client_detail.terms"),
      value: data.tosUri && <FriendlyExternalLink uri={data.tosUri} />,
    },
    {
      label: t("frontend.oauth2_client_detail.policy"),
      value: data.policyUri && <FriendlyExternalLink uri={data.policyUri} />,
    },
  ].filter(({ value }) => !!value);

  return (
    <BlockList>
      <header className={styles.header}>
        <ClientAvatar
          logoUri={data.logoUri || undefined}
          name={data.clientName || data.clientId}
          size="1.5rem"
        />
        <H3>{data.clientName}</H3>
      </header>
      <SessionDetails
        title={t("frontend.oauth2_client_detail.details_title")}
        details={details}
      />
    </BlockList>
  );
};

export default OAuth2ClientDetail;
