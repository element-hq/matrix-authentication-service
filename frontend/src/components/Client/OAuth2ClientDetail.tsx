// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import { H3 } from "@vector-im/compound-web";
import { useTranslation } from "react-i18next";

import { type FragmentType, useFragment } from "../../gql";
import { graphql } from "../../gql/gql";
import ExternalLink from "../ExternalLink/ExternalLink";
import ClientAvatar from "../Session/ClientAvatar";
import * as Info from "../SessionDetail/SessionInfo";

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

  return (
    <div className="flex flex-col gap-10">
      <header className="flex flex-row gap-2 justify-start items-center">
        <ClientAvatar
          logoUri={data.logoUri || undefined}
          name={data.clientName || data.clientId}
          size="1.5rem"
        />
        <H3>{data.clientName}</H3>
      </header>
      <Info.DataSection>
        <Info.DataSectionHeader>
          {t("frontend.oauth2_client_detail.details_title")}
        </Info.DataSectionHeader>
        <Info.DataList>
          {data.clientName && (
            <Info.Data>
              <Info.DataLabel>
                {t("frontend.oauth2_client_detail.name")}
              </Info.DataLabel>
              <Info.DataValue>{data.clientName}</Info.DataValue>
            </Info.Data>
          )}
          {data.tosUri && (
            <Info.Data>
              <Info.DataLabel>
                {t("frontend.oauth2_client_detail.terms")}
              </Info.DataLabel>
              <Info.DataValue>
                <FriendlyExternalLink uri={data.tosUri} />
              </Info.DataValue>
            </Info.Data>
          )}
          {data.policyUri && (
            <Info.Data>
              <Info.DataLabel>
                {t("frontend.oauth2_client_detail.policy")}
              </Info.DataLabel>
              <Info.DataValue>
                <FriendlyExternalLink uri={data.policyUri} />
              </Info.DataValue>
            </Info.Data>
          )}
        </Info.DataList>
      </Info.DataSection>
    </div>
  );
};

export default OAuth2ClientDetail;
