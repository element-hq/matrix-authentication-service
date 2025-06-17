// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { parseISO } from "date-fns";
import { useTranslation } from "react-i18next";
import { type FragmentType, graphql, useFragment } from "../../gql";
import { graphqlRequest } from "../../graphql";
import { getDeviceIdFromScope } from "../../utils/deviceIdFromScope";
import DateTime from "../DateTime";
import ClientAvatar from "../Session/ClientAvatar";
import EndOAuth2SessionButton from "../Session/EndOAuth2SessionButton";
import LastActive from "../Session/LastActive";
import EditSessionName from "./EditSessionName";
import SessionHeader from "./SessionHeader";
import * as Info from "./SessionInfo";

const SET_SESSION_NAME_MUTATION = graphql(/* GraphQL */ `
  mutation SetOAuth2SessionName($sessionId: ID!, $displayName: String!) {
    setOauth2SessionName(input: { oauth2SessionId: $sessionId, humanName: $displayName }) {
      status
    }
  }
`);

export const FRAGMENT = graphql(/* GraphQL */ `
  fragment OAuth2Session_detail on Oauth2Session {
    id
    scope
    createdAt
    finishedAt
    lastActiveIp
    lastActiveAt
    humanName

    ...EndOAuth2SessionButton_session

    userAgent {
      name
      model
      os
    }

    client {
      id
      clientId
      clientName
      clientUri
      logoUri
    }
  }
`);

type Props = {
  session: FragmentType<typeof FRAGMENT>;
};

const OAuth2SessionDetail: React.FC<Props> = ({ session }) => {
  const data = useFragment(FRAGMENT, session);
  const { t } = useTranslation();
  const queryClient = useQueryClient();

  const setDisplayName = useMutation({
    mutationFn: (displayName: string) =>
      graphqlRequest({
        query: SET_SESSION_NAME_MUTATION,
        variables: { sessionId: data.id, displayName },
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["sessionDetail", data.id] });
      queryClient.invalidateQueries({ queryKey: ["sessionsOverview"] });
    },
  });

  const deviceId = getDeviceIdFromScope(data.scope);
  const clientName = data.client.clientName || data.client.clientId;

  const deviceName =
    data.humanName ??
    data.userAgent?.model ??
    (data.userAgent?.name
      ? data.userAgent?.os
        ? t("frontend.session.name_for_platform", {
            name: data.userAgent.name,
            platform: data.userAgent.os,
          })
        : data.userAgent.name
      : t("frontend.session.unknown_device"));

  return (
    <div className="flex flex-col gap-10">
      <SessionHeader to="/sessions">
        {clientName}: {deviceName}
        <EditSessionName mutation={setDisplayName} deviceName={deviceName} />
      </SessionHeader>

      <Info.DataSection>
        <Info.DataSectionHeader>
          {t("frontend.session.title")}
        </Info.DataSectionHeader>
        <Info.DataList>
          {data.lastActiveAt && (
            <Info.Data>
              <Info.DataLabel>
                {t("frontend.session.last_active_label")}
              </Info.DataLabel>
              <Info.DataValue>
                <LastActive lastActive={parseISO(data.lastActiveAt)} />
              </Info.DataValue>
            </Info.Data>
          )}

          <Info.Data>
            <Info.DataLabel>
              {t("frontend.session.signed_in_label")}
            </Info.DataLabel>
            <Info.DataValue>
              <DateTime datetime={data.createdAt} />
            </Info.DataValue>
          </Info.Data>

          {data.finishedAt && (
            <Info.Data>
              <Info.DataLabel>
                {t("frontend.session.finished_label")}
              </Info.DataLabel>
              <Info.DataValue>
                <DateTime datetime={data.finishedAt} />
              </Info.DataValue>
            </Info.Data>
          )}

          <Info.Data>
            <Info.DataLabel>
              {t("frontend.session.device_id_label")}
            </Info.DataLabel>
            <Info.DataValue>{deviceId}</Info.DataValue>
          </Info.Data>

          {data.lastActiveIp && (
            <Info.Data>
              <Info.DataLabel>{t("frontend.session.ip_label")}</Info.DataLabel>
              <Info.DataValue>
                <code>{data.lastActiveIp}</code>
              </Info.DataValue>
            </Info.Data>
          )}
        </Info.DataList>

        <Info.Data>
          <Info.DataLabel>{t("frontend.session.scopes_label")}</Info.DataLabel>
          <Info.ScopeList scope={data.scope} />
        </Info.Data>
      </Info.DataSection>

      <Info.DataSection>
        <Info.DataSectionHeader>
          {t("frontend.oauth2_session_detail.client_title")}
        </Info.DataSectionHeader>
        <Info.DataList>
          <Info.Data>
            <Info.DataLabel>
              {t("frontend.oauth2_session_detail.client_details_name")}
            </Info.DataLabel>
            <Info.DataValue>
              <ClientAvatar
                name={data.client.clientName || data.client.clientId}
                logoUri={data.client.logoUri || undefined}
                size="var(--cpd-space-4x)"
              />
              {data.client.clientName}
            </Info.DataValue>
          </Info.Data>
          <Info.Data>
            <Info.DataLabel>
              {t("frontend.session.client_id_label")}
            </Info.DataLabel>
            <Info.DataValue>
              <code>{data.client.clientId}</code>
            </Info.DataValue>
          </Info.Data>
          <Info.Data>
            <Info.DataLabel>{t("frontend.session.uri_label")}</Info.DataLabel>
            <Info.DataValue>
              <a
                target="_blank"
                rel="noreferrer"
                href={data.client.clientUri || undefined}
              >
                {data.client.clientUri}
              </a>
            </Info.DataValue>
          </Info.Data>
        </Info.DataList>
      </Info.DataSection>

      {!data.finishedAt && <EndOAuth2SessionButton session={data} size="lg" />}
    </div>
  );
};

export default OAuth2SessionDetail;
