// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { VisualList } from "@vector-im/compound-web";
import { parseISO } from "date-fns";
import { useTranslation } from "react-i18next";
import { type FragmentType, graphql, useFragment } from "../../gql";
import { graphqlRequest } from "../../graphql";
import simplifyUrl from "../../utils/simplifyUrl";
import DateTime from "../DateTime";
import EndCompatSessionButton from "../Session/EndCompatSessionButton";
import LastActive from "../Session/LastActive";
import EditSessionName from "./EditSessionName";
import SessionHeader from "./SessionHeader";
import * as Info from "./SessionInfo";

const SET_SESSION_NAME_MUTATION = graphql(/* GraphQL */ `
  mutation SetCompatSessionName($sessionId: ID!, $displayName: String!) {
    setCompatSessionName(input: { compatSessionId: $sessionId, humanName: $displayName }) {
      status
    }
  }
`);

export const FRAGMENT = graphql(/* GraphQL */ `
  fragment CompatSession_detail on CompatSession {
    id
    createdAt
    deviceId
    finishedAt
    lastActiveIp
    lastActiveAt
    humanName

    ...EndCompatSessionButton_session

    userAgent {
      name
      os
      model
    }

    ssoLogin {
      id
      redirectUri
    }
  }
`);

type Props = {
  session: FragmentType<typeof FRAGMENT>;
};

const CompatSessionDetail: React.FC<Props> = ({ session }) => {
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

  const deviceName =
    data.userAgent?.model ??
    (data.userAgent?.name
      ? data.userAgent?.os
        ? t("frontend.session.name_for_platform", {
            name: data.userAgent.name,
            platform: data.userAgent.os,
          })
        : data.userAgent.name
      : t("frontend.session.unknown_device"));

  const clientName = data.ssoLogin?.redirectUri
    ? simplifyUrl(data.ssoLogin.redirectUri)
    : data.deviceId || data.id;

  const sessionName = data.humanName ?? `${clientName}: ${deviceName}`;

  return (
    <div className="flex flex-col gap-10">
      <SessionHeader to="/sessions">
        {sessionName}
        <EditSessionName mutation={setDisplayName} deviceName={sessionName} />
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
            <Info.DataValue>{data.deviceId}</Info.DataValue>
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
          <VisualList className="mt-1">
            <Info.ScopeViewProfile />
            <Info.ScopeViewMessages />
            <Info.ScopeSendMessages />
          </VisualList>
        </Info.Data>
      </Info.DataSection>

      <Info.DataSection>
        <Info.DataSectionHeader>
          {t("frontend.compat_session_detail.client_details_title")}
        </Info.DataSectionHeader>
        <Info.DataList>
          <Info.Data>
            <Info.DataLabel>
              {t("frontend.compat_session_detail.name")}
            </Info.DataLabel>
            <Info.DataValue>{deviceName}</Info.DataValue>
          </Info.Data>
          {data.ssoLogin && (
            <Info.Data>
              <Info.DataLabel>{t("frontend.session.uri_label")}</Info.DataLabel>
              <Info.DataValue>{data.ssoLogin?.redirectUri}</Info.DataValue>
            </Info.Data>
          )}
        </Info.DataList>
      </Info.DataSection>

      {!data.finishedAt && <EndCompatSessionButton session={data} size="lg" />}
    </div>
  );
};

export default CompatSessionDetail;
