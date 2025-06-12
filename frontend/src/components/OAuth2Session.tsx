// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import { parseISO } from "date-fns";
import { useTranslation } from "react-i18next";
import { type FragmentType, graphql, useFragment } from "../gql";
import type { DeviceType, Oauth2ApplicationType } from "../gql/graphql";
import { getDeviceIdFromScope } from "../utils/deviceIdFromScope";
import DateTime from "./DateTime";
import EndOAuth2SessionButton from "./Session/EndOAuth2SessionButton";
import LastActive from "./Session/LastActive";
import * as Card from "./SessionCard";

export const FRAGMENT = graphql(/* GraphQL */ `
  fragment OAuth2Session_session on Oauth2Session {
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
      deviceType
    }

    client {
      id
      clientId
      clientName
      applicationType
      logoUri
    }
  }
`);

const getDeviceTypeFromClientAppType = (
  appType?: Oauth2ApplicationType | null,
): DeviceType => {
  if (appType === "WEB") {
    return "PC";
  }
  if (appType === "NATIVE") {
    return "MOBILE";
  }
  return "UNKNOWN";
};

type Props = {
  session: FragmentType<typeof FRAGMENT>;
};

const OAuth2Session: React.FC<Props> = ({ session }) => {
  const { t } = useTranslation();
  const data = useFragment(FRAGMENT, session);

  const deviceId = getDeviceIdFromScope(data.scope);

  const createdAt = parseISO(data.createdAt);
  const lastActiveAt = data.lastActiveAt
    ? parseISO(data.lastActiveAt)
    : undefined;

  const deviceType =
    (data.userAgent?.deviceType === "UNKNOWN"
      ? null
      : data.userAgent?.deviceType) ??
    getDeviceTypeFromClientAppType(data.client.applicationType);

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
    <Card.Root>
      <Card.LinkBody
        to="/sessions/$id"
        params={{ id: data.id }}
        disabled={!!data.finishedAt}
      >
        <Card.Header type={deviceType}>
          <Card.Name name={deviceName} />
          <Card.Client
            name={clientName}
            logoUri={data.client.logoUri ?? undefined}
          />
        </Card.Header>

        <Card.Metadata>
          {lastActiveAt && (
            <Card.Info label={t("frontend.session.last_active_label")}>
              <LastActive lastActive={lastActiveAt} />
            </Card.Info>
          )}
          <Card.Info label={t("frontend.session.signed_in_label")}>
            <DateTime datetime={createdAt} />
          </Card.Info>
          {deviceId && (
            <Card.Info label={t("frontend.session.device_id_label")}>
              {deviceId}
            </Card.Info>
          )}
        </Card.Metadata>
      </Card.LinkBody>

      {!data.finishedAt && (
        <Card.Action>
          <EndOAuth2SessionButton session={data} size="sm" />
        </Card.Action>
      )}
    </Card.Root>
  );
};

export default OAuth2Session;
