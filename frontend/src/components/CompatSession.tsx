// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { parseISO } from "date-fns";
import { useTranslation } from "react-i18next";
import { type FragmentType, graphql, useFragment } from "../gql";
import simplifyUrl from "../utils/simplifyUrl";
import { browserLogoUri } from "./BrowserSession";
import DateTime from "./DateTime";
import EndCompatSessionButton from "./Session/EndCompatSessionButton";
import LastActive from "./Session/LastActive";
import * as Card from "./SessionCard";

export const FRAGMENT = graphql(/* GraphQL */ `
  fragment CompatSession_session on CompatSession {
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
      deviceType
    }
    ssoLogin {
      id
      redirectUri
    }
  }
`);

const CompatSession: React.FC<{
  session: FragmentType<typeof FRAGMENT>;
}> = ({ session }) => {
  const { t } = useTranslation();
  const data = useFragment(FRAGMENT, session);

  const clientName =
    (data.ssoLogin?.redirectUri
      ? simplifyUrl(data.ssoLogin.redirectUri)
      : undefined);

  const deviceType = data.userAgent?.deviceType ?? "UNKNOWN";

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

  const createdAt = parseISO(data.createdAt);
  const lastActiveAt = data.lastActiveAt
    ? parseISO(data.lastActiveAt)
    : undefined;

  return (
    <Card.Root>
      <Card.LinkBody
        to="/sessions/$id"
        params={{ id: data.id }}
        disabled={!!data.finishedAt}
      >
        <Card.Header type={deviceType}>
          <Card.Name name={deviceName} />
          {clientName && (
            <Card.Client
              name={clientName}
              logoUri={browserLogoUri(data.userAgent?.name ?? undefined)}
            />
          )}
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
          <Card.Info label={t("frontend.session.device_id_label")}>
            {data.deviceId}
          </Card.Info>
        </Card.Metadata>
      </Card.LinkBody>

      {!data.finishedAt && (
        <Card.Action>
          <EndCompatSessionButton session={data} size="sm" />
        </Card.Action>
      )}
    </Card.Root>
  );
};

export default CompatSession;
