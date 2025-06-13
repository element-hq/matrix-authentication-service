// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import { Badge } from "@vector-im/compound-web";
import { parseISO } from "date-fns";
import { useTranslation } from "react-i18next";
import { type FragmentType, graphql, useFragment } from "../../gql";
import DateTime from "../DateTime";
import EndBrowserSessionButton from "../Session/EndBrowserSessionButton";
import LastActive from "../Session/LastActive";
import SessionHeader from "./SessionHeader";
import * as Info from "./SessionInfo";

const FRAGMENT = graphql(/* GraphQL */ `
  fragment BrowserSession_detail on BrowserSession {
    id
    createdAt
    finishedAt
    ...EndBrowserSessionButton_session
    userAgent {
      name
      model
      os
    }
    lastActiveIp
    lastActiveAt
    lastAuthentication {
      id
      createdAt
    }
    user {
      id
      username
    }
  }
`);

type Props = {
  session: FragmentType<typeof FRAGMENT>;
  isCurrent: boolean;
};

const BrowserSessionDetail: React.FC<Props> = ({ session, isCurrent }) => {
  const data = useFragment(FRAGMENT, session);
  const { t } = useTranslation();

  let sessionName = t("frontend.session.generic_browser_session");
  if (data.userAgent) {
    if (data.userAgent.model && data.userAgent.name) {
      sessionName = t("frontend.session.name_for_platform", {
        name: data.userAgent.name,
        platform: data.userAgent.model,
      });
    } else if (data.userAgent.name && data.userAgent.os) {
      sessionName = t("frontend.session.name_for_platform", {
        name: data.userAgent.name,
        platform: data.userAgent.os,
      });
    } else if (data.userAgent.name) {
      sessionName = data.userAgent.name;
    }
  }

  return (
    <div className="flex flex-col gap-10">
      {isCurrent && (
        <Badge className="self-start" kind="green">
          {t("frontend.browser_session_details.current_badge")}
        </Badge>
      )}
      <SessionHeader to="/sessions/browsers">{sessionName}</SessionHeader>
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

          {data.lastActiveIp && (
            <Info.Data>
              <Info.DataLabel>{t("frontend.session.ip_label")}</Info.DataLabel>
              <Info.DataValue>
                <code>{data.lastActiveIp}</code>
              </Info.DataValue>
            </Info.Data>
          )}
        </Info.DataList>
      </Info.DataSection>
      {!data.finishedAt && <EndBrowserSessionButton session={data} size="lg" />}
    </div>
  );
};

export default BrowserSessionDetail;
