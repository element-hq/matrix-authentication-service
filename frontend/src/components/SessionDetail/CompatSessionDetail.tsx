// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { parseISO } from "date-fns";
import { useTranslation } from "react-i18next";
import { useMutation } from "urql";

import { FragmentType, graphql, useFragment } from "../../gql";
import BlockList from "../BlockList/BlockList";
import { END_SESSION_MUTATION, simplifyUrl } from "../CompatSession";
import DateTime from "../DateTime";
import ExternalLink from "../ExternalLink/ExternalLink";
import EndSessionButton from "../Session/EndSessionButton";

import SessionDetails from "./SessionDetails";
import SessionHeader from "./SessionHeader";

export const FRAGMENT = graphql(/* GraphQL */ `
  fragment CompatSession_detail on CompatSession {
    id
    createdAt
    deviceId
    finishedAt
    lastActiveIp
    lastActiveAt
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
  const [, endSession] = useMutation(END_SESSION_MUTATION);
  const { t } = useTranslation();

  const onSessionEnd = async (): Promise<void> => {
    await endSession({ id: data.id });
  };

  const finishedAt = data.finishedAt
    ? [
        {
          label: t("frontend.session.finished_label"),
          value: <DateTime datetime={parseISO(data.finishedAt)} />,
        },
      ]
    : [];

  const sessionDetails = [...finishedAt];

  const clientDetails: { label: string; value: string | JSX.Element }[] = [];

  if (data.ssoLogin?.redirectUri) {
    clientDetails.push({
      label: t("frontend.compat_session_detail.name"),
      value: data.userAgent?.name ?? simplifyUrl(data.ssoLogin.redirectUri),
    });
    clientDetails.push({
      label: t("frontend.session.uri_label"),
      value: (
        <ExternalLink target="_blank" href={data.ssoLogin?.redirectUri}>
          {data.ssoLogin?.redirectUri}
        </ExternalLink>
      ),
    });
  }

  return (
    <BlockList>
      <SessionHeader to="/sessions">{data.deviceId || data.id}</SessionHeader>
      <SessionDetails
        title={t("frontend.compat_session_detail.session_details_title")}
        deviceId={data.deviceId}
        signedIn={parseISO(data.createdAt)}
        lastActive={data.lastActiveAt ? parseISO(data.lastActiveAt) : undefined}
        ipAddress={data.lastActiveIp ?? undefined}
        details={sessionDetails}
        // These scopes need to be kept in sync with `templates/pages/sso.html`
        scopes={["openid", "urn:matrix:org.matrix.msc2967.client:api:*"]}
      />
      {clientDetails.length > 0 ? (
        <SessionDetails
          title={t("frontend.compat_session_detail.client_details_title")}
          details={clientDetails}
        />
      ) : null}
      {!data.finishedAt && <EndSessionButton endSession={onSessionEnd} />}
    </BlockList>
  );
};

export default CompatSessionDetail;
