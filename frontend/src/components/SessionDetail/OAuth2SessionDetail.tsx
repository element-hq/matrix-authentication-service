// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { parseISO } from "date-fns";
import { useTranslation } from "react-i18next";
import { type FragmentType, graphql, useFragment } from "../../gql";
import { graphqlRequest } from "../../graphql";
import { getDeviceIdFromScope } from "../../utils/deviceIdFromScope";
import BlockList from "../BlockList/BlockList";
import DateTime from "../DateTime";
import { Link } from "../Link";
import { END_SESSION_MUTATION } from "../OAuth2Session";
import ClientAvatar from "../Session/ClientAvatar";
import EndSessionButton from "../Session/EndSessionButton";
import SessionDetails from "./SessionDetails";
import SessionHeader from "./SessionHeader";

export const FRAGMENT = graphql(/* GraphQL */ `
  fragment OAuth2Session_detail on Oauth2Session {
    id
    scope
    createdAt
    finishedAt
    lastActiveIp
    lastActiveAt
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
  const queryClient = useQueryClient();
  const endSession = useMutation({
    mutationFn: (id: string) =>
      graphqlRequest({ query: END_SESSION_MUTATION, variables: { id } }),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["sessionsOverview"] });
      queryClient.invalidateQueries({ queryKey: ["appSessionList"] });
      queryClient.invalidateQueries({
        queryKey: ["sessionDetail", data.endOauth2Session.oauth2Session?.id],
      });
    },
  });

  const { t } = useTranslation();

  const onSessionEnd = async (): Promise<void> => {
    await endSession.mutateAsync(data.id);
  };

  const deviceId = getDeviceIdFromScope(data.scope);

  const finishedAt = data.finishedAt
    ? [
        {
          label: t("frontend.session.finished_label"),
          value: <DateTime datetime={parseISO(data.finishedAt)} />,
        },
      ]
    : [];

  const sessionDetails = [...finishedAt];

  const clientTitle = (
    <Link to="/clients/$id" params={{ id: data.client.id }}>
      {t("frontend.oauth2_session_detail.client_title")}
    </Link>
  );
  const clientDetails = [
    {
      label: t("frontend.oauth2_session_detail.client_details_name"),
      value: (
        <>
          <ClientAvatar
            name={data.client.clientName || data.client.clientId}
            logoUri={data.client.logoUri || undefined}
            size="var(--cpd-space-4x)"
          />
          {data.client.clientName}
        </>
      ),
    },
    {
      label: t("frontend.session.client_id_label"),
      value: <code>{data.client.clientId}</code>,
    },
    {
      label: t("frontend.session.uri_label"),
      value: (
        <a
          target="_blank"
          rel="noreferrer"
          href={data.client.clientUri || undefined}
        >
          {data.client.clientUri}
        </a>
      ),
    },
  ];

  return (
    <BlockList>
      <SessionHeader to="/sessions">{deviceId || data.id}</SessionHeader>
      <SessionDetails
        title={t("frontend.session.title")}
        lastActive={data.lastActiveAt ? parseISO(data.lastActiveAt) : undefined}
        signedIn={parseISO(data.createdAt)}
        deviceId={deviceId}
        ipAddress={data.lastActiveIp ?? undefined}
        scopes={data.scope.split(" ")}
        details={sessionDetails}
      />
      <SessionDetails title={clientTitle} details={clientDetails} />
      {!data.finishedAt && <EndSessionButton endSession={onSessionEnd} />}
    </BlockList>
  );
};

export default OAuth2SessionDetail;
