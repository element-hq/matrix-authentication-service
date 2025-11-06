// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { type FragmentType, graphql, useFragment } from "../../gql";
import type { DeviceType, Oauth2ApplicationType } from "../../gql/graphql";
import { graphqlRequest } from "../../graphql";
import * as Card from "../SessionCard";
import EndSessionButton from "./EndSessionButton";

const FRAGMENT = graphql(/* GraphQL */ `
  fragment EndOAuth2SessionButton_session on Oauth2Session {
    id

    userAgent {
      name
      model
      os
      deviceType
    }

    client {
      clientId
      clientName
      applicationType
      logoUri
    }
  }
`);

const END_SESSION_MUTATION = graphql(/* GraphQL */ `
  mutation EndOAuth2Session($id: ID!) {
    endOauth2Session(input: { oauth2SessionId: $id }) {
      status
      oauth2Session {
        id
      }
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
  size: "sm" | "lg";
};

const EndOAuth2SessionButton: React.FC<Props> = ({ session, size }) => {
  const { t } = useTranslation();
  const data = useFragment(FRAGMENT, session);
  const queryClient = useQueryClient();
  const endSession = useMutation({
    mutationFn: () =>
      graphqlRequest({
        query: END_SESSION_MUTATION,
        variables: { id: data.id },
      }),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["sessionsOverview"] });
      queryClient.invalidateQueries({ queryKey: ["appSessionList"] });
      queryClient.invalidateQueries({
        queryKey: ["sessionDetail", data.endOauth2Session.oauth2Session?.id],
      });
    },
  });

  const deviceType =
    (data.userAgent?.deviceType === "UNKNOWN"
      ? null
      : data.userAgent?.deviceType) ??
    getDeviceTypeFromClientAppType(data.client.applicationType);

  const clientName = data.client.clientName || data.client.clientId;

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

  return (
    <EndSessionButton mutation={endSession} size={size}>
      <Card.Body compact>
        <Card.Header type={deviceType}>
          <Card.Name name={deviceName} />
          <Card.Client
            name={clientName}
            logoUri={data.client.logoUri ?? undefined}
          />
        </Card.Header>
      </Card.Body>
    </EndSessionButton>
  );
};

export default EndOAuth2SessionButton;
