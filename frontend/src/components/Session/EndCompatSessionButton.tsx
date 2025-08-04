// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { type FragmentType, graphql, useFragment } from "../../gql";
import { graphqlRequest } from "../../graphql";
import simplifyUrl from "../../utils/simplifyUrl";
import * as Card from "../SessionCard";
import EndSessionButton from "./EndSessionButton";

const FRAGMENT = graphql(/* GraphQL */ `
  fragment EndCompatSessionButton_session on CompatSession {
    id
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

const END_SESSION_MUTATION = graphql(/* GraphQL */ `
  mutation EndCompatSession($id: ID!) {
    endCompatSession(input: { compatSessionId: $id }) {
      status
      compatSession {
        id
      }
    }
  }
`);

type Props = {
  session: FragmentType<typeof FRAGMENT>;
  size: "sm" | "lg";
};

const EndCompatSessionButton: React.FC<Props> = ({ session, size }) => {
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
        queryKey: ["sessionDetail", data.endCompatSession.compatSession?.id],
      });
    },
  });

  const clientName = data.ssoLogin?.redirectUri
    ? simplifyUrl(data.ssoLogin.redirectUri)
    : undefined;

  const deviceType = data.userAgent?.deviceType ?? "UNKNOWN";

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
          {clientName && <Card.Client name={clientName} />}
        </Card.Header>
      </Card.Body>
    </EndSessionButton>
  );
};

export default EndCompatSessionButton;
