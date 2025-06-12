// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import {
  type UseMutationResult,
  useMutation,
  useQueryClient,
} from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { type FragmentType, graphql, useFragment } from "../../gql";
import { graphqlRequest } from "../../graphql";
import * as Card from "../SessionCard";
import EndSessionButton from "./EndSessionButton";

const FRAGMENT = graphql(/* GraphQL */ `
  fragment EndBrowserSessionButton_session on BrowserSession {
    id
    userAgent {
      name
      os
      model
      deviceType
    }
  }
`);

const END_SESSION_MUTATION = graphql(/* GraphQL */ `
  mutation EndBrowserSession($id: ID!) {
    endBrowserSession(input: { browserSessionId: $id }) {
      status
      browserSession {
        id
      }
    }
  }
`);

export const useEndBrowserSession = (
  sessionId: string,
  isCurrent: boolean,
): UseMutationResult<unknown, unknown, void> => {
  const queryClient = useQueryClient();
  const endSession = useMutation({
    mutationFn: () =>
      graphqlRequest({
        query: END_SESSION_MUTATION,
        variables: { id: sessionId },
      }),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["sessionsOverview"] });
      queryClient.invalidateQueries({ queryKey: ["browserSessionList"] });
      queryClient.invalidateQueries({
        queryKey: ["sessionDetail", data.endBrowserSession.browserSession?.id],
      });

      if (isCurrent) {
        window.location.reload();
      }
    },
  });

  return endSession;
};

type Props = {
  session: FragmentType<typeof FRAGMENT>;
  size: "sm" | "lg";
};

const EndBrowserSessionButton: React.FC<Props> = ({ session, size }) => {
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
        queryKey: ["sessionDetail", data.endBrowserSession.browserSession?.id],
      });
    },
  });

  const deviceType = data.userAgent?.deviceType ?? "UNKNOWN";

  let deviceName: string | null = null;
  let clientName: string | null = null;

  // If we have a model, use that as the device name, and the browser (+ OS) as the client name
  if (data.userAgent?.model) {
    deviceName = data.userAgent.model;
    if (data.userAgent?.name) {
      if (data.userAgent?.os) {
        clientName = t("frontend.session.name_for_platform", {
          name: data.userAgent.name,
          platform: data.userAgent.os,
        });
      } else {
        clientName = data.userAgent.name;
      }
    }
  } else {
    // Else use the browser as the device name
    deviceName = data.userAgent?.name ?? t("frontend.session.unknown_browser");
    // and if we have an OS, use that as the client name
    clientName = data.userAgent?.os ?? null;
  }

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

export default EndBrowserSessionButton;
