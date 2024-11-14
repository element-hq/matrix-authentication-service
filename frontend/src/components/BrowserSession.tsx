// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import IconChrome from "@browser-logos/chrome/chrome_64x64.png?url";
import IconFirefox from "@browser-logos/firefox/firefox_64x64.png?url";
import IconSafari from "@browser-logos/safari/safari_64x64.png?url";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Badge } from "@vector-im/compound-web";
import { parseISO } from "date-fns";
import { useCallback } from "react";
import { useTranslation } from "react-i18next";
import { type FragmentType, graphql, useFragment } from "../gql";
import { graphqlRequest } from "../graphql";
import DateTime from "./DateTime";
import EndSessionButton from "./Session/EndSessionButton";
import LastActive from "./Session/LastActive";
import * as Card from "./SessionCard";

const FRAGMENT = graphql(/* GraphQL */ `
  fragment BrowserSession_session on BrowserSession {
    id
    createdAt
    finishedAt
    userAgent {
      raw
      name
      os
      model
      deviceType
    }
    lastActiveIp
    lastActiveAt
    lastAuthentication {
      id
      createdAt
    }
  }
`);

const END_SESSION_MUTATION = graphql(/* GraphQL */ `
  mutation EndBrowserSession($id: ID!) {
    endBrowserSession(input: { browserSessionId: $id }) {
      status
      browserSession {
        id
        ...BrowserSession_session
      }
    }
  }
`);

export const useEndBrowserSession = (
  sessionId: string,
  isCurrent: boolean,
): (() => Promise<void>) => {
  const queryClient = useQueryClient();
  const endSession = useMutation({
    mutationFn: (id: string) =>
      graphqlRequest({ query: END_SESSION_MUTATION, variables: { id } }),
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

  const onSessionEnd = useCallback(async (): Promise<void> => {
    await endSession.mutateAsync(sessionId);
  }, [endSession.mutateAsync, sessionId]);

  return onSessionEnd;
};

export const browserLogoUri = (browser?: string): string | undefined => {
  const lcBrowser = browser?.toLowerCase();

  if (lcBrowser?.includes("chrome") || lcBrowser?.includes("chromium")) {
    return IconChrome;
  }

  if (lcBrowser?.includes("firefox")) {
    return IconFirefox;
  }

  if (lcBrowser?.includes("safari")) {
    return IconSafari;
  }
};

type Props = {
  session: FragmentType<typeof FRAGMENT>;
  isCurrent: boolean;
};

const BrowserSession: React.FC<Props> = ({ session, isCurrent }) => {
  const data = useFragment(FRAGMENT, session);
  const { t } = useTranslation();

  const onSessionEnd = useEndBrowserSession(data.id, isCurrent);

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
          {lastActiveAt && !isCurrent && (
            <Card.Info label={t("frontend.session.last_active_label")}>
              <LastActive lastActive={lastActiveAt} />
            </Card.Info>
          )}

          <Card.Info label={t("frontend.session.signed_in_label")}>
            <DateTime datetime={createdAt} />
          </Card.Info>

          {isCurrent && (
            <Badge kind="green" className="self-center">
              {t("frontend.session.current")}
            </Badge>
          )}
        </Card.Metadata>
      </Card.LinkBody>

      {!data.finishedAt && (
        <Card.Action>
          <EndSessionButton endSession={onSessionEnd}>
            <Card.Body compact>
              <Card.Header type={deviceType}>
                <Card.Name name={deviceName} />
                {clientName && <Card.Client name={clientName} />}
              </Card.Header>
            </Card.Body>
          </EndSessionButton>
        </Card.Action>
      )}
    </Card.Root>
  );
};

export default BrowserSession;
