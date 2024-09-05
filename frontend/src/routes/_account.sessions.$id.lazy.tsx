// Copyright (C) 2024 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { createLazyFileRoute, notFound } from "@tanstack/react-router";
import { Alert } from "@vector-im/compound-web";
import { useTranslation } from "react-i18next";
import { useQuery } from "urql";

import { Link } from "../components/Link";
import BrowserSessionDetail from "../components/SessionDetail/BrowserSessionDetail";
import CompatSessionDetail from "../components/SessionDetail/CompatSessionDetail";
import OAuth2SessionDetail from "../components/SessionDetail/OAuth2SessionDetail";

import { QUERY } from "./_account.sessions.$id";

export const Route = createLazyFileRoute("/_account/sessions/$id")({
  notFoundComponent: NotFound,
  component: SessionDetail,
});

function NotFound(): React.ReactElement {
  const { id } = Route.useParams();
  const { t } = useTranslation();

  return (
    <Alert
      type="critical"
      title={t("frontend.session_detail.alert.title", { deviceId: id })}
    >
      {t("frontend.session_detail.alert.text")}
      <Link to="/sessions" search={{ first: 6 }}>
        {t("frontend.session_detail.alert.button")}
      </Link>
    </Alert>
  );
}

function SessionDetail(): React.ReactElement {
  const { id } = Route.useParams();
  const [result] = useQuery({ query: QUERY, variables: { id } });
  if (result.error) throw result.error;
  const node = result.data?.node;
  if (!node) throw notFound();
  const currentSessionId = result.data?.viewerSession?.id;

  switch (node.__typename) {
    case "CompatSession":
      return <CompatSessionDetail session={node} />;
    case "Oauth2Session":
      return <OAuth2SessionDetail session={node} />;
    case "BrowserSession":
      return (
        <BrowserSessionDetail
          session={node}
          isCurrent={node.id === currentSessionId}
        />
      );
    default:
      throw new Error("Unknown session type");
  }
}
