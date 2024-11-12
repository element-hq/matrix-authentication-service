// Copyright 2024 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { createLazyFileRoute, notFound } from "@tanstack/react-router";
import { Alert } from "@vector-im/compound-web";
import { useTranslation } from "react-i18next";

import { Link } from "../components/Link";
import BrowserSessionDetail from "../components/SessionDetail/BrowserSessionDetail";
import CompatSessionDetail from "../components/SessionDetail/CompatSessionDetail";
import OAuth2SessionDetail from "../components/SessionDetail/OAuth2SessionDetail";

import { useSuspenseQuery } from "@tanstack/react-query";
import { query } from "./_account.sessions.$id";

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
      <Link to="/sessions">{t("frontend.session_detail.alert.button")}</Link>
    </Alert>
  );
}

function SessionDetail(): React.ReactElement {
  const { id } = Route.useParams();
  const {
    data: { node, viewerSession },
  } = useSuspenseQuery(query(id));
  if (!node) throw notFound();

  switch (node.__typename) {
    case "CompatSession":
      return <CompatSessionDetail session={node} />;
    case "Oauth2Session":
      return <OAuth2SessionDetail session={node} />;
    case "BrowserSession":
      return (
        <BrowserSessionDetail
          session={node}
          isCurrent={node.id === viewerSession.id}
        />
      );
    default:
      throw new Error("Unknown session type");
  }
}
