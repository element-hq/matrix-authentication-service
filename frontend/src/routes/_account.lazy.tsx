// Copyright 2024 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { Outlet, createLazyFileRoute, notFound } from "@tanstack/react-router";
import { Heading } from "@vector-im/compound-web";
import { useTranslation } from "react-i18next";

import { useEndBrowserSession } from "../components/BrowserSession";
import Layout from "../components/Layout";
import NavBar from "../components/NavBar";
import NavItem from "../components/NavItem";
import EndSessionButton from "../components/Session/EndSessionButton";
import UnverifiedEmailAlert from "../components/UnverifiedEmailAlert";
import UserGreeting from "../components/UserGreeting";

import { useSuspenseQuery } from "@tanstack/react-query";
import { query } from "./_account";

export const Route = createLazyFileRoute("/_account")({
  component: Account,
});

function Account(): React.ReactElement {
  const { t } = useTranslation();
  const result = useSuspenseQuery(query);
  const session = result.data.viewerSession;
  if (session?.__typename !== "BrowserSession") throw notFound();
  const siteConfig = result.data.siteConfig;
  const onSessionEnd = useEndBrowserSession(session.id, true);

  return (
    <Layout wide>
      <div className="flex flex-col gap-4">
        <header className="flex justify-between mb-4">
          <Heading size="lg" weight="semibold">
            {t("frontend.account.title")}
          </Heading>

          <EndSessionButton endSession={onSessionEnd} />
        </header>

        <UserGreeting user={session.user} siteConfig={siteConfig} />

        <UnverifiedEmailAlert user={session.user} />

        <NavBar>
          <NavItem to="/">{t("frontend.nav.settings")}</NavItem>
          <NavItem to="/sessions">{t("frontend.nav.devices")}</NavItem>
        </NavBar>
      </div>

      <Outlet />
    </Layout>
  );
}
