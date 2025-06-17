// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import { useSuspenseQuery } from "@tanstack/react-query";
import { notFound, redirect } from "@tanstack/react-router";
import IconArrowLeft from "@vector-im/compound-design-tokens/assets/web/icons/arrow-left";
import IconErrorSolid from "@vector-im/compound-design-tokens/assets/web/icons/error-solid";
import { useTranslation } from "react-i18next";
import { ButtonLink } from "../components/ButtonLink";
import Layout from "../components/Layout";
import PageHeading from "../components/PageHeading";
import { query } from "./emails.$id.verify";

export const Route = createFileRoute({
  async loader({ context, params }): Promise<void> {
    const data = await context.queryClient.ensureQueryData(query(params.id));
    if (!data.userEmailAuthentication) {
      throw notFound();
    }

    // If the user has not completed the verification process, it means they got
    // to this page by mistake
    if (!data.userEmailAuthentication.completedAt) {
      throw redirect({ to: "/emails/$id/verify", params });
    }
  },

  component: EmailInUse,
});

function EmailInUse(): React.ReactElement {
  const { id } = Route.useParams();
  const {
    data: { userEmailAuthentication },
  } = useSuspenseQuery(query(id));
  if (!userEmailAuthentication) throw notFound();
  const { t } = useTranslation();

  return (
    <Layout>
      <PageHeading
        Icon={IconErrorSolid}
        invalid
        title={t("frontend.email_in_use.heading", {
          email: userEmailAuthentication.email,
        })}
      />

      <ButtonLink Icon={IconArrowLeft} kind="tertiary" to="/">
        {t("action.back")}
      </ButtonLink>
    </Layout>
  );
}
