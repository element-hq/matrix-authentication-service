// Copyright 2024 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import IconKeyOffSolid from "@vector-im/compound-design-tokens/assets/web/icons/key-off-solid";
import { Text } from "@vector-im/compound-web";
import { useTranslation } from "react-i18next";
import PageHeading from "../components/PageHeading";

export const Route = createFileRoute({
  component: () => {
    const { t } = useTranslation();
    return (
      <>
        <PageHeading
          Icon={IconKeyOffSolid}
          title={t("frontend.reset_cross_signing.cancelled.heading")}
          invalid
        />
        <Text className="text-center text-secondary" size="lg">
          {t("frontend.reset_cross_signing.cancelled.description_1")}
        </Text>
        <Text className="text-center text-secondary" size="lg">
          {t("frontend.reset_cross_signing.cancelled.description_2")}
        </Text>
      </>
    );
  },
});
