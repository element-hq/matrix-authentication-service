// Copyright 2024 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import IconUserAdd from "@vector-im/compound-design-tokens/assets/web/icons/user-add";
import { Button } from "@vector-im/compound-web";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import GoogleLogo from "./logos/google";
import GithubLogo from "./logos/github";
import GitlabLogo from "./logos/gitlab";
import TwitterLogo from "./logos/twitter";
import FacebookLogo from "./logos/facebook";
import AppleLogo from "./logos/apple";

import { FragmentType, graphql, useFragment } from "../../gql";
import LoadingSpinner from "../LoadingSpinner";

const FRAGMENT = graphql(/* GraphQL */ `
  fragment LinkUpstreamProvider_provider on UpstreamOAuth2Provider {
    id
    humanName
    brandName
  }
`);

const LinkUpstreamProvider: React.FC<{
  upstreamProvider: FragmentType<typeof FRAGMENT>;
  disabled?: boolean;
}> = ({ upstreamProvider, disabled }) => {
  const data = useFragment(FRAGMENT, upstreamProvider);
  const [inProgress, setInProgress] = useState(false);
  const { t } = useTranslation();

  const onConfirm = async (
    e: React.MouseEvent<HTMLButtonElement>,
  ): Promise<void> => {
    e.preventDefault();

    setInProgress(true);
    const upstreamURL = `/upstream/authorize/${data.id.replace("upstream_oauth2_provider:", "")}`;
    window.location.replace(upstreamURL);
    setInProgress(false);
  };

  // Pick the right svg from the brand name
  //
  // Supported upstream providers:
  // - Google
  // - GitHub
  // - GitLab
  // - Twitter
  // - Facebook
  // - Apple
  const logo = (function (brandName?: string | null) {
    if (!brandName) {
      return null;
    }
    if (brandName.toLowerCase() === "google") {
      return GoogleLogo;
    } else if (brandName.toLowerCase() === "github") {
      return GithubLogo;
    } else if (brandName.toLowerCase() === "gitlab") {
      return GitlabLogo;
    } else if (brandName.toLowerCase() === "twitter") {
      return TwitterLogo;
    } else if (brandName.toLowerCase() === "facebook") {
      return FacebookLogo;
    } else if (brandName.toLowerCase() === "apple") {
      return AppleLogo;
    }
  })(data.brandName);

  return (
    <>
      <Button
        type="button"
        kind="primary"
        onClick={onConfirm}
        disabled={disabled ?? inProgress}
        Icon={(disabled ?? inProgress) ? undefined : (logo ?? IconUserAdd)}
      >
        {inProgress && <LoadingSpinner inline />}
        {t("frontend.link_upstream_button.text", {
          provider: data?.humanName ?? "Unknown",
        })}
      </Button>
    </>
  );
};

export default LinkUpstreamProvider;
