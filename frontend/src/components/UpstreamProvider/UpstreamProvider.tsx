// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import IconUserAdd from "@vector-im/compound-design-tokens/assets/web/icons/user-add";
import { Button } from "@vector-im/compound-web";
import { useState } from "react";

import { FragmentType, graphql, useFragment } from "../../gql";
import LoadingSpinner from "../LoadingSpinner";

const FRAGMENT = graphql(/* GraphQL */ `
  fragment UpstreamProvider_provider on UpstreamOAuth2Provider {
    id
    createdAt
    humanName
    upstreamOauth2LinksForUser {
      id
      provider {
        id
      }
    }
  }
`);

const UpstreamProvider: React.FC<{
  upstreamProvider: FragmentType<typeof FRAGMENT>;
  disabled?: boolean;
}> = ({ upstreamProvider, disabled }) => {
  const data = useFragment(FRAGMENT, upstreamProvider);
  const [inProgress, setInProgress] = useState(false);

  const onConfirm = async (
    e: React.MouseEvent<HTMLButtonElement>,
  ): Promise<void> => {
    e.preventDefault();

    setInProgress(true);
    const upstreamURL = `/upstream/authorize/${data.id.replace("upstream_oauth2_provider:", "")}`;
    window.location.replace(upstreamURL);
    setInProgress(false);
  };

  return (
    <>
      <Button
        type="button"
        kind="primary"
        onClick={onConfirm}
        disabled={disabled ?? inProgress}
        Icon={disabled ?? inProgress ? undefined : IconUserAdd}
      >
        {inProgress && <LoadingSpinner inline />}
        {data?.humanName ?? "Unknown"}
      </Button>
    </>
  );
};

export default UpstreamProvider;
