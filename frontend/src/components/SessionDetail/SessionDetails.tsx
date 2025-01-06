// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import IconChat from "@vector-im/compound-design-tokens/assets/web/icons/chat";
import IconComputer from "@vector-im/compound-design-tokens/assets/web/icons/computer";
import IconError from "@vector-im/compound-design-tokens/assets/web/icons/error";
import IconInfo from "@vector-im/compound-design-tokens/assets/web/icons/info";
import IconSend from "@vector-im/compound-design-tokens/assets/web/icons/send";
import IconUserProfile from "@vector-im/compound-design-tokens/assets/web/icons/user-profile";
import { Text } from "@vector-im/compound-web";
import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";

import Block from "../Block/Block";
import DateTime from "../DateTime";
import LastActive from "../Session/LastActive";
import { VisualList, VisualListItem } from "../VisualList/VisualList";

import styles from "./SessionDetails.module.css";

type Detail = { label: string; value: ReactNode };
type Props = {
  title: string | ReactNode;
  lastActive?: Date;
  signedIn?: Date;
  deviceId?: string;
  ipAddress?: string;
  scopes?: string[];
  details?: Detail[];
};

const Scope: React.FC<{ scope: string }> = ({ scope }) => {
  const { t } = useTranslation();
  // Filter out "urn:matrix:org.matrix.msc2967.client:device:"
  if (scope.startsWith("urn:matrix:org.matrix.msc2967.client:device:")) {
    return null;
  }

  // Needs to be manually kept in sync with /templates/components/scope.html
  const scopeMap: Record<string, [number, typeof IconInfo, string][]> = {
    openid: [[0, IconUserProfile, t("mas.scope.view_profile")]],
    "urn:mas:graphql:*": [
      [1, IconInfo, t("mas.scope.edit_profile")],
      [2, IconComputer, t("mas.scope.manage_sessions")],
    ],
    "urn:matrix:org.matrix.msc2967.client:api:*": [
      [3, IconChat, t("mas.scope.view_messages")],
      [4, IconSend, t("mas.scope.send_messages")],
    ],
    "urn:synapse:admin:*": [[5, IconError, t("mas.scope.synapse_admin")]],
    "urn:mas:admin": [[6, IconError, t("mas.scope.mas_admin")]],
  } as const;

  const mappedScopes: [number | string, typeof IconInfo, string][] = scopeMap[
    scope
  ] ?? [[scope, IconInfo, scope]];

  return (
    <>
      {mappedScopes.map(([key, Icon, text]) => (
        <VisualListItem key={key} Icon={Icon} label={text} />
      ))}
    </>
  );
};

const Datum: React.FC<{ label: string; value: ReactNode }> = ({
  label,
  value,
}) => {
  return (
    <div className={styles.datum}>
      <Text size="sm" weight="regular" as="h5">
        {label}
      </Text>
      {typeof value === "string" ? (
        <Text size="md" className={styles.datumValue}>
          {value}
        </Text>
      ) : (
        value
      )}
    </div>
  );
};

const SessionDetails: React.FC<Props> = ({
  title,
  lastActive,
  signedIn,
  deviceId,
  ipAddress,
  details,
  scopes,
}) => {
  const { t } = useTranslation();

  return (
    <Block title={title}>
      <div className={styles.wrapper}>
        {lastActive && (
          <Datum
            label={t("frontend.session.last_active_label")}
            value={
              <LastActive
                className={styles.datumValue}
                lastActive={lastActive}
              />
            }
          />
        )}
        {signedIn && (
          <Datum
            label={t("frontend.session.signed_in_label")}
            value={
              <DateTime className={styles.datumValue} datetime={signedIn} />
            }
          />
        )}
        {deviceId && (
          <Datum
            label={t("frontend.session.device_id_label")}
            value={deviceId}
          />
        )}
        {ipAddress && (
          <Datum
            label={t("frontend.session.ip_label")}
            value={<code className={styles.datumValue}>{ipAddress}</code>}
          />
        )}
        {details?.map(({ label, value }) => (
          <Datum key={label} label={label} value={value} />
        ))}
      </div>

      {scopes?.length && (
        <Datum
          label={t("frontend.session.scopes_label")}
          value={
            <VisualList>
              {scopes.map((scope) => (
                <Scope key={scope} scope={scope} />
              ))}
            </VisualList>
          }
        />
      )}
    </Block>
  );
};

export default SessionDetails;
