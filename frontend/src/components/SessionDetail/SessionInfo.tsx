// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import IconChat from "@vector-im/compound-design-tokens/assets/web/icons/chat";
import IconComputer from "@vector-im/compound-design-tokens/assets/web/icons/computer";
import IconErrorSolid from "@vector-im/compound-design-tokens/assets/web/icons/error-solid";
import IconInfo from "@vector-im/compound-design-tokens/assets/web/icons/info";
import IconSend from "@vector-im/compound-design-tokens/assets/web/icons/send";
import IconUserProfile from "@vector-im/compound-design-tokens/assets/web/icons/user-profile";
import {
  Heading,
  Text,
  VisualList,
  VisualListItem,
} from "@vector-im/compound-web";
import cx from "classnames";
import type * as React from "react";
import { useTranslation } from "react-i18next";
import Separator from "../Separator/Separator";

export const ScopeViewProfile: React.FC = () => {
  const { t } = useTranslation();
  return (
    <VisualListItem Icon={IconUserProfile}>
      {t("mas.scope.view_profile")}
    </VisualListItem>
  );
};

const ScopeEditProfile: React.FC = () => {
  const { t } = useTranslation();
  return (
    <VisualListItem Icon={IconInfo}>
      {t("mas.scope.edit_profile")}
    </VisualListItem>
  );
};

const ScopeManageSessions: React.FC = () => {
  const { t } = useTranslation();
  return (
    <VisualListItem Icon={IconComputer}>
      {t("mas.scope.manage_sessions")}
    </VisualListItem>
  );
};

export const ScopeViewMessages: React.FC = () => {
  const { t } = useTranslation();
  return (
    <VisualListItem Icon={IconChat}>
      {t("mas.scope.view_messages")}
    </VisualListItem>
  );
};

export const ScopeSendMessages: React.FC = () => {
  const { t } = useTranslation();
  return (
    <VisualListItem Icon={IconSend}>
      {t("mas.scope.send_messages")}
    </VisualListItem>
  );
};

const ScopeSynapseAdmin: React.FC = () => {
  const { t } = useTranslation();
  return (
    <VisualListItem Icon={IconErrorSolid}>
      {t("mas.scope.synapse_admin")}
    </VisualListItem>
  );
};

const ScopeMasAdmin: React.FC = () => {
  const { t } = useTranslation();
  return (
    <VisualListItem Icon={IconErrorSolid}>
      {t("mas.scope.mas_admin")}
    </VisualListItem>
  );
};

const ScopeOther: React.FC<{ scope: string }> = ({ scope }) => {
  return <VisualListItem Icon={IconInfo}>{scope}</VisualListItem>;
};

const Scope: React.FC<{ scope: string }> = ({ scope }) => {
  // Filter out "urn:matrix:org.matrix.msc2967.client:device:"
  if (scope.startsWith("urn:matrix:org.matrix.msc2967.client:device:")) {
    return null;
  }

  switch (scope) {
    case "openid":
      return <ScopeViewProfile />;
    case "urn:mas:graphql:*":
      return (
        <>
          <ScopeEditProfile />
          <ScopeManageSessions />
        </>
      );
    case "urn:matrix:org.matrix.msc2967.client:api:*":
      return (
        <>
          <ScopeViewMessages />
          <ScopeSendMessages />
        </>
      );
    case "urn:synapse:admin:*":
      return <ScopeSynapseAdmin />;
    case "urn:mas:admin":
      return <ScopeMasAdmin />;
    default:
      return <ScopeOther scope={scope} />;
  }
};

export const ScopeList: React.FC<{ scope: string }> = ({ scope }) => {
  const scopes = scope.split(" ");
  return (
    <VisualList className="mt-1">
      {scopes.map((scope) => (
        <Scope key={scope} scope={scope} />
      ))}
    </VisualList>
  );
};

export const Data: React.FC<
  React.PropsWithChildren<{ className?: string }>
> = ({ children, className }) => (
  <li className={cx("flex flex-col min-w-0", className)}>{children}</li>
);

export const DataLabel: React.FC<
  React.PropsWithChildren<{ className?: string }>
> = ({ children, className }) => (
  <Text
    size="sm"
    weight="regular"
    as="h5"
    className={cx("text-secondary", className)}
  >
    {children}
  </Text>
);

export const DataValue: React.FC<
  React.PropsWithChildren<{ className?: string }>
> = ({ children, className }) => (
  <Text
    size="md"
    weight="regular"
    className={cx("text-ellipsis overflow-hidden", className)}
  >
    {children}
  </Text>
);

export const DataList: React.FC<
  React.PropsWithChildren<{ className?: string }>
> = ({ children, className }) => (
  <ul className={cx("flex flex-wrap gap-x-10 gap-y-6", className)}>
    {children}
  </ul>
);

export const DataSection: React.FC<
  React.PropsWithChildren<{ className?: string }>
> = ({ children, className }) => (
  <section className={cx("flex flex-col gap-6", className)}>{children}</section>
);

export const DataSectionHeader: React.FC<
  React.PropsWithChildren<{ className?: string }>
> = ({ children, className }) => (
  <>
    <Heading as="h4" size="sm" weight="semibold" className={className}>
      {children}
    </Heading>
    <Separator className="-mt-4" kind="section" />
  </>
);
