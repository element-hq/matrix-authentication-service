// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import { Children, createElement } from "react";

type Variant = "headline" | "title" | "subtitle" | "body" | "caption" | "micro";

type Props = {
  children: React.ReactNode;
  className?: string;
  variant: Variant;
  bold?: boolean;
  justified?: boolean;
};

const elementMap: Record<Variant, "h1" | "h2" | "h3" | "p" | "small"> = {
  headline: "h1",
  title: "h2",
  subtitle: "h3",
  body: "p",
  caption: "p",
  micro: "small",
};

const classMap: Record<Variant, string> = {
  headline: "text-3xl font-semibold",
  title: "text-2xl font-semibold",
  subtitle: "text-lg",
  body: "text-base",
  caption: "text-sm",
  micro: "text-xs",
};

const Typography: React.FC<Props> = ({
  variant,
  children,
  bold,
  justified,
  className: extraClassName,
}) => {
  const element = elementMap[variant];
  const boldClass = bold ? "font-semibold" : "";
  const justifiedClass = justified ? "text-justify" : "";
  const className = `text-black dark:text-white ${boldClass} ${justifiedClass} ${classMap[variant]} ${extraClassName}`;
  return createElement(element, { className }, ...Children.toArray(children));
};

export default Typography;
