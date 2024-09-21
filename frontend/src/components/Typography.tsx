// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { createElement, Children } from "react";

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
}: Props) => {
  const element = elementMap[variant];
  const boldClass = bold ? "font-semibold" : "";
  const justifiedClass = justified ? "text-justify" : "";
  const className = `text-black dark:text-white ${boldClass} ${justifiedClass} ${classMap[variant]} ${extraClassName}`;
  return createElement(element, { className }, ...Children.toArray(children));
};

type SimpleProps = { children: React.ReactNode };

export const Bold: React.FC<SimpleProps> = ({ children }: SimpleProps) => (
  <strong className="font-semibold">{children}</strong>
);

export const Code: React.FC<SimpleProps> = ({ children }: SimpleProps) => (
  <code className="font-mono text-sm">{children}</code>
);

export const Title: React.FC<SimpleProps> = ({ children }: SimpleProps) => (
  <Typography variant="title">{children}</Typography>
);

export const Subtitle: React.FC<SimpleProps> = ({ children }: SimpleProps) => (
  <Typography variant="subtitle">{children}</Typography>
);

type BodyProps = { children: React.ReactNode; justified?: boolean };

export const Body: React.FC<BodyProps> = ({
  children,
  justified,
}: BodyProps) => (
  <Typography variant="body" justified={justified}>
    {children}
  </Typography>
);

export default Typography;
