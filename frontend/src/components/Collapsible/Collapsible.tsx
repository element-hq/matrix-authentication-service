// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import * as Collapsible from "@radix-ui/react-collapsible";
import IconChevronUp from "@vector-im/compound-design-tokens/assets/web/icons/chevron-up";
import { H4, IconButton } from "@vector-im/compound-web";
import classNames from "classnames";
import { useCallback, useId, useState } from "react";
import { useTranslation } from "react-i18next";

import styles from "./Collapsible.module.css";

export const Section: React.FC<
  {
    title: string;
    description?: string;
  } & Omit<
    React.ComponentProps<typeof Collapsible.Root>,
    "asChild" | "aria-labelledby" | "aria-describedby" | "open"
  >
> = ({ title, description, defaultOpen, className, children, ...props }) => {
  const { t } = useTranslation();
  const [open, setOpen] = useState(defaultOpen || false);
  const titleId = useId();
  const descriptionId = useId();
  const onClick = useCallback((e: React.MouseEvent<HTMLElement>) => {
    e.preventDefault();
    setOpen((open) => !open);
  }, []);

  return (
    <Collapsible.Root
      {...props}
      open={open}
      onOpenChange={setOpen}
      asChild
      aria-labelledby={titleId}
      aria-describedby={description ? descriptionId : undefined}
      className={classNames(styles.root, className)}
    >
      <section>
        <header className={styles.heading}>
          <div className={styles.trigger}>
            <H4 onClick={onClick} id={titleId} className={styles.triggerTitle}>
              {title}
            </H4>
            <Collapsible.Trigger className={styles.triggerIcon} asChild>
              <IconButton
                tooltip={open ? t("action.collapse") : t("action.expand")}
              >
                <IconChevronUp />
              </IconButton>
            </Collapsible.Trigger>
          </div>

          {description && (
            <p className={styles.description} id={descriptionId}>
              {description}
            </p>
          )}
        </header>

        <Collapsible.Content asChild>
          <article className={styles.content}>{children}</article>
        </Collapsible.Content>
      </section>
    </Collapsible.Root>
  );
};
