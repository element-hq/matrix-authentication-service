// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import { useMutation, useQueryClient } from "@tanstack/react-query";
import IconClose from "@vector-im/compound-design-tokens/assets/web/icons/close";
import IconEdit from "@vector-im/compound-design-tokens/assets/web/icons/edit";
import {
  Avatar,
  Button,
  Form,
  IconButton,
  Text,
  Tooltip,
} from "@vector-im/compound-web";
import {
  type ComponentPropsWithoutRef,
  forwardRef,
  useRef,
  useState,
} from "react";
import { useTranslation } from "react-i18next";
import { type FragmentType, graphql, useFragment } from "../../gql";
import { graphqlRequest } from "../../graphql";
import * as Dialog from "../Dialog";
import LoadingSpinner from "../LoadingSpinner";
import styles from "./UserGreeting.module.css";

export const FRAGMENT = graphql(/* GraphQL */ `
  fragment UserGreeting_user on User {
    id
    matrix {
      mxid
      displayName
    }
  }
`);

export const CONFIG_FRAGMENT = graphql(/* GraphQL */ `
  fragment UserGreeting_siteConfig on SiteConfig {
    displayNameChangeAllowed
  }
`);

const SET_DISPLAYNAME_MUTATION = graphql(/* GraphQL */ `
  mutation SetDisplayName($userId: ID!, $displayName: String) {
    setDisplayName(input: { userId: $userId, displayName: $displayName }) {
      status
    }
  }
`);

// This needs to be its own component because else props and refs aren't passed properly in the trigger
const EditButton = forwardRef<
  HTMLButtonElement,
  { label: string } & ComponentPropsWithoutRef<"button">
>(({ label, ...props }, ref) => (
  <Tooltip label={label}>
    <IconButton
      ref={ref}
      type="button"
      size="var(--cpd-space-6x)"
      className={styles.editButton}
      {...props}
    >
      <IconEdit />
    </IconButton>
  </Tooltip>
));

type Props = {
  user: FragmentType<typeof FRAGMENT>;
  siteConfig: FragmentType<typeof CONFIG_FRAGMENT>;
};

const UserGreeting: React.FC<Props> = ({ user, siteConfig }) => {
  const fieldRef = useRef<HTMLInputElement>(null);
  const data = useFragment(FRAGMENT, user);
  const { displayNameChangeAllowed } = useFragment(CONFIG_FRAGMENT, siteConfig);
  const queryClient = useQueryClient();

  const setDisplayName = useMutation({
    mutationFn: ({
      userId,
      displayName,
    }: {
      userId: string;
      displayName: string | null;
    }) =>
      graphqlRequest({
        query: SET_DISPLAYNAME_MUTATION,
        variables: { userId, displayName },
      }),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["currentUserGreeting"] });
      if (data.setDisplayName.status === "SET") {
        setOpen(false);
      }
    },
  });

  const [open, setOpen] = useState(false);
  const { t } = useTranslation();

  const onSubmit = (event: React.FormEvent<HTMLFormElement>): void => {
    event.preventDefault();

    const form = event.currentTarget;
    const formData = new FormData(form);
    const displayName = (formData.get("displayname") as string) || null;
    setDisplayName.mutate({ displayName, userId: data.id });
  };

  return (
    <div className={styles.user}>
      <Avatar
        size="var(--cpd-space-14x)"
        id={data.matrix.mxid}
        name={data.matrix.displayName || data.matrix.mxid}
        className={styles.avatar}
      />
      <div className={styles.meta}>
        {data.matrix.displayName ? (
          <>
            <Text size="lg" weight="semibold">
              {data.matrix.displayName}
            </Text>
            <Text size="md" className={styles.mxid}>
              {data.matrix.mxid}
            </Text>
          </>
        ) : (
          <Text size="lg" weight="semibold">
            {data.matrix.mxid}
          </Text>
        )}
      </div>

      {displayNameChangeAllowed && (
        <Dialog.Dialog
          trigger={<EditButton label={t("action.edit")} />}
          open={open}
          onOpenChange={(open) => {
            // Reset the form when the dialog is opened or closed
            fieldRef.current?.form?.reset();
            setOpen(open);
          }}
        >
          <Dialog.Title>
            {t("frontend.account.edit_profile.title")}
          </Dialog.Title>

          <Avatar
            size="88px"
            className="self-center"
            id={data.matrix.mxid}
            name={data.matrix.displayName || data.matrix.mxid}
          />

          <Form.Root onSubmit={onSubmit}>
            <div className={styles.dialogForm}>
              <Form.Field
                name="displayname"
                serverInvalid={
                  setDisplayName.data?.setDisplayName.status === "INVALID"
                }
              >
                <Form.Label>
                  {t("frontend.account.edit_profile.display_name_label")}
                </Form.Label>

                <Form.ActionControl
                  type="text"
                  Icon={IconClose}
                  autoComplete="name"
                  defaultValue={data.matrix.displayName || undefined}
                  actionLabel={t("action.clear")}
                  ref={fieldRef}
                  onActionClick={() => {
                    if (fieldRef.current) {
                      fieldRef.current.value = "";
                      fieldRef.current.focus();
                    }
                  }}
                />

                <Form.HelpMessage>
                  {t("frontend.account.edit_profile.display_name_help")}
                </Form.HelpMessage>
              </Form.Field>

              <Form.Field name="mxid">
                <Form.Label>
                  {t("frontend.account.edit_profile.username_label")}
                </Form.Label>
                <Form.TextControl value={data.matrix.mxid} readOnly />
              </Form.Field>
            </div>

            <Form.Submit disabled={setDisplayName.isPending}>
              {setDisplayName.isPending && <LoadingSpinner inline />}
              {t("action.save")}
            </Form.Submit>
          </Form.Root>

          <Dialog.Close asChild>
            <Button kind="tertiary">{t("action.cancel")}</Button>
          </Dialog.Close>
        </Dialog.Dialog>
      )}
    </div>
  );
};

export default UserGreeting;
