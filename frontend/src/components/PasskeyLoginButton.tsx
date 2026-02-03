import { useMutation } from "@tanstack/react-query";
import IconKey from "@vector-im/compound-design-tokens/assets/web/icons/key";
import CheckIcon from "@vector-im/compound-design-tokens/assets/web/icons/check";
import { Alert, Button } from "@vector-im/compound-web";
import { useTranslation } from "react-i18next";
import { checkSupport, performAuthentication } from "../utils/webauthn";
import { useCallback, useEffect, useRef } from "react";
import LoadingSpinner from "./LoadingSpinner";

const PasskeyLoginButton: React.FC<{
  options: PublicKeyCredentialRequestOptionsJSON;
  challengeId: string;
  csrfToken: string;
}> = ({ options, challengeId, csrfToken }) => {
  const formRef = useRef<HTMLFormElement>(null);
  const responseRef = useRef<HTMLInputElement>(null);
  const { t } = useTranslation();
  const abortControllerRef = useRef<AbortController>(null);

  const { mutate, error, isPending, isSuccess } = useMutation({
    throwOnError: false,
    mutationFn: async ({
      options,
      mediation,
    }: {
      options: PublicKeyCredentialRequestOptionsJSON;
      mediation: CredentialMediationRequirement;
    }) => {
      // Cancel any running webauthn flow
      abortControllerRef.current?.abort();
      abortControllerRef.current = new AbortController();
      const signal = abortControllerRef.current.signal;

      const data = await performAuthentication(options, mediation, signal);
      responseRef.current!.value = data;
      formRef.current!.submit();
    },
  });

  useEffect(() => {
    // Start a conditional mediation if available and if the regular
    // user-interactive mediation is not running
    if (isPending) return;

    // Cancel any running webauthn flow
    abortControllerRef.current?.abort();
    abortControllerRef.current = new AbortController();
    const signal = abortControllerRef.current.signal;

    (async () => {
      if (
        window.PublicKeyCredential &&
        PublicKeyCredential.isConditionalMediationAvailable &&
        (await PublicKeyCredential.isConditionalMediationAvailable())
      ) {
        signal.throwIfAborted();
        // We're not using the mutation here, because we don't want to
        // throw an error if the user rejects the conditional mediation
        const result = await performAuthentication(
          options,
          "conditional",
          signal,
        );
        signal.throwIfAborted();
        if (!responseRef.current || !formRef.current) return;
        responseRef.current.value = result;
        formRef.current.submit();
      }
    })().catch((cause) => {
      // If the conditional mediation fails for any reason, we just log about
      // it, we don't really need to show a user-facing error for it
      console.error(
        new Error("WebAuthn conditional mediation failed", { cause }),
      );
    });
  }, [isPending]);

  // When unmounting the component, abort any running webauthn flow
  useEffect(() => {
    return () => {
      abortControllerRef.current?.abort();
    };
  }, []);

  const handleSubmit = useCallback(
    (e: React.FormEvent<HTMLFormElement>): void => {
      e.preventDefault();
      mutate({ options, mediation: "optional" });
    },
    [mutate],
  );

  const support = checkSupport();

  return (
    <form
      method="POST"
      className="flex flex-col gap-6"
      ref={formRef}
      onSubmit={handleSubmit}
    >
      {error && (
        /* TODO: have better errors */
        <Alert type="critical" title={error.toString()} />
      )}
      <input type="hidden" name="csrf" value={csrfToken} />
      <input type="hidden" name="webauthn_challenge_id" value={challengeId} />
      <input type="hidden" name="webauthn_response" ref={responseRef} />
      <Button
        type="submit"
        kind="secondary"
        size="lg"
        Icon={isSuccess ? CheckIcon : isPending ? undefined : IconKey}
        disabled={!support || isPending || isSuccess}
      >
        {isPending && <LoadingSpinner inline />}
        {t("passkeys.login")}
      </Button>
    </form>
  );
};

export default PasskeyLoginButton;
