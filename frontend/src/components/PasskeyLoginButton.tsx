import { useMutation } from "@tanstack/react-query";
import IconKey from "@vector-im/compound-design-tokens/assets/web/icons/key";
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

  const { mutate, error, isPending } = useMutation({
    throwOnError: false,
    mutationFn: async ({
      options,
      mediation,
      signal,
    }: {
      options: PublicKeyCredentialRequestOptionsJSON;
      mediation: CredentialMediationRequirement;
      signal?: AbortSignal;
    }) => await performAuthentication(options, mediation, signal),

    onSuccess: (data) => {
      responseRef.current!.value = data;
      formRef.current!.submit();
    },
  });

  // Start a conditional mediation if available
  useEffect(() => {
    // We setup an abort signal to cancel the mediation if the component gets unmounted
    const abortController = new AbortController();
    const signal = abortController.signal;

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
      console.error(
        new Error("WebAuthn conditional mediation failed", { cause }),
      );
    });

    return () => {
      abortController.abort();
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
      {error && error.name !== "NotAllowedError" && (
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
        Icon={isPending ? undefined : IconKey}
        disabled={!support || isPending}
      >
        {isPending && <LoadingSpinner inline />}
        {t("passkeys.login")}
      </Button>
    </form>
  );
};

export default PasskeyLoginButton;
