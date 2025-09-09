import { useMutation } from "@tanstack/react-query";
import IconKey from "@vector-im/compound-design-tokens/assets/web/icons/key";
import { Alert, Button } from "@vector-im/compound-web";
import { useTranslation } from "react-i18next";
import { checkSupport, performAuthentication } from "../utils/webauthn";

const PasskeyLoginButton: React.FC<{ options?: string }> = ({ options }) => {
  const { t } = useTranslation();
  const webauthnCeremony = useMutation({
    mutationFn: async (options: string) => {
      try {
        return { response: await performAuthentication(options) };
      } catch (e) {
        console.error(e);
        return { error: e as Error };
      }
    },
    onSuccess: (data) => {
      if (data.response) {
        const form = document.querySelector("form") as HTMLFormElement;
        const formResponse = form?.querySelector(
          '[name="passkey_response"]',
        ) as HTMLInputElement;

        formResponse.value = data.response;
        form.submit();
      }
    },
  });

  if (!options) return;

  const handleClick = async (
    e: React.FormEvent<HTMLButtonElement>,
  ): Promise<void> => {
    e.preventDefault();

    webauthnCeremony.mutate(options);
  };

  const support = checkSupport();

  return (
    <div className="flex flex-col gap-6">
      {webauthnCeremony.data?.error &&
        webauthnCeremony.data?.error.name !== "NotAllowedError" && (
          <Alert
            type="critical"
            title={webauthnCeremony.data?.error.toString()}
          />
        )}
      <Button
        kind="secondary"
        size="lg"
        Icon={IconKey}
        onClick={handleClick}
        disabled={!support}
      >
        {t("passkeys.login")}
      </Button>
    </div>
  );
};

export default PasskeyLoginButton;
