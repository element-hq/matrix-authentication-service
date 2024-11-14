import { QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider, createMemoryHistory } from "@tanstack/react-router";
import { TooltipProvider } from "@vector-im/compound-web";
import i18n from "i18next";
import { I18nextProvider } from "react-i18next";
import { queryClient } from "../../src/graphql";
import { router } from "../../src/router";

export const App: React.FC<{ route: string }> = ({ route }) => {
  const history = createMemoryHistory({
    initialEntries: [route],
  });

  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <I18nextProvider i18n={i18n}>
          <RouterProvider
            router={router}
            history={history}
            context={{ queryClient }}
          />
        </I18nextProvider>
      </TooltipProvider>
    </QueryClientProvider>
  );
};
