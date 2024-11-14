import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  RouterProvider,
  createHashHistory,
  createRouter,
} from "@tanstack/react-router";
import { TooltipProvider } from "@vector-im/compound-web";
import i18n from "i18next";
import { I18nextProvider } from "react-i18next";
import { routeTree } from "../../src/routeTree.gen";

export const App: React.FC<{ route: string }> = ({ route }) => {
  const queryClient = new QueryClient();
  const history = createHashHistory();
  history.replace(route);

  const router = createRouter({
    routeTree,
    context: { queryClient },
    history,
  });

  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <I18nextProvider i18n={i18n}>
          <RouterProvider router={router} />
        </I18nextProvider>
      </TooltipProvider>
    </QueryClientProvider>
  );
};
