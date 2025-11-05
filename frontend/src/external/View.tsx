import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { TooltipProvider } from "@vector-im/compound-web";
import { createElement, StrictMode, Suspense } from "react";
import ReactDOM from "react-dom/client";
import { I18nextProvider } from "react-i18next";
import ErrorBoundary from "../components/ErrorBoundary";
import i18n, { setupI18n } from "../i18n";
import PasswordFormLoader from "./register/PasswordFormLoader";
import "../shared.css";

setupI18n();

type mountComponentType = Record<string, React.ComponentType<any>>;

const COMPONENTS: mountComponentType = {
  PasswordFormLoader: PasswordFormLoader,
};

function mountComponent(selector: string) {
  const el = document.querySelector(selector);
  if (!el) return;
  const name = el.getAttribute("data-component");
  const propsJSON = el.getAttribute("data-props") || "{}";

  try {
    if (!name) {
      console.warn("name is not defined");
      return;
    }

    const props = JSON.parse(propsJSON);
    const component = COMPONENTS[name];

    if (!component) {
      console.warn(`Unknown component : ${name}`);
      return;
    }

    const queryClient = new QueryClient();

    ReactDOM.createRoot(el).render(
      <StrictMode>
        <QueryClientProvider client={queryClient}>
          <ErrorBoundary>
            <TooltipProvider>
              <Suspense fallback={<div>Loading password form...</div>}>
                <I18nextProvider i18n={i18n}>
                  {createElement(component, props)}
                </I18nextProvider>
              </Suspense>
            </TooltipProvider>
          </ErrorBoundary>
        </QueryClientProvider>
      </StrictMode>,
    );
  } catch (err) {
    console.error(`Cannot mount component : ${name}:`, err);
  }
}
mountComponent("#view");
