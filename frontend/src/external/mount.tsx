import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { TooltipProvider } from "@vector-im/compound-web";
import { createElement, StrictMode, Suspense } from "react";
import ReactDOM from "react-dom/client";
import { I18nextProvider } from "react-i18next";
import ErrorBoundary from "../components/ErrorBoundary";
import i18n, { setupI18n } from "../i18n";

setupI18n();

export function mountWithProviders<P = Record<string, unknown>>(
  selector: string,
  Component: React.ComponentType<P>,
  defaultProps?: Partial<P>,
) {
  try {
    const el = document.querySelector(selector);
    if (!el) throw new Error(`can not find ${selector} in DOM`);
    const propsJSON = el.getAttribute("data-props") || "{}";
    const parsedProps = JSON.parse(propsJSON);
    const props = { ...(defaultProps ?? {}), ...(parsedProps ?? {}) };
    const queryClient = new QueryClient();
    ReactDOM.createRoot(el).render(
      <StrictMode>
        <QueryClientProvider client={queryClient}>
          <ErrorBoundary>
            <TooltipProvider>
              <Suspense fallback={<div>{`Loading... ${selector}…`}</div>}>
                <I18nextProvider i18n={i18n}>
                  {createElement(
                    Component as React.ComponentType<any>,
                    props as P,
                  )}
                </I18nextProvider>
              </Suspense>
            </TooltipProvider>
          </ErrorBoundary>
        </QueryClientProvider>
      </StrictMode>,
    );
  } catch (err) {
    console.error(`Cannot mount component on ${selector}:`, err);
  }
}
