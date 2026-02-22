import { StrictMode } from "react";
import ReactDOM from "react-dom/client";
import { RouterProvider, createRouter } from "@tanstack/react-router";
import * as TanStackQueryProvider from "./integrations/tanstack-query/root-provider.tsx";
import { AuthProvider } from "./contexts/AuthContext";
import { AudioPlayerProvider } from "./contexts/AudioPlayerContext";
import { routeTree } from "./routeTree.gen";
import "./styles.css";

const TanStackQueryProviderContext = TanStackQueryProvider.getContext();
const router = createRouter({
  routeTree,
  context: {
    ...TanStackQueryProviderContext,
  },
  defaultPreload: "intent",
  scrollRestoration: true,
  defaultStructuralSharing: true,
  defaultPreloadStaleTime: 0,
});

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}

const rootElement = document.getElementById("app");
if (rootElement && !rootElement.innerHTML) {
  const root = ReactDOM.createRoot(rootElement);
  root.render(
    <StrictMode>
      <TanStackQueryProvider.Provider {...TanStackQueryProviderContext}>
        <AuthProvider>
          <AudioPlayerProvider>
            <RouterProvider router={router} />
          </AudioPlayerProvider>
        </AuthProvider>
      </TanStackQueryProvider.Provider>
    </StrictMode>,
  );
}
