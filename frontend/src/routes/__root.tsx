import {
  Outlet,
  createRootRouteWithContext,
  useRouterState,
  useNavigate,
} from "@tanstack/react-router";
import { useEffect, useState } from "react";

import { toast as sonnerToast, Toaster } from "sonner";
import MusicPlayer from "../components/MusicPlayer";
import { useAuth } from "../contexts/AuthContext";
import { Button } from "../components/ui/button";
import { checkUsersExist } from "../api/auth";
import { useWebSocket } from "../hooks/useWebSocket";

import type { QueryClient } from "@tanstack/react-query";

interface MyRouterContext {
  queryClient: QueryClient;
}

interface ToastProps {
  id: string | number;
  title: string;
  description?: string;
  action?: {
    label: string;
    onClick: () => void;
  };
}

function toastCustom(options: Omit<ToastProps, "id"> | string) {
  const toastOptions =
    typeof options === "string" ? { title: options } : options;

  return sonnerToast.custom((id) => (
    <CustomToast
      id={id}
      title={toastOptions.title}
      description={toastOptions.description}
      action={toastOptions.action}
    />
  ));
}

export const toast = Object.assign(toastCustom, {
  success: (message: string) => toastCustom({ title: message }),
  error: (message: string) => toastCustom({ title: message }),
  loading: (message: string) =>
    sonnerToast.custom((id) => <CustomLoadingToast id={id} title={message} />),
  info: (message: string) => toastCustom({ title: message }),
  dismiss: (id?: string | number) => sonnerToast.dismiss(id),
});

function CustomLoadingToast(props: { id: string | number; title: string }) {
  const { title } = props;

  return (
    <div
      className="group flex rounded-(--button-radius) bg-background border border-(--button-border) shadow-lg items-center p-4 justify-center relative"
      style={{ minWidth: "250px", maxWidth: "420px" }}
    >
      <div className="flex items-center justify-center gap-3">
        <div className="w-4 h-4 border-2 border-foreground/20 border-t-foreground rounded-full animate-spin" />
        <div className="text-center">
          <p className="text-sm font-medium text-foreground">{title}</p>
        </div>
      </div>
    </div>
  );
}

function CustomToast(props: ToastProps) {
  const { title, description, action, id } = props;

  return (
    <div
      className="group flex rounded-(--button-radius) bg-background border border-(--button-border) shadow-lg items-center p-4 justify-center relative"
      style={{ minWidth: "250px", maxWidth: "420px" }}
    >
      <button
        onClick={() => sonnerToast.dismiss(id)}
        className="absolute -top-2 -right-2 w-6 h-6 rounded-full bg-background border border-(--button-border) flex items-center justify-center text-muted-foreground hover:text-foreground transition-all shadow-md opacity-0 group-hover:opacity-100"
        aria-label="Close"
      >
        <svg
          xmlns="http://www.w3.org/2000/svg"
          width="12"
          height="12"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <line x1="18" y1="6" x2="6" y2="18" />
          <line x1="6" y1="6" x2="18" y2="18" />
        </svg>
      </button>
      <div className="flex flex-1 items-center justify-center">
        <div className="w-full text-center">
          <p className="text-sm font-medium text-foreground">{title}</p>
          {description && (
            <p className="mt-1 text-sm text-muted-foreground">{description}</p>
          )}
        </div>
      </div>
      {action && (
        <div className="ml-4 shrink-0">
          <Button
            size="sm"
            onClick={() => {
              action.onClick();
              sonnerToast.dismiss(id);
            }}
          >
            {action.label}
          </Button>
        </div>
      )}
    </div>
  );
}

function RootComponent() {
  const routerState = useRouterState();
  const isProfileRoute = routerState.location.pathname.startsWith("/profile");
  const { isAuthenticated, isLoading: authLoading } = useAuth();
  const navigate = useNavigate();
  const [hasCheckedUsers, setHasCheckedUsers] = useState(false);
  const [isCheckingUsers, setIsCheckingUsers] = useState(false);

  useWebSocket(isAuthenticated);

  useEffect(() => {
    const currentPath = routerState.location.pathname;

    if (
      currentPath.startsWith("/initialize") ||
      currentPath.startsWith("/login") ||
      currentPath.startsWith("/register")
    ) {
      return;
    }

    if (hasCheckedUsers || isCheckingUsers || authLoading) {
      return;
    }

    const checkAndRedirect = async () => {
      setIsCheckingUsers(true);
      try {
        const result = await checkUsersExist();
        setHasCheckedUsers(true);
        if (!result.users_exist) {
          navigate({ to: "/initialize", replace: true });
        }
      } catch (error) {
        console.error("Failed to check if users exist:", error);
        setHasCheckedUsers(true);
      } finally {
        setIsCheckingUsers(false);
      }
    };

    checkAndRedirect();
  }, [
    routerState.location.pathname,
    authLoading,
    hasCheckedUsers,
    isCheckingUsers,
    navigate,
  ]);

  return (
    <>
      <Outlet />
      {isAuthenticated && <MusicPlayer hideControls={isProfileRoute} />}
      <Toaster
        position="top-center"
        offset="16px"
        style={{
          width: "100%",
          maxWidth: "100vw",
          display: "flex",
          justifyContent: "center",
        }}
      />
    </>
  );
}

export const Route = createRootRouteWithContext<MyRouterContext>()({
  component: RootComponent,
});
