import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { useAuth } from "../../contexts/AuthContext";
import { LoginForm } from "../../components/LoginForm";
import { motion } from "motion/react";
import { checkUsersExist } from "../../api/auth";

export const Route = createFileRoute("/login/")({
  component: LoginPage,
});

function LoginPage() {
  const { isAuthenticated, isLoading: authLoading } = useAuth();
  const navigate = useNavigate();
  const [hasCheckedUsers, setHasCheckedUsers] = useState(false);
  const [connectionError, setConnectionError] = useState(false);

  useEffect(() => {
    if (hasCheckedUsers || authLoading) {
      return;
    }

    const checkUsers = async () => {
      try {
        const result = await checkUsersExist();
        setHasCheckedUsers(true);
        setConnectionError(false);
        if (!result.users_exist) {
          navigate({ to: "/initialize", replace: true });
        }
      } catch (error) {
        console.error("Failed to check if users exist:", error);
        setHasCheckedUsers(true);
        setConnectionError(true);
      }
    };

    checkUsers();
  }, [hasCheckedUsers, authLoading, navigate]);

  useEffect(() => {
    if (!authLoading && isAuthenticated) {
      navigate({ to: "/" });
    }
  }, [isAuthenticated, authLoading, navigate]);

  if (authLoading || !hasCheckedUsers || isAuthenticated) {
    return <div className="min-h-screen bg-[#181818]" />;
  }

  const handleLoginSuccess = () => {
    navigate({ to: "/" });
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-[#181818] p-4">
      <div className="w-full max-w-[500px]">
        <motion.div
          layout
          initial={{ opacity: 0, y: 5, filter: "blur(8px)" }}
          animate={{ opacity: 1, y: 0, filter: "blur(0px)" }}
          transition={{
            opacity: { duration: 0.25, ease: [0.4, 0, 0.2, 1] },
            y: { duration: 0.25, ease: [0.4, 0, 0.2, 1] },
            filter: { duration: 0.25, ease: [0.4, 0, 0.2, 1] },
            layout: { type: "spring", stiffness: 400, damping: 25 },
          }}
          className="border border-[#353333] rounded-[45px] px-10 py-12"
          style={{
            background: "linear-gradient(0deg, #131313 0%, #161616 100%)",
            boxShadow: "0 25px 27.4px -10px rgba(0, 0, 0, 0.19)",
          }}
        >
          <div className="text-center mb-8">
            <h1 className="text-[39px] font-light text-white">{`{ vault }`}</h1>
          </div>

          {connectionError ? (
            <div className="text-center space-y-4">
              <p className="text-red-400 text-sm">
                Unable to connect to the server
              </p>
              <button
                onClick={() => {
                  setHasCheckedUsers(false);
                  setConnectionError(false);
                }}
                className="px-4 py-2 text-sm text-white/60 hover:text-white transition-colors"
              >
                Retry
              </button>
            </div>
          ) : (
            <LoginForm onSubmitSuccess={handleLoginSuccess} />
          )}
        </motion.div>
      </div>
    </div>
  );
}
