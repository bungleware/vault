import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useEffect, useState, useRef } from "react";
import type { FormEvent } from "react";
import { useAuth } from "../../contexts/AuthContext";
import { Button } from "../../components/ui/button";
import { Input } from "../../components/ui/input";
import { Label } from "../../components/ui/label";
import { ApiError } from "../../api/client";
import { motion, AnimatePresence } from "motion/react";
import { getInstanceInfo } from "../../api/stats";
import { resetInstance } from "../../api/instance";

export const Route = createFileRoute("/reset-setup/")({
  component: ResetSetupPage,
});

function ResetSetupPage() {
  const { isAuthenticated, isLoading: authLoading, user } = useAuth();
  const navigate = useNavigate();
  const [instanceInfo, setInstanceInfo] = useState<{ name: string } | null>(
    null,
  );
  const [isChecking, setIsChecking] = useState(true);
  const [instanceNameConfirm, setInstanceNameConfirm] = useState("");
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const errorWrapperRef = useRef<HTMLDivElement>(null);
  const [errorHeight, setErrorHeight] = useState(0);

  useEffect(() => {
    const fetchInfo = async () => {
      try {
        const info = await getInstanceInfo();
        setInstanceInfo(info);
      } catch (error) {
        console.error("Failed to get instance info:", error);
        setInstanceInfo({ name: "Vault" });
      } finally {
        setIsChecking(false);
      }
    };

    fetchInfo();
  }, []);

  useEffect(() => {
    if (!authLoading && !isAuthenticated) {
      navigate({ to: "/login" });
    }
  }, [isAuthenticated, authLoading, navigate]);

  useEffect(() => {
    if (!authLoading && isAuthenticated && user && !user.is_admin) {
      navigate({ to: "/" });
    }
  }, [isAuthenticated, authLoading, user, navigate]);

  useEffect(() => {
    if (error) {
      requestAnimationFrame(() => {
        requestAnimationFrame(() => {
          if (errorWrapperRef.current) {
            const wrapper = errorWrapperRef.current;
            const originalHeight = wrapper.style.height;
            wrapper.style.height = "auto";
            const naturalHeight = wrapper.scrollHeight;
            wrapper.style.height = originalHeight;
            setErrorHeight(naturalHeight);
          }
        });
      });
    } else {
      setErrorHeight(0);
    }
  }, [error]);

  if (isChecking || authLoading || !isAuthenticated || !user?.is_admin) {
    return <div className="min-h-screen bg-[#181818]" />;
  }

  const handleSubmit = async (e?: FormEvent) => {
    e?.preventDefault();

    const trimmedInstanceName = instanceNameConfirm.trim();
    const trimmedUsername = username.trim();
    const trimmedEmail = email.trim();
    const trimmedPassword = password.trim();

    if (!trimmedInstanceName) {
      setError("Please enter the instance name to confirm.");
      return;
    }

    if (trimmedInstanceName !== instanceInfo?.name) {
      setError("Instance name does not match. Please try again.");
      return;
    }

    if (!trimmedUsername || !trimmedEmail || !trimmedPassword) {
      if (!trimmedUsername && !trimmedEmail && !trimmedPassword) {
        setError("Please enter your username, email, and password.");
      } else if (!trimmedUsername) {
        setError("Please enter your username.");
      } else if (!trimmedEmail) {
        setError("Please enter your email.");
      } else if (!trimmedPassword) {
        setError("Please enter your password.");
      }
      return;
    }

    if (trimmedEmail.length < 5 || !trimmedEmail.includes("@")) {
      setError("Please enter a valid email address.");
      return;
    }

    if (trimmedPassword.length < 8) {
      setError("Password must be at least 8 characters long.");
      return;
    }

    setError("");

    try {
      setIsLoading(true);
      await resetInstance(trimmedInstanceName, {
        username: trimmedUsername,
        email: trimmedEmail,
        password: trimmedPassword,
      });
      navigate({ to: "/login" });
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message || "Reset failed. Please try again.");
      } else {
        setError("An unexpected error occurred. Please try again.");
      }
    } finally {
      setIsLoading(false);
    }
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
            <p
              className="text-[#7c7c7c] text-sm font-light mt-3"
              style={{ fontFamily: '"IBM Plex Mono", monospace' }}
            >
              Reset instance and create new admin
            </p>
          </div>

          <div
            className="mb-6 p-4 border border-red-500/30 rounded-2xl"
            style={{
              background:
                "linear-gradient(0deg, #2a1515 0%, rgba(40, 20, 20, 0.3) 100%)",
            }}
          >
            <p
              className="text-red-400 text-sm font-light text-center"
              style={{ fontFamily: '"IBM Plex Mono", monospace' }}
            >
              This will permanently delete ALL data including all users,
              projects, tracks, and files.
            </p>
          </div>

          <motion.div
            ref={errorWrapperRef}
            animate={{
              height: errorHeight,
              opacity: error ? 1 : 0,
            }}
            transition={{
              height: { type: "spring", stiffness: 400, damping: 25 },
              opacity: { duration: 0.2 },
            }}
            className="mb-3 overflow-hidden"
          >
            <AnimatePresence>
              {error && (
                <motion.div
                  key="error"
                  initial={{ opacity: 0, y: -8, filter: "blur(8px)" }}
                  animate={{ opacity: 1, y: 0, filter: "blur(0px)" }}
                  exit={{ opacity: 0, y: -8, filter: "blur(8px)" }}
                  transition={{
                    opacity: { duration: 0.2 },
                    y: { duration: 0.2 },
                    filter: { duration: 0.25, ease: [0.4, 0, 0.2, 1] },
                  }}
                >
                  <div
                    className="p-4 border border-red-500/30 rounded-2xl"
                    style={{
                      background:
                        "linear-gradient(0deg, #2a1515 0%, rgba(40, 20, 20, 0.3) 100%)",
                    }}
                  >
                    <p
                      className="text-red-400 text-sm text-center font-light whitespace-pre-line"
                      style={{ fontFamily: '"IBM Plex Mono", monospace' }}
                    >
                      {error}
                    </p>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </motion.div>

          <form onSubmit={handleSubmit} className="space-y-5">
            <div className="space-y-2">
              <Label
                htmlFor="confirm-instance"
                className="text-[#7c7c7c] text-base font-light ml-5"
                style={{ fontFamily: '"IBM Plex Mono", monospace' }}
              >
                instance name (type to confirm)
              </Label>
              <Input
                id="confirm-instance"
                type="text"
                placeholder={instanceInfo?.name}
                value={instanceNameConfirm}
                onChange={(e) => {
                  setInstanceNameConfirm(e.target.value);
                  setError("");
                }}
                disabled={isLoading}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.preventDefault();
                    handleSubmit();
                  }
                }}
                className="border-[#353333]/50 text-white text-lg md:text-lg placeholder:text-white/40 h-12 rounded-2xl px-5"
                style={{
                  background:
                    "linear-gradient(0deg, #1D1D1D 0%, rgba(40, 40, 40, 0.22) 100%)",
                }}
              />
            </div>

            <div className="space-y-2">
              <Label
                htmlFor="username"
                className="text-[#7c7c7c] text-base font-light ml-5"
                style={{ fontFamily: '"IBM Plex Mono", monospace' }}
              >
                username
              </Label>
              <Input
                id="username"
                type="text"
                placeholder="admin"
                value={username}
                onChange={(e) => {
                  setUsername(e.target.value);
                  setError("");
                }}
                disabled={isLoading}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.preventDefault();
                    handleSubmit();
                  }
                }}
                className="border-[#353333]/50 text-white text-lg md:text-lg placeholder:text-white/80 h-12 rounded-2xl px-5"
                style={{
                  background:
                    "linear-gradient(0deg, #1D1D1D 0%, rgba(40, 40, 40, 0.22) 100%)",
                }}
              />
            </div>

            <div className="space-y-2">
              <Label
                htmlFor="email"
                className="text-[#7c7c7c] text-base font-light ml-5"
                style={{ fontFamily: '"IBM Plex Mono", monospace' }}
              >
                email
              </Label>
              <Input
                id="email"
                type="email"
                placeholder="admin@example.com"
                value={email}
                onChange={(e) => {
                  setEmail(e.target.value);
                  setError("");
                }}
                disabled={isLoading}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.preventDefault();
                    handleSubmit();
                  }
                }}
                className="border-[#353333]/50 text-white text-lg md:text-lg placeholder:text-white/80 h-12 rounded-2xl px-5"
                style={{
                  background:
                    "linear-gradient(0deg, #1D1D1D 0%, rgba(40, 40, 40, 0.22) 100%)",
                }}
              />
            </div>

            <div className="space-y-2">
              <Label
                htmlFor="password"
                className="text-[#7c7c7c] text-base font-light ml-5"
                style={{ fontFamily: '"IBM Plex Mono", monospace' }}
              >
                password
              </Label>
              <Input
                id="password"
                type="password"
                placeholder="••••••••"
                value={password}
                onChange={(e) => {
                  setPassword(e.target.value);
                  setError("");
                }}
                disabled={isLoading}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.preventDefault();
                    handleSubmit();
                  }
                }}
                className="border-[#353333]/50 text-white text-lg md:text-lg placeholder:text-white/80 h-12 rounded-2xl px-5"
                style={{
                  background:
                    "linear-gradient(0deg, #1D1D1D 0%, rgba(40, 40, 40, 0.22) 100%)",
                }}
              />
              <p
                className="text-[#6a6a6a] text-xs ml-5"
                style={{ fontFamily: '"IBM Plex Mono", monospace' }}
              >
                Minimum 8 characters
              </p>
            </div>

            <Button
              type="submit"
              disabled={isLoading}
              className="w-full border border-[#353333] hover:brightness-110 text-white font-semibold text-lg h-12 rounded-2xl transition-all mt-6 relative overflow-hidden disabled:opacity-50"
              style={{
                background: "linear-gradient(0deg, #1D1D1D 0%, #282828 100%)",
              }}
            >
              <AnimatePresence mode="popLayout" initial={false}>
                <motion.div
                  key={isLoading ? "loading" : "reset"}
                  initial={{ opacity: 0, scale: 0.25, filter: "blur(4px)" }}
                  animate={{ opacity: 1, scale: 1, filter: "blur(0px)" }}
                  exit={{ opacity: 0, scale: 0.25, filter: "blur(4px)" }}
                  transition={{
                    type: "spring",
                    duration: 0.3,
                    bounce: 0,
                  }}
                  className="absolute inset-0 flex items-center justify-center"
                >
                  {isLoading ? "" : "Reset instance"}
                </motion.div>
              </AnimatePresence>
            </Button>
          </form>
        </motion.div>
      </div>
    </div>
  );
}
