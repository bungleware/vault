"use client";

import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useState, useRef, useEffect } from "react";
import { useMutation } from "@tanstack/react-query";
import { registerWithInvite, validateInviteToken } from "@/api/admin";
import type { AuthResponse } from "@/types/api";
import { useAuth } from "@/contexts/AuthContext";
import { toast } from "@/routes/__root";
import { AlertCircle } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";

export const Route = createFileRoute("/accept-invite")({
  component: AcceptInvitePage,
});

function AcceptInvitePage() {
  const { token } = Route.useSearch() as { token?: string };
  const navigate = useNavigate();
  const { setAuthFromResponse } = useAuth();

  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [errors, setErrors] = useState<{ [key: string]: string }>({});
  const errorWrapperRef = useRef<HTMLDivElement>(null);
  const [errorHeight, setErrorHeight] = useState(0);
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    if (errors.submit) {
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
  }, [errors.submit]);

  useEffect(() => {
    if (token) {
      validateInviteToken(token).catch((error) => {
        const errorMessage =
          error?.response?.data ||
          error?.message ||
          "This invite link is invalid, already used, or has expired";
        setErrors({ submit: errorMessage });
      });
    }
  }, [token]);

  const registerMutation = useMutation({
    mutationFn: (data: {
      username: string;
      email: string;
      password: string;
      inviteToken: string;
    }) =>
      registerWithInvite(
        data.username,
        data.email,
        data.password,
        data.inviteToken
      ),
    onSuccess: (response: AuthResponse) => {
      setAuthFromResponse(response);
      toast.success("Account created");
      navigate({ to: "/" });
    },
    onError: (error: any) => {
      const errorMessage =
        error?.response?.data?.message ||
        "Failed to create account. Please try again.";
      toast.error(errorMessage);
      setErrors({ submit: errorMessage });
      setIsLoading(false);
    },
  });

  const validateForm = (): boolean => {
    const newErrors: { [key: string]: string } = {};

    if (!username.trim()) {
      newErrors.username = "Username is required";
    } else if (username.length < 3) {
      newErrors.username = "Username must be at least 3 characters";
    }

    if (!email.trim()) {
      newErrors.email = "Email is required";
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      newErrors.email = "Invalid email address";
    }

    if (!password) {
      newErrors.password = "Password is required";
    } else if (password.length < 8) {
      newErrors.password = "Password must be at least 8 characters";
    }

    if (password !== confirmPassword) {
      newErrors.confirmPassword = "Passwords do not match";
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!token) {
      setErrors({ submit: "Invalid invite link" });
      return;
    }

    if (!validateForm()) {
      return;
    }

    setIsLoading(true);
    setIsLoading(true);
    await registerMutation.mutateAsync({
      username,
      email,
      password,
      inviteToken: token,
    });
  };

  if (!token) {
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
            <div className="text-center mb-6">
              <div className="flex justify-center mb-3">
                <AlertCircle className="h-8 w-8 text-red-400" />
              </div>
              <h1 className="text-[39px] font-light text-white">
                Invalid Link
              </h1>
              <p
                className="text-[#7c7c7c] text-sm font-light mt-3"
                style={{ fontFamily: '"IBM Plex Mono", monospace' }}
              >
                This invite link is invalid or has expired
              </p>
            </div>

            <button
              onClick={() => navigate({ to: "/login" })}
              className="w-full border border-[#353333] hover:brightness-110 text-white font-semibold text-lg h-12 rounded-2xl transition-all relative overflow-hidden"
              style={{
                background: "linear-gradient(0deg, #1D1D1D 0%, #282828 100%)",
              }}
            >
              Back to Login
            </button>
          </motion.div>
        </div>
      </div>
    );
  }

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
              Create your account
            </p>
          </div>

          <motion.div
            ref={errorWrapperRef}
            animate={{
              height: errorHeight,
              opacity: errors.submit ? 1 : 0,
            }}
            transition={{
              height: { type: "spring", stiffness: 400, damping: 25 },
              opacity: { duration: 0.2 },
            }}
            className="mb-3 overflow-hidden"
          >
            <AnimatePresence>
              {errors.submit && (
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
                      {errors.submit}
                    </p>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </motion.div>

          <div className="space-y-5">
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
                value={username}
                onChange={(e) => {
                  setUsername(e.target.value);
                  if (errors.username) {
                    setErrors({ ...errors, username: "" });
                  }
                }}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.preventDefault();
                    handleSubmit(e as any);
                  }
                }}
                disabled={isLoading}
                className="border-[#353333]/50 text-white text-lg md:text-lg placeholder:text-white/80 h-12 rounded-2xl px-5"
                style={{
                  background:
                    "linear-gradient(0deg, #1D1D1D 0%, rgba(40, 40, 40, 0.22) 100%)",
                }}
              />
              {errors.username && (
                <p className="text-red-400 text-xs ml-5">{errors.username}</p>
              )}
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
                value={email}
                onChange={(e) => {
                  setEmail(e.target.value);
                  if (errors.email) {
                    setErrors({ ...errors, email: "" });
                  }
                }}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.preventDefault();
                    handleSubmit(e as any);
                  }
                }}
                disabled={isLoading}
                className="border-[#353333]/50 text-white text-lg md:text-lg placeholder:text-white/80 h-12 rounded-2xl px-5"
                style={{
                  background:
                    "linear-gradient(0deg, #1D1D1D 0%, rgba(40, 40, 40, 0.22) 100%)",
                }}
              />
              {errors.email && (
                <p className="text-red-400 text-xs ml-5">{errors.email}</p>
              )}
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
                value={password}
                onChange={(e) => {
                  setPassword(e.target.value);
                  if (errors.password) {
                    setErrors({ ...errors, password: "" });
                  }
                }}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.preventDefault();
                    handleSubmit(e as any);
                  }
                }}
                disabled={isLoading}
                className="border-[#353333]/50 text-white text-lg md:text-lg placeholder:text-white/80 h-12 rounded-2xl px-5"
                style={{
                  background:
                    "linear-gradient(0deg, #1D1D1D 0%, rgba(40, 40, 40, 0.22) 100%)",
                }}
              />
              {errors.password && (
                <p className="text-red-400 text-xs ml-5">{errors.password}</p>
              )}
            </div>

            <div className="space-y-2">
              <Label
                htmlFor="confirmPassword"
                className="text-[#7c7c7c] text-base font-light ml-5"
                style={{ fontFamily: '"IBM Plex Mono", monospace' }}
              >
                confirm password
              </Label>
              <Input
                id="confirmPassword"
                type="password"
                value={confirmPassword}
                onChange={(e) => {
                  setConfirmPassword(e.target.value);
                  if (errors.confirmPassword) {
                    setErrors({ ...errors, confirmPassword: "" });
                  }
                }}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.preventDefault();
                    handleSubmit(e as any);
                  }
                }}
                disabled={isLoading}
                className="border-[#353333]/50 text-white text-lg md:text-lg placeholder:text-white/80 h-12 rounded-2xl px-5"
                style={{
                  background:
                    "linear-gradient(0deg, #1D1D1D 0%, rgba(40, 40, 40, 0.22) 100%)",
                }}
              />
              {errors.confirmPassword && (
                <p className="text-red-400 text-xs ml-5">
                  {errors.confirmPassword}
                </p>
              )}
            </div>

            <button
              type="button"
              onClick={(e) => {
                e.preventDefault();
                e.stopPropagation();
                handleSubmit(e);
              }}
              disabled={isLoading}
              className="w-full border border-[#353333] hover:brightness-110 text-white font-semibold text-lg h-12 rounded-2xl transition-all mt-6 relative overflow-hidden disabled:opacity-50"
              style={{
                background: "linear-gradient(0deg, #1D1D1D 0%, #282828 100%)",
              }}
            >
              <AnimatePresence mode="popLayout" initial={false}>
                <motion.div
                  key={isLoading ? "loading" : "create"}
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
                  {isLoading ? "" : "Create account"}
                </motion.div>
              </AnimatePresence>
            </button>
          </div>
        </motion.div>
      </div>
    </div>
  );
}
