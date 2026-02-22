"use client";

import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useState, useEffect } from "react";
import { useMutation } from "@tanstack/react-query";
import { resetPassword, validateResetToken } from "@/api/admin";
import { toast } from "@/routes/__root";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { motion, AnimatePresence } from "motion/react";
import { AlertCircle, Check } from "lucide-react";

export const Route = createFileRoute("/reset-password")({
  component: ResetPasswordPage,
});

function ResetPasswordPage() {
  const { token } = Route.useSearch() as { token?: string };
  const navigate = useNavigate();

  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [errors, setErrors] = useState<{ [key: string]: string }>({});
  const [isSuccess, setIsSuccess] = useState(false);
  const [isValidating, setIsValidating] = useState(true);

  useEffect(() => {
    const checkToken = async () => {
      if (!token) {
        setIsValidating(false);
        return;
      }

      try {
        await validateResetToken(token);
        setIsValidating(false);
      } catch (error) {
        navigate({ to: "/login" });
      }
    };

    checkToken();
  }, [token, navigate]);

  const resetMutation = useMutation({
    mutationFn: (data: { password: string; resetToken: string }) =>
      resetPassword(data.password, data.resetToken),
    onSuccess: async () => {
      setIsSuccess(true);
      toast.success("Password reset successfully!");
      setTimeout(() => {
        window.location.href = "/login";
      }, 2000);
    },
    onError: (error: any) => {
      const errorMessage =
        error?.response?.data?.message ||
        "Failed to reset password. Please try again.";
      toast.error(errorMessage);
      setErrors({ submit: errorMessage });
    },
  });

  const validateForm = (): boolean => {
    const newErrors: { [key: string]: string } = {};

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
      setErrors({ submit: "Invalid reset link" });
      return;
    }

    if (!validateForm()) {
      return;
    }

    await resetMutation.mutateAsync({
      password,
      resetToken: token,
    });
  };

  if (isValidating) {
    return <div className="min-h-screen bg-[#181818]" />;
  }

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
                This password reset link is invalid or has expired
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

  if (isSuccess) {
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
              <motion.div
                initial={{ scale: 0 }}
                animate={{ scale: 1 }}
                transition={{ delay: 0.2 }}
                className="flex justify-center mb-3"
              >
                <div className="bg-green-500/20 rounded-full p-3">
                  <Check className="h-6 w-6 text-green-400" />
                </div>
              </motion.div>
              <h1 className="text-2xl font-bold text-white mb-2">
                Password Reset Successful
              </h1>
              <p className="text-[#7c7c7c] mb-6">
                Your password has been updated. You'll be redirected to the
                login page shortly.
              </p>
            </div>
            <button
              onClick={() => navigate({ to: "/login" })}
              className="w-full border border-[#353333] hover:brightness-110 text-white font-semibold text-lg h-12 rounded-2xl transition-all relative overflow-hidden"
              style={{
                background: "linear-gradient(0deg, #1D1D1D 0%, #282828 100%)",
              }}
            >
              Go to Login
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
              Reset your password
            </p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-5">
            {errors.submit && (
              <motion.div
                initial={{ opacity: 0, y: -8, filter: "blur(8px)" }}
                animate={{ opacity: 1, y: 0, filter: "blur(0px)" }}
                className="mb-3 overflow-hidden"
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

            <div className="space-y-2">
              <Label
                htmlFor="password"
                className="text-[#7c7c7c] text-base font-light ml-5"
                style={{ fontFamily: '"IBM Plex Mono", monospace' }}
              >
                new password
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
                disabled={resetMutation.isPending}
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
                disabled={resetMutation.isPending}
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

            <Button
              type="button"
              onClick={(e) => {
                e.preventDefault();
                e.stopPropagation();
                handleSubmit(e);
              }}
              disabled={resetMutation.isPending}
              className="w-full border border-[#353333] hover:brightness-110 text-white font-semibold text-lg h-12 rounded-2xl transition-all mt-6 relative overflow-hidden"
              style={{
                background: "linear-gradient(0deg, #1D1D1D 0%, #282828 100%)",
              }}
            >
              <AnimatePresence mode="popLayout" initial={false}>
                <motion.div
                  key={resetMutation.isPending ? "loading" : "reset"}
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
                  {resetMutation.isPending ? "" : "Reset Password"}
                </motion.div>
              </AnimatePresence>
            </Button>
          </form>

          <p className="text-[#7c7c7c] text-center text-sm mt-6">
            Remember your password?{" "}
            <button
              onClick={() => navigate({ to: "/login" })}
              className="text-white hover:underline transition-colors"
              style={{ fontFamily: '"IBM Plex Mono", monospace' }}
            >
              Sign in here
            </button>
          </p>
        </motion.div>
      </div>
    </div>
  );
}
