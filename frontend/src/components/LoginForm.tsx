import { useState, useEffect, useRef } from "react";
import type { FormEvent } from "react";
import { useAuth } from "../contexts/AuthContext";
import { Button } from "./ui/button";
import { Input } from "./ui/input";
import { Label } from "./ui/label";
import { ApiError } from "../api/client";
import { motion, AnimatePresence } from "motion/react";

interface LoginFormProps {
  buttonText?: string;
  onSubmitSuccess?: () => void;
}

export function LoginForm({
  buttonText = "Sign in",
  onSubmitSuccess,
}: LoginFormProps) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const errorWrapperRef = useRef<HTMLDivElement>(null);
  const [errorHeight, setErrorHeight] = useState(0);

  const { login } = useAuth();

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

  const handleSubmit = async (e?: FormEvent) => {
    e?.preventDefault();

    const trimmedUsername = username.trim();
    const trimmedPassword = password.trim();

    if (!trimmedUsername || !trimmedPassword) {
      if (!trimmedUsername && !trimmedPassword) {
        setError("Please enter your username and password.");
      } else if (!trimmedUsername) {
        setError("Please enter your username.");
      } else {
        setError("Please enter your password.");
      }
      return;
    }

    setIsLoading(true);
    setError("");

    try {
      await login({ username: trimmedUsername, password: trimmedPassword });
      onSubmitSuccess?.();
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.status === 401) {
          setError("Invalid username or password.\nPlease try again.");
        } else if (err.status === 0) {
          setError(
            "Unable to connect to server.\nPlease check your connection.",
          );
        } else {
          setError(err.message || "Login failed.\nPlease try again.");
        }
      } else {
        setError("An unexpected error occurred. Please try again.");
      }
      setIsLoading(false);
    }
  };

  return (
    <>
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
              if (error) setError("");
            }}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                handleSubmit();
              }
            }}
            disabled={isLoading}
            className="border-[#353333]/50 text-white text-lg
            md:text-lg placeholder:text-white/80 h-12 rounded-2xl px-5"
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
            value={password}
            onChange={(e) => {
              setPassword(e.target.value);
              if (error) setError("");
            }}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                handleSubmit();
              }
            }}
            disabled={isLoading}
            className="border-[#353333]/50 text-white text-lg
            md:text-lg placeholder:text-white/80 h-12 rounded-2xl px-5"
            style={{
              background:
                "linear-gradient(0deg, #1D1D1D 0%, rgba(40, 40, 40, 0.22) 100%)",
            }}
          />
        </div>

        <Button
          type="button"
          onClick={(e) => {
            e.preventDefault();
            e.stopPropagation();
            handleSubmit();
          }}
          disabled={isLoading}
          className="w-full border border-[#353333] hover:brightness-110 text-white font-semibold text-lg h-12 rounded-2xl transition-all mt-6 relative overflow-hidden"
          style={{
            background: "linear-gradient(0deg, #1D1D1D 0%, #282828 100%)",
          }}
        >
          <AnimatePresence mode="popLayout" initial={false}>
            <motion.div
              key={isLoading ? "loading" : "sign-in"}
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
              {isLoading ? "" : buttonText}
            </motion.div>
          </AnimatePresence>
        </Button>
      </div>
    </>
  );
}
