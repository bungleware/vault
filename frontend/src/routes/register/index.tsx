import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useState, useEffect, useRef, type FormEvent } from "react";
import { useAuth } from "../../contexts/AuthContext";
import { Button } from "../../components/ui/button";
import { Input } from "../../components/ui/input";
import { Label } from "../../components/ui/label";
import { ApiError } from "../../api/client";
import { motion, AnimatePresence } from "motion/react";

export const Route = createFileRoute("/register/")({
  component: RegisterPage,
});

function RegisterPage() {
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const errorWrapperRef = useRef<HTMLDivElement>(null);
  const [errorHeight, setErrorHeight] = useState(0);

  const { register, isAuthenticated, isLoading: authLoading } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    if (!authLoading && isAuthenticated) {
      navigate({ to: "/" });
    }
  }, [isAuthenticated, authLoading, navigate]);

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

  if (authLoading || isAuthenticated) {
    return <div className="min-h-screen bg-[#181818]" />;
  }

  const handleSubmit = async (e?: FormEvent) => {
    e?.preventDefault();

    const trimmedUsername = username.trim();
    const trimmedEmail = email.trim();
    const trimmedPassword = password.trim();
    const trimmedConfirmPassword = confirmPassword.trim();

    if (!trimmedUsername || !trimmedEmail || !trimmedPassword) {
      if (!trimmedUsername && !trimmedEmail && !trimmedPassword) {
        setError("Please enter your username, email, and password.");
      } else if (!trimmedUsername) {
        setError("Please enter your username.");
      } else if (!trimmedEmail) {
        setError("Please enter your email.");
      } else {
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

    if (trimmedPassword !== trimmedConfirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    setIsLoading(true);
    setError("");

    try {
      await register({ username: trimmedUsername, email: trimmedEmail, password: trimmedPassword });
      navigate({ to: "/" });
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message || "Registration failed. Please try again.");
      } else {
        setError("An unexpected error occurred. Please try again.");
      }
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
              Create your account
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
                md:text-lg placeholder:text-white/40 h-12 rounded-2xl px-5"
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
                value={email}
                onChange={(e) => {
                  setEmail(e.target.value);
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
                md:text-lg placeholder:text-white/40 h-12 rounded-2xl px-5"
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
                md:text-lg placeholder:text-white/40 h-12 rounded-2xl px-5"
                style={{
                  background:
                    "linear-gradient(0deg, #1D1D1D 0%, rgba(40, 40, 40, 0.22) 100%)",
                }}
              />
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
                md:text-lg placeholder:text-white/40 h-12 rounded-2xl px-5"
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
            </Button>
          </div>
        </motion.div>
      </div>
    </div>
  );
}
