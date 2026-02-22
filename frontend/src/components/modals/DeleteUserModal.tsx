import { useEffect, useState } from "react";
import { AnimatePresence, motion } from "motion/react";
import { Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import type { UserResponse } from "@/api/admin";

interface DeleteUserModalProps {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: (password?: string) => void;
  user: UserResponse | null;
  isDeleting: boolean;
  requirePassword?: boolean;
  title?: string;
  warningText?: string;
  confirmText?: string;
  error?: string | null;
}

export default function DeleteUserModal({
  isOpen,
  onClose,
  onConfirm,
  user,
  isDeleting,
  requirePassword = false,
  title = "Delete User",
  warningText,
  confirmText = "Delete User",
  error,
}: DeleteUserModalProps) {
  const [password, setPassword] = useState("");

  useEffect(() => {
    if (!isOpen) {
      setPassword("");
    }
  }, [isOpen]);

  useEffect(() => {
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !isDeleting) {
        onClose();
      }
    };

    if (isOpen) {
      document.addEventListener("keydown", handleEscape);
    }

    return () => {
      document.removeEventListener("keydown", handleEscape);
    };
  }, [isOpen, isDeleting, onClose]);

  const handleConfirm = () => {
    onConfirm(requirePassword ? password : undefined);
  };

  const defaultWarning = `This will permanently delete user "${user?.username}" and all associated data. This action cannot be undone.`;

  return (
    <AnimatePresence>
      {isOpen && (
        <motion.div
          key="delete-user-modal"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.15 }}
          className="fixed inset-0 z-1100 flex items-center justify-center p-4"
        >
          <div
            className="absolute inset-0 bg-black/80"
            onClick={isDeleting ? undefined : onClose}
          />

          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.95 }}
            transition={{ duration: 0.15 }}
            className="relative z-10 w-full max-w-md border border-[#292828] rounded-[34px] shadow-2xl overflow-hidden"
            style={{
              background: "linear-gradient(0deg, #151515 0%, #1D1D1D 100%)",
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="p-6 md:p-8">
              <div className="flex justify-center mb-4">
                <div className="w-14 h-14 rounded-full flex items-center justify-center bg-red-500/10 border border-red-500/20">
                  <Trash2 className="size-7 text-red-500" />
                </div>
              </div>

              <h2 className="text-2xl font-semibold text-white text-center mb-3">
                {title}
              </h2>

              <div
                className="rounded-2xl border border-red-500/30 p-4 mb-6"
                style={{
                  background:
                    "linear-gradient(0deg, #2a1515 0%, rgba(40, 20, 20, 0.3) 100%)",
                }}
              >
                <p
                  className="text-sm text-red-400 font-light leading-relaxed text-center"
                  style={{ fontFamily: '"IBM Plex Mono", monospace' }}
                >
                  {warningText || defaultWarning}
                </p>
              </div>

              {requirePassword && (
                <div className="mb-6">
                  <label className="text-sm text-[#848484] mb-2 block">
                    Enter your password to confirm
                  </label>
                  <input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" && password.trim()) {
                        handleConfirm();
                      }
                    }}
                    placeholder="Password"
                    className="w-full bg-[#191919] border border-[#353333] rounded-lg px-4 py-2.5 text-white text-sm placeholder:text-[#5a5a5a] outline-none focus:border-[#555]"
                    autoFocus
                    disabled={isDeleting}
                  />
                  {error && (
                    <p className="text-xs text-[#ff5656] mt-2">{error}</p>
                  )}
                </div>
              )}

              {!requirePassword && (
                <p className="text-sm text-muted-foreground text-center mb-6">
                  Are you sure you want to proceed with deleting this user?
                </p>
              )}

              <div className="flex flex-col gap-3">
                <Button
                  onClick={handleConfirm}
                  disabled={isDeleting || (requirePassword && !password.trim())}
                  variant="destructive"
                  className="w-full bg-[#381d1d] hover:bg-[#4a2626] border-[#7f3434] border-[0.5px] text-[#ff5656] font-medium"
                >
                  {isDeleting ? (
                    <>
                      <div className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-[#ff5656]/20 border-t-[#ff5656] mr-2" />
                      Deleting...
                    </>
                  ) : (
                    confirmText
                  )}
                </Button>
                <Button
                  onClick={onClose}
                  disabled={isDeleting}
                  className="w-full"
                >
                  Cancel
                </Button>
              </div>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
