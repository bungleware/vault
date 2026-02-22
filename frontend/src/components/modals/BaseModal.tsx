import { useEffect } from "react";
import { createPortal } from "react-dom";
import { AnimatePresence, motion } from "motion/react";

interface BaseModalProps {
  isOpen: boolean;
  onClose: () => void;
  children: React.ReactNode;
  maxWidth?: "sm" | "md" | "lg" | "xl" | "2xl";
  disableClose?: boolean;
  dataAttributes?: Record<string, string>;
}

const maxWidthClasses = {
  sm: "max-w-sm",
  md: "max-w-md",
  lg: "max-w-lg",
  xl: "max-w-xl",
  "2xl": "max-w-2xl",
};

export default function BaseModal({
  isOpen,
  onClose,
  children,
  maxWidth = "md",
  disableClose = false,
  dataAttributes = {},
}: BaseModalProps) {
  useEffect(() => {
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !disableClose) {
        onClose();
      }
    };

    if (isOpen) {
      document.addEventListener("keydown", handleEscape);
      document.body.style.overflow = "hidden";
    }

    return () => {
      document.removeEventListener("keydown", handleEscape);
      document.body.style.overflow = "unset";
    };
  }, [isOpen, disableClose, onClose]);

  return (
    <>
      {createPortal(
        <AnimatePresence>
          {isOpen && (
            <>
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.1 }}
                className="fixed inset-0 z-1000 bg-black/80"
                onClick={disableClose ? undefined : onClose}
                {...(dataAttributes["data-modal-backdrop"] && {
                  "data-modal-backdrop": dataAttributes["data-modal-backdrop"],
                })}
              />

              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.1 }}
                className="fixed inset-0 z-1000 flex items-center justify-center p-4 pointer-events-none"
                {...(dataAttributes["data-modal-container"] && {
                  "data-modal-container":
                    dataAttributes["data-modal-container"],
                })}
              >
                <motion.div
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: 8 }}
                  transition={{ duration: 0.1 }}
                  className={`relative z-10 w-full ${maxWidthClasses[maxWidth]} border border-[#292828] rounded-[34px] shadow-2xl overflow-hidden pointer-events-auto`}
                  style={{
                    background:
                      "linear-gradient(0deg, #151515 0%, #1D1D1D 100%)",
                  }}
                  onClick={(e) => e.stopPropagation()}
                  {...(dataAttributes["data-modal-content"] && {
                    "data-modal-content": dataAttributes["data-modal-content"],
                  })}
                >
                  {children}
                </motion.div>
              </motion.div>
            </>
          )}
        </AnimatePresence>,
        document.body,
      )}
    </>
  );
}
