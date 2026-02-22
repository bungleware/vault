import { useState } from "react";
import { motion, AnimatePresence } from "motion/react";
import { Plus, FolderPlus, FilePlus } from "lucide-react";

interface MorphingAddButtonProps {
  onAddProject: () => void;
  onAddFolder: () => void;
  isCreatingProject?: boolean;
  isCreatingFolder?: boolean;
  className?: string;
  bottomOffset?: string;
}

export default function MorphingAddButton({
  onAddProject,
  onAddFolder,
  isCreatingProject = false,
  isCreatingFolder = false,
  className = "",
  bottomOffset,
}: MorphingAddButtonProps) {
  const [isExpanded, setIsExpanded] = useState(false);

  const handleToggle = () => {
    setIsExpanded(!isExpanded);
  };

  const handleAddProject = () => {
    onAddProject();
    setIsExpanded(false);
  };

  const handleAddFolder = () => {
    onAddFolder();
    setIsExpanded(false);
  };

  const handleBackdropClick = () => {
    setIsExpanded(false);
  };

  return (
    <>
      <AnimatePresence>
        {isExpanded && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.15 }}
            className="fixed inset-0 z-115 bg-black/20"
            onClick={handleBackdropClick}
          />
        )}
      </AnimatePresence>

      <div
        className={`fixed left-1/2 -translate-x-1/2 z-120 ${bottomOffset || "bottom-8"} ${className}`}
      >
        {!isExpanded && (
          <motion.span
            layoutId="morphing-add-button-container"
            className="inline-block"
            style={{
              borderRadius: "24px",
              background:
                "linear-gradient(180deg, var(--button-gradient-from) 0%, var(--button-gradient-to) 100%)",
              border: "1px solid var(--button-border)",
              boxShadow: "0 4px 6px -1px rgba(0, 0, 0, 0.1)",
            }}
            transition={{
              layout: {
                type: "spring",
                stiffness: 800,
                damping: 45,
              },
            }}
          >
            <button
              onClick={handleToggle}
              className="h-10 text-base font-semibold inline-flex items-center justify-center gap-2 whitespace-nowrap px-6 text-primary-foreground hover:brightness-120 transition-all cursor-pointer active:scale-95 w-full"
              style={{
                background: "transparent",
                border: "none",
              }}
            >
              <motion.span
                initial={{ opacity: 0, filter: "blur(4px)" }}
                animate={{ opacity: 1, filter: "blur(0px)" }}
                transition={{ duration: 0.15, delay: 0.05 }}
                className="inline-flex items-center gap-2"
              >
                <Plus className="size-5" />
                Add
              </motion.span>
            </button>
          </motion.span>
        )}

        <AnimatePresence initial={false} mode="popLayout">
          {isExpanded && (
            <motion.div
              layout
              className="overflow-hidden rounded-3xl"
              style={{
                borderRadius: "24px",
                background: "linear-gradient(0deg, #151515 0%, #1D1D1D 100%)",
                border: "1px solid #353333",
                boxShadow: "0 25px 50px -12px rgba(0, 0, 0, 0.25)",
                padding: "8px",
              }}
              layoutId="morphing-add-button-container"
              onClick={(e) => e.stopPropagation()}
              exit={{ opacity: 0 }}
              transition={{
                layout: {
                  type: "spring",
                  stiffness: 800,
                  damping: 45,
                },
                opacity: { duration: 0.05 },
              }}
            >
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.08 }}
                className="relative flex flex-col gap-2"
              >
                <motion.button
                  initial={{
                    opacity: 0,
                    scale: 0.9,
                    filter: "blur(8px)",
                  }}
                  animate={{
                    opacity: 1,
                    scale: 1,
                    filter: "blur(0px)",
                  }}
                  exit={{
                    opacity: 0,
                    filter: "blur(4px)",
                  }}
                  transition={{
                    type: "spring",
                    stiffness: 500,
                    damping: 35,
                    delay: 0.05,
                  }}
                  onClick={handleAddFolder}
                  disabled={isCreatingFolder}
                  className="h-10 text-base font-semibold rounded-2xl px-6 inline-flex items-center justify-center gap-2 whitespace-nowrap bg-white/5 hover:bg-white/10 transition-colors cursor-pointer active:scale-95 disabled:opacity-50 disabled:pointer-events-none text-white border border-[#353333]"
                >
                  <FolderPlus className="size-5" />
                  Add folder
                </motion.button>
                <motion.button
                  initial={{
                    opacity: 0,
                    scale: 0.9,
                    filter: "blur(8px)",
                  }}
                  animate={{
                    opacity: 1,
                    scale: 1,
                    filter: "blur(0px)",
                  }}
                  exit={{
                    opacity: 0,
                    filter: "blur(4px)",
                  }}
                  transition={{
                    type: "spring",
                    stiffness: 500,
                    damping: 35,
                    delay: 0.08,
                  }}
                  onClick={handleAddProject}
                  disabled={isCreatingProject}
                  className="h-10 text-base font-semibold rounded-2xl px-6 inline-flex items-center justify-center gap-2 whitespace-nowrap bg-white/5 hover:bg-white/10 transition-colors cursor-pointer active:scale-95 disabled:opacity-50 disabled:pointer-events-none text-white border border-[#353333]"
                >
                  <FilePlus className="size-5" />
                  Add project
                </motion.button>
              </motion.div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </>
  );
}
