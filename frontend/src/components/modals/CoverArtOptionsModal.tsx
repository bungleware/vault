import { X, FolderOpen, Download } from "lucide-react";
import { AnimatePresence, motion } from "motion/react";
import { createPortal } from "react-dom";
import { Button } from "@/components/ui/button";

interface CoverArtOptionsModalProps {
  isOpen: boolean;
  onClose: () => void;
  onLibraryClick: () => void;
  onExportClick: () => void;
  hasExistingCover: boolean;
  canEdit?: boolean;
  canDownload?: boolean;
}

export default function CoverArtOptionsModal({
  isOpen,
  onClose,
  onLibraryClick,
  onExportClick,
  hasExistingCover,
  canEdit = true,
  canDownload = true,
}: CoverArtOptionsModalProps) {
  const handleLibraryClick = () => {
    onLibraryClick();
    onClose();
  };

  const handleExportClick = () => {
    onExportClick();
    onClose();
  };

  return createPortal(
    <AnimatePresence>
      {isOpen && (
        <>
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.15 }}
            className="fixed inset-0 bg-black/50 z-200"
            onClick={onClose}
          />

          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.95 }}
            transition={{
              duration: 0.15,
              ease: [0.16, 1, 0.3, 1],
            }}
            className="fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-201 w-[calc(100%-2rem)] sm:w-full max-w-[400px]"
            onClick={(e) => e.stopPropagation()}
          >
            <div
              className="relative flex flex-col overflow-hidden rounded-[34px] text-white shadow-2xl border border-[#292828]"
              style={{
                background: "linear-gradient(0deg, #151515 0%, #1D1D1D 100%)",
              }}
            >
              <div className="flex items-center justify-between p-5 border-b border-white/10">
                <h3 className="text-lg font-semibold">Cover Art</h3>
                <Button
                  size="icon-lg"
                  onClick={onClose}
                  aria-label="Close modal"
                >
                  <X className="size-5" />
                </Button>
              </div>

              <div className="p-4 space-y-2">
                {canEdit && (
                  <button
                    onClick={handleLibraryClick}
                    className="w-full flex items-center gap-4 p-4 rounded-2xl bg-white/5 hover:bg-white/10 transition-colors text-left"
                    type="button"
                  >
                    <div className="flex items-center justify-center w-12 h-12 rounded-full bg-white/10">
                      <FolderOpen className="size-5" />
                    </div>
                    <div className="flex-1">
                      <div className="font-semibold text-base">Library</div>
                      <div className="text-sm text-white/60">
                        Choose from your files
                      </div>
                    </div>
                  </button>
                )}

                {hasExistingCover && canDownload && (
                  <button
                    onClick={handleExportClick}
                    className="w-full flex items-center gap-4 p-4 rounded-2xl bg-white/5 hover:bg-white/10 transition-colors text-left"
                    type="button"
                  >
                    <div className="flex items-center justify-center w-12 h-12 rounded-full bg-white/10">
                      <Download className="size-5" />
                    </div>
                    <div className="flex-1">
                      <div className="font-semibold text-base">Export</div>
                      <div className="text-sm text-white/60">
                        Download cover art
                      </div>
                    </div>
                  </button>
                )}
              </div>
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>,
    document.body,
  );
}
