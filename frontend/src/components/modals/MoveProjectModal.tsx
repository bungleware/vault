import { useMemo } from "react";
import { FolderIcon, Home } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useAllFolders } from "@/hooks/useFolders";
import BaseModal from "./BaseModal";

interface MoveProjectModalProps {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: (folderId: number | null) => void;
  projectName: string;
  currentFolderId?: number | null;
  isMoving?: boolean;
}

export default function MoveProjectModal({
  isOpen,
  onClose,
  onConfirm,
  projectName,
  currentFolderId,
  isMoving = false,
}: MoveProjectModalProps) {
  const { data: allFolders, isLoading: isLoadingFolders } = useAllFolders();

  const folders = useMemo(() => {
    if (!allFolders) return [];
    return currentFolderId
      ? allFolders.filter((f) => f.id !== currentFolderId)
      : allFolders;
  }, [allFolders, currentFolderId]);

  const handleFolderClick = (folderId: number | null) => {
    if (!isMoving) {
      onConfirm(folderId);
    }
  };

  return (
    <BaseModal isOpen={isOpen} onClose={onClose} disableClose={isMoving}>
      <div className="p-6 md:p-8 space-y-6">
        <div className="text-center space-y-3 p-3">
          <h2 className="text-2xl font-semibold text-white">Move Project</h2>
          <p className="text-sm text-muted-foreground">
            Click a folder to move{" "}
            <span className="text-white font-medium">
              &ldquo;{projectName}&rdquo;
            </span>{" "}
            to.
          </p>
        </div>

        <div className="space-y-2">
          <div className="max-h-[300px] overflow-y-auto rounded-2xl border border-white/10">
            {isLoadingFolders ? (
              <div className="text-center py-8 text-muted-foreground">
                Loading folders...
              </div>
            ) : (
              <>
                {currentFolderId && (
                  <button
                    onClick={() => handleFolderClick(null)}
                    disabled={isMoving}
                    className={`w-full px-4 py-3 text-left transition-all border-b border-white/5 flex items-center gap-2 ${
                      isMoving
                        ? "opacity-50 cursor-not-allowed"
                        : "bg-white/5 hover:bg-white/10"
                    }`}
                  >
                    <Home className="size-4 text-white" />
                    <span className="text-base font-medium text-white">
                      Root (No Folder)
                    </span>
                  </button>
                )}
                {folders.length === 0 && !currentFolderId ? (
                  <div className="text-center py-8 text-muted-foreground">
                    No folders available. Create a folder first.
                  </div>
                ) : (
                  folders.map((folder) => (
                    <button
                      key={folder.id}
                      onClick={() => handleFolderClick(folder.id)}
                      disabled={isMoving}
                      className={`w-full px-4 py-3 text-left transition-all border-b border-white/5 last:border-b-0 flex items-center gap-2 ${
                        isMoving
                          ? "opacity-50 cursor-not-allowed"
                          : "bg-white/5 hover:bg-white/10"
                      }`}
                    >
                      <FolderIcon className="size-4 text-white" />
                      <span className="text-base font-medium text-white">
                        {folder.name}
                      </span>
                    </button>
                  ))
                )}
              </>
            )}
          </div>
        </div>

        <div className="pt-2">
          <Button onClick={onClose} disabled={isMoving} className="w-full">
            Cancel
          </Button>
        </div>
      </div>
    </BaseModal>
  );
}
