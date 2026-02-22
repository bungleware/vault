import { useMemo, useEffect } from "react";
import { FolderIcon, Home } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useAllFolders } from "@/hooks/useFolders";
import type { Folder } from "@/types/api";
import BaseModal from "./BaseModal";

interface MoveFolderModalProps {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: (folderId: number | null) => void;
  folderName: string;
  currentFolderId: number;
  currentParentId?: number | null;
  isMoving?: boolean;
}

function getDescendantFolderIds(
  folderId: number,
  allFolders: Folder[],
): Set<number> {
  const descendants = new Set<number>();
  const queue = [folderId];

  while (queue.length > 0) {
    const currentId = queue.shift()!;
    const children = allFolders.filter((f) => f.parent_id === currentId);
    for (const child of children) {
      descendants.add(child.id);
      queue.push(child.id);
    }
  }

  return descendants;
}

export default function MoveFolderModal({
  isOpen,
  onClose,
  onConfirm,
  folderName,
  currentFolderId,
  currentParentId: _currentParentId,
  isMoving = false,
}: MoveFolderModalProps) {
  const {
    data: allFolders,
    isLoading: isLoadingFolders,
    refetch,
  } = useAllFolders();

  useEffect(() => {
    if (isOpen) {
      refetch();
    }
  }, [isOpen, refetch]);

  const folders = useMemo(() => {
    if (!allFolders) return [];

    const descendantIds = getDescendantFolderIds(currentFolderId, allFolders);

    return allFolders.filter(
      (f) => f.id !== currentFolderId && !descendantIds.has(f.id),
    );
  }, [allFolders, currentFolderId]);

  const handleFolderClick = (folderId: number | null) => {
    if (!isMoving) {
      onConfirm(folderId);
    }
  };

  return (
    <BaseModal
      isOpen={isOpen}
      onClose={onClose}
      disableClose={isMoving}
      dataAttributes={{
        "data-modal-backdrop": "true",
        "data-modal-container": "true",
        "data-modal-content": "true",
      }}
    >
      <div className="p-6 md:p-8 space-y-6">
        <div className="text-center space-y-3 p-3">
          <h2 className="text-2xl font-semibold text-white">Move Folder</h2>
          <p className="text-sm text-muted-foreground">
            Click a folder to move{" "}
            <span className="text-white font-medium">
              &ldquo;{folderName}&rdquo;
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
                {folders.length === 0 ? (
                  <div className="text-center py-8 text-muted-foreground">
                    No folders available.
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
