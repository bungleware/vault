import { useState, useRef, useEffect } from "react";
import type React from "react";
import { useNavigate } from "@tanstack/react-router";
import type { Project, Folder, SharedTrackResponse } from "@/types/api";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  MoreHorizontal,
  FolderOpen,
  FolderX,
  Trash2,
  Folder as FolderIcon,
  FolderInput,
} from "lucide-react";
import { motion, AnimatePresence } from "motion/react";
import { useFolderContents, usePrefetchFolders } from "@/hooks/useFolders";
import {
  useProjectCoverImage,
  preloadCover,
} from "@/hooks/useProjectCoverImage";
import { useDeleteFolder, useMoveFolder } from "@/hooks/useFolders";
import DeleteFolderModal from "./modals/DeleteFolderModal";
import MoveFolderModal from "./modals/MoveFolderModal";
import { toast } from "@/routes/__root";

type PreviewItem = Project | Folder | SharedTrackResponse;

function ProjectCoverThumbnail({ project }: { project: Project }) {
  const { imageUrl, isLoading } = useProjectCoverImage(project, "medium");

  if (isLoading) {
    return (
      <div className="size-full bg-neutral-800 border-(--card-border) border rounded-2xl animate-pulse" />
    );
  }

  if (imageUrl) {
    return (
      <img
        src={imageUrl}
        alt={`${project.name} cover`}
        className="size-full object-cover border-(--card-border) border rounded-2xl"
        draggable={false}
        loading="eager"
        decoding="sync"
      />
    );
  }

  return (
    <div className="size-full bg-neutral-800 border-(--card-border) border rounded-2xl flex items-center justify-center">
      <span className="text-white/30 text-lg font-bold">
        {String(project.name).charAt(0).toUpperCase()}
      </span>
    </div>
  );
}

function FolderThumbnail({}: { folder: Folder }) {
  return (
    <div className="size-full bg-neutral-700/50 border-(--card-border) border rounded-2xl flex items-center justify-center">
      <FolderIcon className="size-6 text-white/40" />
    </div>
  );
}

function SharedTrackCoverThumbnail({ track }: { track: SharedTrackResponse }) {
  const coverSource =
    track.project_public_id || track.project_id
      ? {
          public_id: String(track.project_public_id ?? track.project_id),
          cover_url: track.cover_url ?? undefined,
        }
      : null;

  const { imageUrl, isLoading } = useProjectCoverImage(
    coverSource ?? undefined,
    "medium",
  );

  const resolvedCover = imageUrl ||
    (track.cover_url
      ? `${track.cover_url}${track.cover_url.includes("?") ? "&" : "?"}size=medium`
      : undefined);

  if (isLoading) {
    return (
      <div className="size-full bg-neutral-800 border-(--card-border) border rounded-2xl animate-pulse" />
    );
  }

  return (
    <div className="size-full bg-neutral-800 border-(--card-border) border rounded-2xl flex items-center justify-center">
      {resolvedCover ? (
        <img
          src={resolvedCover}
          alt={`${track.title} cover`}
          className="size-full object-cover border-(--card-border) border rounded-2xl"
          draggable={false}
          loading="eager"
          decoding="sync"
        />
      ) : (
        <span className="text-white/30 text-lg font-bold">
          {String(track.title).charAt(0).toUpperCase()}
        </span>
      )}
    </div>
  );
}

function PreviewItemThumbnail({ item }: { item: PreviewItem }) {
  if ("shared_by_username" in item) {
    return <SharedTrackCoverThumbnail track={item as SharedTrackResponse} />;
  } else if ("public_id" in item) {
    return <ProjectCoverThumbnail project={item as Project} />;
  } else {
    return <FolderThumbnail folder={item as Folder} />;
  }
}

function IncomingItemCover({ project }: { project: Project }) {
  const { imageUrl } = useProjectCoverImage(project, "medium");

  if (imageUrl) {
    return (
      <img
        src={imageUrl}
        alt={`${project.name} cover`}
        className="size-full object-cover"
        draggable={false}
      />
    );
  }

  return (
    <div className="size-full bg-neutral-800 flex items-center justify-center">
      <span className="text-white text-lg font-bold">
        {String(project.name).charAt(0).toUpperCase()}
      </span>
    </div>
  );
}

interface FolderCardProps {
  folder: { id: string; name: string; items: Project[]; folderId?: number };
  className?: string;
  hoverIncomingItems?: Project[];
  hoverActive?: boolean;
  isDropping?: boolean;
  dragScaleDown?: boolean;
  isDragging?: boolean;
  onEmptyFolder?: (folderId: string) => void;
}

export default function FolderCard({
  folder,
  className,
  hoverIncomingItems = [],
  isDropping = false,
  dragScaleDown = false,
  isDragging = false,
  onEmptyFolder,
}: FolderCardProps) {
  const navigate = useNavigate();
  const deleteFolder = useDeleteFolder();
  const moveFolder = useMoveFolder();
  const prefetchFolders = usePrefetchFolders();

  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [showMoveModal, setShowMoveModal] = useState(false);
  const [isDropdownOpen, setIsDropdownOpen] = useState(false);
  const modalJustClosedRef = useRef(false);
  const isDraggingRef = useRef(false);

  const { data: folderContents } = useFolderContents(folder.folderId);

  useEffect(() => {
    if (!folderContents) return;
    const items: Array<{ public_id: string; cover_url?: string | null }> = [
      ...folderContents.projects,
      ...(folderContents.shared_tracks || []).map((t) => ({
        public_id: String(t.project_public_id ?? t.project_id),
        cover_url: t.cover_url ?? undefined,
      })),
    ];
    for (const item of items.slice(0, 4)) {
      if (item.cover_url) {
        preloadCover(item, "medium");
      }
    }
  }, [folderContents]);

  useEffect(() => {
    if (folder.folderId || !folder.items.length) return;
    for (const item of folder.items.slice(0, 4)) {
      if (item.cover_url) {
        preloadCover(item, "medium");
      }
    }
  }, [folder.folderId, folder.items]);

  useEffect(() => {
    if (isDragging) {
      isDraggingRef.current = true;
    }
  }, [isDragging]);

  const getItemOrder = (item: PreviewItem): number => {
    if ("folder_order" in item) {
      return item.folder_order;
    } else if (
      "custom_order" in item &&
      typeof item.custom_order === "number"
    ) {
      return item.custom_order;
    } else {
      return Number.MAX_SAFE_INTEGER;
    }
  };

  const getPreviewItems = (): PreviewItem[] => {
    if (folder.folderId && folderContents) {
      const sharedTracks = folderContents.shared_tracks || [];
      const allItems: PreviewItem[] = [
        ...folderContents.folders,
        ...folderContents.projects,
        ...sharedTracks,
      ];

      allItems.sort((a, b) => getItemOrder(a) - getItemOrder(b));

      return allItems.slice(0, 4);
    } else {
      return folder.items.slice(0, 4);
    }
  };

  const getTotalCount = (): number => {
    if (folder.folderId && folderContents) {
      const sharedTracks = folderContents.shared_tracks || [];
      return (
        folderContents.projects.length +
        folderContents.folders.length +
        sharedTracks.length
      );
    } else {
      return folder.items.length;
    }
  };

  const previewItems = getPreviewItems();
  const totalCount = getTotalCount();
  const sharedTracks = folderContents?.shared_tracks || [];

  const itemsToShow = (() => {
    if (folder.folderId && folderContents) {
      const allItems: PreviewItem[] = [
        ...folderContents.folders,
        ...folderContents.projects,
        ...sharedTracks,
      ];
      allItems.sort((a, b) => getItemOrder(a) - getItemOrder(b));
      return allItems;
    } else {
      return folder.items;
    }
  })();

  const getGridPosition = (index: number) => {
    const positions = [
      "top-[8px] left-[8px]",
      "top-[8px] right-[8px]",
      "bottom-[8px] left-[8px]",
      "bottom-[8px] right-[8px]",
    ];
    return positions[index] || "";
  };

  const handleOpen = () => {
    if (folder.folderId) {
      navigate({
        to: "/folder/$folderId",
        params: { folderId: String(folder.folderId) },
      });
    }
  };

  const handleDeleteClick = () => {
    setShowDeleteModal(true);
  };

  const handleDeleteConfirm = async () => {
    if (!folder.folderId) return;
    try {
      await deleteFolder.mutateAsync(folder.folderId);
      setShowDeleteModal(false);
      modalJustClosedRef.current = true;
      setTimeout(() => {
        modalJustClosedRef.current = false;
      }, 100);
    } catch (_error) {
      toast.error("Failed to delete folder");
    }
  };

  const handleMoveClick = () => {
    setShowMoveModal(true);
  };

  const handleMoveConfirm = async (parentId: number | null) => {
    if (!folder.folderId) return;
    try {
      await moveFolder.mutateAsync({ id: folder.folderId, parentId });
      setShowMoveModal(false);
      modalJustClosedRef.current = true;
      setTimeout(() => {
        modalJustClosedRef.current = false;
      }, 100);
    } catch (_error) {
      toast.error("Failed to move folder");
    }
  };

  const handleCardClick = (e: React.MouseEvent) => {
    if (isDraggingRef.current) {
      isDraggingRef.current = false;
      return;
    }

    if (modalJustClosedRef.current) {
      modalJustClosedRef.current = false;
      return;
    }

    if (showDeleteModal || showMoveModal) {
      return;
    }

    const target = e.target as HTMLElement;
    if (
      target.closest("button") ||
      target.closest('[role="menuitem"]') ||
      target.closest('[role="menu"]')
    ) {
      return;
    }

    handleOpen();
  };

  return (
    // biome-ignore lint/a11y/noStaticElementInteractions lint/a11y/noNoninteractiveTabindex:
    <div
      className={cn(
        "group select-none cursor-pointer transition-transform duration-300",
        dragScaleDown && isDragging ? "scale-[0.5]" : undefined,
        className,
      )}
      onClick={handleCardClick}
      role="button"
      tabIndex={0}
      data-dropdown-open={isDropdownOpen}
      data-modal-open={showDeleteModal || showMoveModal}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          handleOpen();
        }
      }}
    >
      <div className="relative aspect-square rounded-(--card-border-radius) border border-(--card-border) bg-neutral-800/40 overflow-hidden">
        <div className="grid grid-cols-2 grid-rows-2 size-full gap-1 p-2">
          {[0, 1, 2, 3].map((index) => {
            const item = previewItems[index];
            return (
              <div
                key={
                  item
                    ? "public_id" in item
                      ? item.public_id
                      : `folder-${item.id}`
                    : `empty-${index}`
                }
                className="size-full"
              >
                {item ? <PreviewItemThumbnail item={item} /> : null}
              </div>
            );
          })}
        </div>

        <AnimatePresence>
          {isDropping && hoverIncomingItems.length > 0 && (
            <motion.div
              key="incoming-item"
              className={cn(
                "absolute w-[calc(50%-10px)] h-[calc(50%-10px)] rounded-2xl border-(--card-border) border overflow-hidden z-20",
                getGridPosition(Math.min(itemsToShow.length, 3)),
              )}
              initial={{ opacity: 0, scale: 0.3 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, transition: { duration: 0.15 } }}
              transition={{
                type: "spring",
                stiffness: 500,
                damping: 30,
              }}
            >
              <IncomingItemCover project={hoverIncomingItems[0]} />
            </motion.div>
          )}
        </AnimatePresence>
      </div>
      <motion.div
        className={cn("mt-3 h-11")}
        animate={{ opacity: isDragging ? 0.8 : 1 }}
        transition={{ duration: 0.3 }}
      >
        <div className="relative h-full">
          <div
            className={cn(
              "absolute inset-0",
              isDragging ? "opacity-0" : "opacity-100",
            )}
            style={{
              transition: "opacity 0.3s ease-in-out",
            }}
          >
            <div
              className="truncate text-sm font-semibold text-foreground"
              title={folder.name}
            >
              {folder.name}
            </div>
            <div className="text-xs text-muted-foreground">
              {totalCount} items
            </div>
          </div>

          <div
            className={cn(
              "absolute bottom-0 right-0",
              isDragging ? "opacity-0 pointer-events-none" : undefined,
            )}
          >
            <DropdownMenu
              open={isDropdownOpen}
              onOpenChange={(open) => {
                setIsDropdownOpen(open);
                if (open) prefetchFolders();
              }}
            >
              <DropdownMenuTrigger asChild>
                <Button
                  variant="ghost"
                  size="icon-sm"
                  aria-label="Folder options"
                  className="-mr-3 select-none p-0 h-5 rounded-md hover:bg-muted/30 transition-none"
                  onMouseDown={(e) => e.preventDefault()}
                >
                  <MoreHorizontal />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent
                align="center"
                side="top"
                className="w-44 border-muted bg-background"
              >
                <DropdownMenuItem
                  onSelect={handleOpen}
                  disabled={!folder.folderId}
                >
                  <FolderOpen className="ml-1 mr-1.5 size-4.5" />
                  Open
                </DropdownMenuItem>
                <DropdownMenuItem
                  onSelect={handleMoveClick}
                  disabled={!folder.folderId}
                >
                  <FolderInput className="ml-1 mr-1.5 size-4.5" />
                  Move
                </DropdownMenuItem>
                <DropdownMenuItem
                  onSelect={() => onEmptyFolder?.(folder.id)}
                  disabled={itemsToShow.length === 0}
                >
                  <FolderX className="ml-1 mr-1.5 size-4.5" />
                  Empty
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem
                  variant="destructive"
                  onSelect={handleDeleteClick}
                  disabled={!folder.folderId}
                >
                  <Trash2 className="ml-1 mr-1.5 size-4.5" />
                  Delete
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </div>
      </motion.div>

      {folder.folderId && (
        <>
          <DeleteFolderModal
            isOpen={showDeleteModal}
            onClose={() => {
              setShowDeleteModal(false);
              modalJustClosedRef.current = true;
              setTimeout(() => {
                modalJustClosedRef.current = false;
              }, 100);
            }}
            onConfirm={handleDeleteConfirm}
            folderName={folder.name}
            itemCount={totalCount}
            isDeleting={deleteFolder.isPending}
          />

          <MoveFolderModal
            isOpen={showMoveModal}
            onClose={() => {
              setShowMoveModal(false);
              modalJustClosedRef.current = true;
              setTimeout(() => {
                modalJustClosedRef.current = false;
              }, 100);
            }}
            onConfirm={handleMoveConfirm}
            folderName={folder.name}
            currentFolderId={folder.folderId}
            currentParentId={folderContents?.folder.parent_id}
            isMoving={moveFolder.isPending}
          />
        </>
      )}
    </div>
  );
}
