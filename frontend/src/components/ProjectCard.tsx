import { useEffect, useRef, useState } from "react";
import type React from "react";

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
  Pause,
  Play,
  FolderOpen,
  Pencil,
  Trash2,
  FolderInput,
  Copy,
  ListPlus,
  Download,
  LogOut,
  Users,
} from "lucide-react";

import type { Project } from "@/types/api";
import { cn } from "@/lib/utils";
import { useAuth } from "@/contexts/AuthContext";
import { useNavigate } from "@tanstack/react-router";
import {
  CROSSFADE_DURATION_MS,
  BLUR_DURATION_MS,
  CROSSFADE_BLUR_PX,
  CROSSFADE_EASING,
  BLUR_EASING,
} from "@/lib/constants";
import { motion, useMotionValue, useSpring, useTransform } from "motion/react";
import {
  useDeleteProject,
  useMoveProject,
  useDuplicateProject,
  useExportProject,
} from "@/hooks/useProjects";
import { usePrefetchFolders } from "@/hooks/useFolders";
import { useTracks } from "@/hooks/useTracks";
import { useAudioPlayer } from "@/contexts/AudioPlayerContext";
import DeleteProjectModal from "./modals/DeleteProjectModal";
import MoveProjectModal from "./modals/MoveProjectModal";
import { toast } from "@/routes/__root";
import { useProjectCoverImage } from "@/hooks/useProjectCoverImage";
import { Filter } from "virtual:refractionFilter?width=48&height=48&radius=16&bezelWidth=12&glassThickness=40&refractiveIndex=1.45&bezelType=convex_squircle";

function IncomingItemCover({ project }: { project: Project }) {
  const { imageUrl } = useProjectCoverImage(project, "medium");

  if (imageUrl) {
    return (
      <img
        src={imageUrl}
        alt={`${project.name} cover`}
        className="size-full object-cover"
        draggable={false}
        loading="lazy"
        decoding="async"
      />
    );
  }

  return (
    <div className="size-full bg-neutral-800 flex items-center justify-center text-white text-lg font-bold">
      {String(project.name).charAt(0).toUpperCase()}
    </div>
  );
}

interface ProjectCardProps {
  project: Project;
  className?: string;
  dragHandleProps?: {
    onPointerDown: (event: React.PointerEvent) => void;
    onPointerUp?: (event: React.PointerEvent) => void;
    onPointerMove?: (event: React.PointerEvent) => void;
  } & React.HTMLAttributes<HTMLDivElement>;
  isDragging?: boolean;
  dragScaleDown?: boolean;
  hoverAsFolder?: boolean;
  hoverFolderItems?: Project[];
  isDropping?: boolean;
  isBeingDropped?: boolean;
  isOwned?: boolean;
  canExport?: boolean;
  isShared?: boolean;
  sharedByUsername?: string | null;
  onLeaveClick?: () => void;
}

export default function ProjectCard({
  project,
  className,
  dragHandleProps,
  isDragging,
  dragScaleDown,
  hoverAsFolder,
  hoverFolderItems = [],
  isDropping = false,
  isOwned = true,
  canExport = true,
  isShared = false,
  sharedByUsername,
  onLeaveClick,
}: ProjectCardProps) {
  const { user } = useAuth();
  const navigate = useNavigate();
  const deleteProject = useDeleteProject();
  const moveProject = useMoveProject();
  const duplicateProject = useDuplicateProject();
  const exportProject = useExportProject();
  const prefetchFolders = usePrefetchFolders();
  const { data: tracks = [], isLoading: isLoadingTracks } = useTracks(
    project.id,
  );
  const { addProjectToQueue, play, pause, isPlaying, currentTrack } =
    useAudioPlayer();
  const { imageUrl: coverImage } = useProjectCoverImage(project, "medium");
  const [isTextCrossfading, setIsTextCrossfading] = useState(false);
  const prevHoverRef = useRef<boolean | undefined>(undefined);
  const [, setLastHoverFolderItems] = useState<Project[]>([]);
  const isDraggingRef = useRef(false);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [showMoveModal, setShowMoveModal] = useState(false);
  const modalJustClosedRef = useRef(false);
  const authorDisplay =
    (typeof project.author_override === "string" &&
    project.author_override.trim().length > 0
      ? project.author_override
      : sharedByUsername || user?.username) || "Unknown";

  const playButtonPointerDown = useMotionValue(0);
  const playButtonIsUp = useTransform(
    () => (playButtonPointerDown.get() > 0.5 ? 1 : 0) as number,
  );

  const playButtonBlurBase = useMotionValue(0);
  const playButtonBlur = useSpring(playButtonBlurBase, {
    damping: 30,
    stiffness: 200,
  });
  const playButtonSpecularOpacity = useMotionValue(0.6);
  const playButtonSpecularSaturation = useMotionValue(12);
  const playButtonRefractionBase = useMotionValue(1.1);

  useEffect(() => {
    const timer = setTimeout(() => {
      playButtonBlurBase.set(3);
    }, 280);
    return () => clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const playButtonPressMultiplier = useTransform(
    playButtonIsUp as any,
    [0, 1],
    [0.4, 0.9],
  );

  const playButtonScaleRatio = useSpring(
    useTransform(
      [playButtonPressMultiplier, playButtonRefractionBase],
      ([m, base]) => (Number(m) || 0) * (Number(base) || 0),
    ),
  );

  const playButtonScaleSpring = useSpring(
    useTransform(playButtonIsUp as any, [0, 1], [1, 0.95]),
    { damping: 80, stiffness: 2000 },
  );

  const playButtonBackgroundOpacity = useMotionValue(0.7);

  const playButtonBackgroundColor = useTransform(
    playButtonBackgroundOpacity,
    (op) => `rgba(40, 39, 39, ${op})`,
  );

  const goToProject = () => {
    navigate({
      to: "/project/$projectId",
      params: { projectId: String(project.public_id) },
    });
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

    goToProject();
  };

  const handleCardKeyDown = (event: React.KeyboardEvent<HTMLDivElement>) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      goToProject();
    }
  };

  const handleDeleteClick = () => {
    setShowDeleteModal(true);
  };

  const handleDeleteConfirm = async () => {
    try {
      await deleteProject.mutateAsync(project.public_id);
      setShowDeleteModal(false);
      modalJustClosedRef.current = true;
      setTimeout(() => {
        modalJustClosedRef.current = false;
      }, 100);
    } catch (_error) {
      toast.error("Failed to delete project");
    }
  };

  const handleMoveClick = () => {
    setShowMoveModal(true);
  };

  const handleMoveConfirm = async (folderId: number | null) => {
    try {
      await moveProject.mutateAsync({ id: project.public_id, folderId });
      setShowMoveModal(false);
      modalJustClosedRef.current = true;
      setTimeout(() => {
        modalJustClosedRef.current = false;
      }, 100);
    } catch (error) {
      const errorMessage =
        error instanceof Error && error.message.includes("not found")
          ? "Project or folder not found. It may have been deleted."
          : "Failed to move project";
      toast.error(errorMessage);
      setShowMoveModal(false);
    }
  };

  const handleDuplicateClick = async () => {
    try {
      await duplicateProject.mutateAsync(project.public_id);
    } catch (_error) {
      toast.error("Failed to duplicate project");
    }
  };

  const handleExportClick = async () => {
    try {
      await exportProject.mutateAsync({
        id: project.public_id,
        projectName: String(project.name),
      });
    } catch (_error) {
      toast.error("Failed to export project");
    }
  };

  const handleAddToQueueClick = () => {
    if (isLoadingTracks) {
      toast.error("Loading tracks...");
      return;
    }
    if (tracks.length === 0) {
      toast.error("No tracks to add to queue");
      return;
    }

    const projectTracks = tracks.map((t) => ({
      id: t.public_id,
      title: String(t.title),
      artist: t.artist,
      projectName: String(project.name),
      coverUrl: coverImage,
      projectId: project.public_id,
      projectCoverUrl: project.cover_url ?? undefined,
      waveform: t.waveform,
      versionId: t.active_version_id ?? undefined,
    }));

    addProjectToQueue(projectTracks);
    toast.success(
      `Added ${tracks.length} track${tracks.length === 1 ? "" : "s"} to queue`,
    );
  };

  const handlePlayPause = () => {
    if (tracks.length === 0) return;

    const currentTrackExists =
      currentTrack && tracks.some((t) => t.public_id === currentTrack.id);

    if (isPlaying && currentTrackExists) {
      pause();
      return;
    }

    const trackToPlay =
      (currentTrack && tracks.find((t) => t.public_id === currentTrack.id)) ||
      tracks[0];

    if (trackToPlay) {
      const trackIndex = tracks.findIndex(
        (t) => t.public_id === trackToPlay.public_id,
      );

      const tracksAfterPlaying =
        trackIndex >= 0 ? tracks.slice(trackIndex + 1) : [];

      const reorderedTracks =
        trackIndex >= 0
          ? [...tracks.slice(trackIndex), ...tracks.slice(0, trackIndex)]
          : tracks;

      const projectTracks = reorderedTracks.map((t) => ({
        id: t.public_id,
        title: String(t.title),
        artist: t.artist,
        projectName: String(project.name),
        coverUrl: coverImage,
        projectId: project.public_id,
        projectCoverUrl: project.cover_url ?? undefined,
        waveform: t.waveform,
        versionId: t.active_version_id ?? undefined,
      }));

      const queueTracks = tracksAfterPlaying.map((t) => ({
        id: t.public_id,
        title: String(t.title),
        artist: t.artist,
        projectName: String(project.name),
        coverUrl: coverImage,
        projectId: project.public_id,
        projectCoverUrl: project.cover_url ?? undefined,
        waveform: t.waveform,
        versionId: t.active_version_id ?? undefined,
      }));

      play(
        {
          id: trackToPlay.public_id,
          title: String(trackToPlay.title),
          artist: trackToPlay.artist,
          projectName: String(project.name),
          coverUrl: coverImage,
          projectId: project.public_id,
          projectCoverUrl: project.cover_url ?? undefined,
          waveform: trackToPlay.waveform,
          versionId: trackToPlay.active_version_id ?? undefined,
        },
        projectTracks,
        true,
        false,
        queueTracks,
      );
    }
  };

  useEffect(() => {
    if (isDragging) {
      isDraggingRef.current = true;
    }
  }, [isDragging]);

  useEffect(() => {
    if (prevHoverRef.current === undefined) {
      prevHoverRef.current = hoverAsFolder;
      return;
    }
    if (prevHoverRef.current !== hoverAsFolder) {
      setIsTextCrossfading(true);
      const t = setTimeout(
        () => setIsTextCrossfading(false),
        CROSSFADE_DURATION_MS,
      );
      prevHoverRef.current = hoverAsFolder;
      return () => clearTimeout(t);
    }
    prevHoverRef.current = hoverAsFolder;
  }, [hoverAsFolder]);

  useEffect(() => {
    if (hoverAsFolder && hoverFolderItems && hoverFolderItems.length > 0) {
      setLastHoverFolderItems(hoverFolderItems);
    }
  }, [hoverAsFolder, hoverFolderItems]);

  return (
    // biome-ignore lint/a11y/noStaticElementInteractions lint/a11y/noNoninteractiveTabindex:
    <div
      className={cn(
        "group select-none cursor-pointer transition-transform duration-300",
        dragScaleDown && isDragging ? "scale-[0.5]" : undefined,
        className,
      )}
      onClick={handleCardClick}
      onKeyDown={handleCardKeyDown}
      role="button"
      tabIndex={0}
    >
      <div
        className={cn(
          "relative aspect-square rounded-(--card-border-radius) border border-(--card-border) bg-neutral-800/40",
        )}
        style={{ touchAction: "auto" }}
        {...dragHandleProps}
      >
        <motion.div
          className={cn(
            "absolute overflow-hidden",
            "transition-[top,left,right,bottom,border-radius] duration-200",
            !coverImage && "",
            hoverAsFolder
              ? "top-2 left-2 right-[calc(50%+2px)] bottom-[calc(50%+2px)] rounded-2xl border-(--card-border) border"
              : "inset-0 rounded-(--card-border-radius)",
          )}
          animate={{ opacity: isDragging ? 0.8 : 1 }}
          transition={{ duration: 0.3 }}
        >
          {coverImage ? (
            <img
              src={coverImage}
              alt={String(project.name)}
              className="size-full object-cover"
              draggable={false}
              loading="lazy"
              decoding="async"
            />
          ) : (
            <div className="size-full bg-neutral-800 flex items-center justify-center"></div>
          )}
        </motion.div>

        {isDropping && hoverFolderItems.length > 0 && (
          <motion.div
            className="absolute top-2 right-2 w-[calc(50%-10px)] h-[calc(50%-10px)] rounded-2xl border-(--card-border) border overflow-hidden z-20"
            initial={{ opacity: 0, scale: 0.3 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{
              type: "spring",
              stiffness: 500,
              damping: 30,
            }}
          >
            <IncomingItemCover project={hoverFolderItems[0]} />
          </motion.div>
        )}

        <Filter
          id={`play-button-filter-${project.public_id}`}
          blur={playButtonBlur}
          scaleRatio={playButtonScaleRatio}
          specularOpacity={playButtonSpecularOpacity}
          specularSaturation={playButtonSpecularSaturation}
        />

        <motion.button
          type="button"
          aria-label={
            isPlaying &&
            currentTrack &&
            tracks.some((t) => t.public_id === currentTrack.id)
              ? "Pause"
              : "Play"
          }
          className={cn(
            "absolute -bottom-3 -right-3 z-10 shadow-md transition-opacity size-12 rounded-2xl flex items-center justify-center",
            isDragging || hoverAsFolder
              ? "opacity-0 pointer-events-none"
              : undefined,
          )}
          style={{
            backdropFilter: `url(#play-button-filter-${project.public_id})`,
            backgroundColor: playButtonBackgroundColor,
            scale: playButtonScaleSpring,
          }}
          onClick={(e) => {
            e.stopPropagation();
            handlePlayPause();
          }}
          onMouseDown={() => playButtonPointerDown.set(1)}
          onMouseUp={() => playButtonPointerDown.set(0)}
          onMouseLeave={() => playButtonPointerDown.set(0)}
        >
          {isPlaying &&
          currentTrack &&
          tracks.some((t) => t.public_id === currentTrack.id) ? (
            <Pause className="size-5" fill="white" stroke="white" />
          ) : (
            <Play className="size-5" fill="white" stroke="white" />
          )}
        </motion.button>
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
              isDragging || hoverAsFolder ? "opacity-0" : "opacity-100",
            )}
            style={{
              transition: `opacity ${CROSSFADE_DURATION_MS}ms ${CROSSFADE_EASING}, filter ${BLUR_DURATION_MS}ms ${BLUR_EASING}`,
              filter: isTextCrossfading
                ? `blur(${CROSSFADE_BLUR_PX}px)`
                : undefined,
            }}
          >
            <div
              className="flex items-center gap-2 text-sm font-semibold text-foreground"
              title={String(project.name)}
            >
              <span className="truncate">{String(project.name)}</span>
            </div>
            <div className="flex min-w-0 items-center gap-2 text-xs text-muted-foreground">
              {isShared && (
                <Users className="size-3 text-muted-foreground shrink-0" />
              )}
              <span className="truncate" title={authorDisplay}>
                {authorDisplay}
              </span>
            </div>
          </div>

          <div
            className={cn(
              "absolute inset-0",
              hoverAsFolder && !isDragging ? "opacity-100" : "opacity-0",
            )}
            style={{
              transition: `opacity ${CROSSFADE_DURATION_MS}ms ${CROSSFADE_EASING}, filter ${BLUR_DURATION_MS}ms ${BLUR_EASING}`,
              filter: isTextCrossfading
                ? `blur(${CROSSFADE_BLUR_PX}px)`
                : undefined,
            }}
            aria-hidden={!(hoverAsFolder && !isDragging)}
          >
            <div
              className="truncate text-sm font-semibold text-foreground"
              title="New Folder"
            >
              New Folder
            </div>
            <div className="text-xs text-muted-foreground">
              {(1 + hoverFolderItems.length).toString()} items
            </div>
          </div>

          <div
            className={cn(
              "absolute bottom-0 right-0",
              isDragging ? "opacity-0 pointer-events-none" : undefined,
            )}
          >
            <DropdownMenu onOpenChange={(open) => open && prefetchFolders()}>
              <DropdownMenuTrigger asChild>
                <Button
                  variant="ghost"
                  size="icon-sm"
                  aria-label={
                    hoverAsFolder ? "Folder options" : "Project options"
                  }
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
                {hoverAsFolder ? (
                  <>
                    <DropdownMenuItem
                      onSelect={() => {}}
                    >
                      <FolderOpen className="ml-1 mr-1.5 size-4.5" />
                      Open
                    </DropdownMenuItem>
                    <DropdownMenuItem
                      onSelect={() => {}}
                    >
                      <Pencil className="ml-1 mr-1.5 size-4.5" />
                      Rename
                    </DropdownMenuItem>
                    <DropdownMenuSeparator />
                    <DropdownMenuItem
                      variant="destructive"
                      onSelect={handleDeleteClick}
                    >
                      <Trash2 className="ml-1 mr-1.5 size-4.5" />
                      Delete
                    </DropdownMenuItem>
                  </>
                ) : isOwned ? (
                  <>
                    <DropdownMenuItem onSelect={handleAddToQueueClick}>
                      <ListPlus className="ml-1 mr-1.5 size-4.5" />
                      Add to queue
                    </DropdownMenuItem>
                    <DropdownMenuItem onSelect={handleMoveClick}>
                      <FolderInput className="ml-1 mr-1.5 size-4.5" />
                      Move
                    </DropdownMenuItem>
                    {isOwned && (
                      <DropdownMenuItem onSelect={handleDuplicateClick}>
                        <Copy className="ml-1 mr-1.5 size-4.5" />
                        Duplicate
                      </DropdownMenuItem>
                    )}
                    <DropdownMenuItem onSelect={handleExportClick}>
                      <Download className="ml-1 mr-1.5 size-4.5" />
                      Export
                    </DropdownMenuItem>
                    <DropdownMenuSeparator />
                    <DropdownMenuItem
                      variant="destructive"
                      onSelect={handleDeleteClick}
                    >
                      <Trash2 className="ml-1 mr-1.5 size-4.5" />
                      Delete
                    </DropdownMenuItem>
                  </>
                ) : (
                  <>
                    <DropdownMenuItem onSelect={handleAddToQueueClick}>
                      <ListPlus className="ml-1 mr-1.5 size-4.5" />
                      Add to queue
                    </DropdownMenuItem>
                    <DropdownMenuItem onSelect={handleMoveClick}>
                      <FolderInput className="ml-1 mr-1.5 size-4.5" />
                      Move
                    </DropdownMenuItem>
                    {canExport && (
                      <DropdownMenuItem onSelect={handleExportClick}>
                        <Download className="ml-1 mr-1.5 size-4.5" />
                        Export
                      </DropdownMenuItem>
                    )}
                    <DropdownMenuSeparator />
                    <DropdownMenuItem
                      variant="destructive"
                      onSelect={onLeaveClick ?? (() => {})}
                    >
                      <LogOut className="ml-1 mr-1.5 size-4.5" />
                      Leave
                    </DropdownMenuItem>
                  </>
                )}
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </div>
      </motion.div>

      <DeleteProjectModal
        isOpen={showDeleteModal}
        onClose={() => {
          setShowDeleteModal(false);
          modalJustClosedRef.current = true;
          setTimeout(() => {
            modalJustClosedRef.current = false;
          }, 100);
        }}
        onConfirm={handleDeleteConfirm}
        projectName={String(project.name)}
        isDeleting={deleteProject.isPending}
      />

      <MoveProjectModal
        isOpen={showMoveModal}
        onClose={() => {
          setShowMoveModal(false);
          modalJustClosedRef.current = true;
          setTimeout(() => {
            modalJustClosedRef.current = false;
          }, 100);
        }}
        onConfirm={handleMoveConfirm}
        projectName={String(project.name)}
        currentFolderId={project.folder_id}
        isMoving={moveProject.isPending}
      />
    </div>
  );
}
