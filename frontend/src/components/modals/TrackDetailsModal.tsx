import {
  ChevronLeft,
  Link,
  FileText,
  AudioWaveform,
  ListPlus,
  Download,
  FolderInput,
  Copy,
  Trash2,
  Users,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { useEffect, useState, useMemo, useCallback, useRef, memo } from "react";
import { createPortal } from "react-dom";
import { AnimatePresence, motion } from "motion/react";
import TrackVersionsModal from "./TrackVersionsModal";
import { toast } from "@/routes/__root";
import DeleteTrackModal from "./DeleteTrackModal";
import MoveTrackModal from "./MoveTrackModal";
import ShareModal from "./ShareModal";
import ScrollingText from "@/components/ScrollingText";
import {
  deleteTrack,
  downloadTrack,
  updateTrack,
  duplicateTrack,
  moveTrack,
} from "@/api/tracks";
import { useAudioPlayer } from "@/contexts/AudioPlayerContext";
import { usePrefetchProjects } from "@/hooks/useProjects";
import { useQueryClient } from "@tanstack/react-query";
import { trackKeys } from "@/hooks/useTracks";
import { usePrefetchSharingData } from "@/hooks/useSharing";

interface TrackDetailsModalProps {
  isOpen: boolean;
  onClose: () => void;
  trackId: string;
  track: {
    title: string;
    duration?: string;
    key?: string | null;
    bpm?: number | null;
    fileName?: string;
    active_version_id?: number | null;
    waveform?: string | null;
    visibility_status?: "private" | "invite_only" | "public";
  };
  onUpdate?: () => void;
  projectName?: string;
  artist?: string | null;
  coverUrl?: string | null;
  projectId?: string;
  projectCoverUrl?: string | null;
  onOpenNotes?: () => void;
  isSharedView?: boolean;
  shareToken?: string;
  allowDownloads?: boolean;
  isProjectOwned?: boolean;
  canEdit?: boolean;
  isInSharedProject?: boolean;
  projectAllowsDownloads?: boolean;
  initialModalState?: "details" | "versions" | "share";
  shouldFocusTitle?: boolean;
}

type ModalState = "closed" | "details" | "versions" | "share";

function TrackDetailsModal({
  isOpen,
  onClose,
  trackId,
  track,
  onUpdate,
  projectName,
  artist,
  coverUrl,
  projectId,
  projectCoverUrl,
  onOpenNotes,
  isSharedView = false,
  shareToken,
  allowDownloads = false,
  isProjectOwned = true,
  canEdit = true,
  isInSharedProject = false,
  projectAllowsDownloads = true,
  initialModalState,
  shouldFocusTitle = false,
}: TrackDetailsModalProps) {
  const [modalState, setModalState] = useState<ModalState>("closed");
  const [localTrack, setLocalTrack] = useState(track);
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false);
  const [isDeletingTrack, setIsDeletingTrack] = useState(false);
  const [isMoveModalOpen, setIsMoveModalOpen] = useState(false);
  const [isMovingTrack, setIsMovingTrack] = useState(false);
  const [isDuplicatingTrack, setIsDuplicatingTrack] = useState(false);
  const [trackTitle, setTrackTitle] = useState(track.title);
  const [isTitleFocused, setIsTitleFocused] = useState(false);
  const [titleOverflows, setTitleOverflows] = useState(false);
  const { addToQueue, currentTrack, stop } = useAudioPlayer();
  const queryClient = useQueryClient();
  const prevTrackIdRef = useRef(trackId);
  const closeTimeoutRef = useRef<number | null>(null);
  const trackRef = useRef(track);
  const prefetchProjects = usePrefetchProjects();
  const prefetchSharingData = usePrefetchSharingData();
  const titleInputRef = useRef<HTMLInputElement>(null);

  const canDownload = useMemo(
    () =>
      isProjectOwned ||
      (isInSharedProject &&
        projectAllowsDownloads &&
        (track as any).can_download !== false) ||
      allowDownloads,
    [
      isProjectOwned,
      isInSharedProject,
      projectAllowsDownloads,
      track,
      allowDownloads,
    ],
  );

  const versionModalTrack = useMemo(
    () => ({
      title: localTrack.title,
      key: localTrack.key,
      bpm: localTrack.bpm,
      active_version_id: localTrack.active_version_id,
    }),
    [
      localTrack.title,
      localTrack.key,
      localTrack.bpm,
      localTrack.active_version_id,
    ],
  );

  const handleTrackUpdate = useCallback(
    (updates: { active_version_id?: number; title?: string }) => {
      setLocalTrack((prev) => ({ ...prev, ...updates }));
      if (updates.title !== undefined) {
        setTrackTitle(updates.title);
      }
    },
    [],
  );

  useEffect(() => {
    if (isOpen && initialModalState) {
      setModalState(initialModalState);
    }
  }, [isOpen, initialModalState]);

  useEffect(() => {
    trackRef.current = track;
  }, [track]);

  useEffect(() => {
    const trackChanged = prevTrackIdRef.current !== trackId;

    if (isOpen) {
      prefetchProjects();

      if (closeTimeoutRef.current !== null) {
        clearTimeout(closeTimeoutRef.current);
        closeTimeoutRef.current = null;
      }

      if (trackChanged) {
        setModalState("details");
      } else {
        setModalState((currentState) =>
          currentState === "closed" ? "details" : currentState,
        );
      }

      setLocalTrack(trackRef.current);
      setTrackTitle(trackRef.current.title);
    } else {
      setModalState("closed");
    }

    prevTrackIdRef.current = trackId;
  }, [isOpen, trackId]);

  useEffect(() => {
    return () => {
      if (closeTimeoutRef.current !== null) {
        clearTimeout(closeTimeoutRef.current);
      }
    };
  }, []);

  useEffect(() => {
    if (modalState === "details") {
      setTrackTitle(localTrack.title);
    }
  }, [modalState, localTrack.title]);

  useEffect(() => {
    if (modalState === "details" && shouldFocusTitle && titleInputRef.current) {
      setTimeout(() => {
        if (titleInputRef.current) {
          titleInputRef.current.focus();
          const length = titleInputRef.current.value.length;
          titleInputRef.current.setSelectionRange(length, length);
        }
      }, 200);
    }
  }, [modalState, shouldFocusTitle]);

  useEffect(() => {
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        handleClose();
      }
    };

    if (modalState !== "closed") {
      document.addEventListener("keydown", handleEscape);
      document.body.style.overflow = "hidden";
    }

    return () => {
      document.removeEventListener("keydown", handleEscape);
      document.body.style.overflow = "unset";
    };
  }, [modalState]);

  const handleClose = () => {
    setModalState("closed");
  };

  const handleMoreInfo = () => {
    setModalState("versions");
  };

  const handleBackFromVersions = () => {
    setModalState("details");
  };

  const handleBackFromShare = () => {
    setModalState("details");
  };

  const handleConfirmDeleteTrack = async () => {
    if (isDeletingTrack) return;
    setIsDeletingTrack(true);
    try {
      await deleteTrack(trackId);

      if (currentTrack?.id === trackId) {
        stop();
      }

      setIsDeleteModalOpen(false);
      handleClose();
      onUpdate?.();
    } catch (error) {
      toast.error("Failed to delete track");
      console.error("Failed to delete track:", error);
    } finally {
      setIsDeletingTrack(false);
    }
  };

  const handleAddToQueue = () => {
    addToQueue({
      id: trackId,
      title: track.title,
      artist: artist,
      projectName: projectName,
      coverUrl: coverUrl,
      projectId: projectId,
      projectCoverUrl: projectCoverUrl ?? undefined,
    });
    toast.success(`Added "${track.title}" to queue`);
  };

  const handleExport = async () => {
    if (!track.active_version_id) {
      toast.error("No active version to export");
      return;
    }

    if (!canDownload) {
      toast.error("Downloads are not allowed for this track");
      return;
    }

    try {
      toast.loading("Preparing download...");
      await downloadTrack(trackId, track.active_version_id);
      toast.dismiss();
      toast.success("Download started");
    } catch (error) {
      toast.dismiss();
      toast.error("Failed to download track");
      console.error("Failed to download track:", error);
    }
  };

  const handleSaveTrackTitle = async () => {
    if (trackTitle === localTrack.title) return;
    if (!canEdit) return;

    try {
      await updateTrack(trackId, { title: trackTitle });
      setLocalTrack((prev) => ({ ...prev, title: trackTitle }));

      queryClient.invalidateQueries({ queryKey: trackKeys.detail(trackId) });
      queryClient.invalidateQueries({ queryKey: ["shared-tracks"] });
      queryClient.invalidateQueries({ queryKey: ["shared-projects"] });
      queryClient.invalidateQueries({ queryKey: ["tracks"] });
    } catch (error) {
      toast.error("Failed to update track title");
      console.error("Failed to update track title:", error);
      setTrackTitle(localTrack.title);
    }
  };

  const handleDownloadSharedTrack = async () => {
    if (!shareToken || !allowDownloads) {
      toast.error("Downloads are not allowed");
      return;
    }

    try {
      const toastId = toast.loading("Preparing download...");
      const downloadUrl = `/api/share/${shareToken}/track/${trackId}/download`;
      const response = await fetch(downloadUrl);

      if (!response.ok) {
        throw new Error(`Download failed: ${response.statusText}`);
      }

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${track.title}.mp3`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);

      toast.dismiss(toastId);
      toast.success("Download started");
    } catch (error) {
      toast.dismiss();
      toast.error("Failed to download track");
      console.error("Failed to download track:", error);
    }
  };

  const handleDuplicate = async () => {
    if (isDuplicatingTrack) return;
    setIsDuplicatingTrack(true);
    try {
      await duplicateTrack(trackId);
      handleClose();
      onUpdate?.();
    } catch (error) {
      toast.error("Failed to duplicate track");
      console.error("Failed to duplicate track:", error);
    } finally {
      setIsDuplicatingTrack(false);
    }
  };

  const handleConfirmMove = async (targetProjectId: number) => {
    if (isMovingTrack) return;
    setIsMovingTrack(true);
    try {
      await moveTrack(trackId, targetProjectId);
      setIsMoveModalOpen(false);
      handleClose();
      onUpdate?.();
    } catch (error) {
      toast.error("Failed to move track");
      console.error("Failed to move track:", error);
    } finally {
      setIsMovingTrack(false);
    }
  };

  const formatDuration = (duration?: string) => {
    if (!duration) {
      return "0m 00s";
    }
    const [minutes = "0", seconds = "00"] = duration.split(":");
    return `${minutes}m ${seconds.padStart(2, "0")}s`;
  };

  const showScrollingTitle = titleOverflows && !isTitleFocused;

  return (
    <>
      {createPortal(
        <>
          <AnimatePresence
            onExitComplete={() => {
              if (modalState === "closed") {
                onClose();
              }
            }}
          >
            {modalState !== "closed" && (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.15 }}
                className="fixed inset-0 z-1000 bg-black/80"
                onClick={handleClose}
              />
            )}
          </AnimatePresence>

          <AnimatePresence>
            {modalState === "details" && (
              <motion.div
                key="details-modal"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.15 }}
                className="fixed inset-0 z-1000 flex items-center justify-center p-4 pointer-events-none"
              >
                <motion.div
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: 8 }}
                  transition={{ duration: 0.15 }}
                  className={`relative z-10 w-full ${isSharedView ? "max-w-md" : "max-w-md md:max-w-4xl"} border border-[#292828] rounded-[34px] shadow-2xl overflow-hidden pointer-events-auto`}
                  style={{
                    background:
                      "linear-gradient(0deg, #151515 0%, #1D1D1D 100%)",
                  }}
                  onClick={(e) => e.stopPropagation()}
                >
                  <div
                    className={`grid ${isSharedView ? "grid-cols-1" : "grid-cols-1 md:grid-cols-[2fr_3fr]"} ${isSharedView ? "max-h-auto" : "max-h-[680px] md:min-h-[560px]"} overflow-y-auto md:overflow-visible`}
                  >
                    <div
                      className={`flex flex-col ${isSharedView ? "px-6 py-8" : "md:p-6"}`}
                      style={{
                        borderRight: isSharedView ? "none" : "none",
                        backgroundImage: isSharedView
                          ? "none"
                          : "linear-gradient(to bottom, #353333 4px, transparent 4px)",
                        backgroundSize: "1px 8px",
                        backgroundRepeat: "repeat-y",
                        backgroundPosition: "right",
                      }}
                    >
                      <div
                        className={`sticky top-0 z-10 ${isSharedView ? "pt-0 px-6 pb-4 md:pb-4 bg-none" : "pt-6 px-6 pb-2 md:static md:p-0 bg-linear-to-b from-[#1a1a1a] from-70% to-transparent md:bg-none"}`}
                      >
                        <Button
                          size="icon-lg"
                          onClick={handleClose}
                          className={`self-start ${isSharedView ? "mb-2" : "mb-2 md:mb-6"}`}
                        >
                          <ChevronLeft className="size-5" />
                        </Button>
                      </div>

                      <div
                        className={`flex flex-col items-center ${isSharedView ? "gap-6 px-0 pb-8" : "gap-4 px-6 md:gap-6 md:pb-6 md:p-0"}`}
                      >
                        <div className="flex flex-col items-center gap-2">
                          <div className="flex items-center justify-center gap-2 w-full">
                            {isInSharedProject && (
                              <Users className="size-4 text-muted-foreground shrink-0" />
                            )}
                            <div className="relative w-full">
                              <input
                                ref={titleInputRef}
                                type="text"
                                value={trackTitle}
                                onChange={(e) => setTrackTitle(e.target.value)}
                                onFocus={() => setIsTitleFocused(true)}
                                onBlur={(event) => {
                                  setIsTitleFocused(false);
                                  handleSaveTrackTitle();
                                  event.currentTarget.scrollLeft = 0;
                                }}
                                onKeyDown={(e) => {
                                  if (e.key === "Enter") {
                                    e.currentTarget.blur();
                                  }
                                }}
                                disabled={!canEdit}
                                className={cn(
                                  "text-2xl font-semibold text-white text-center bg-transparent border-none outline-none focus:outline-none w-full disabled:opacity-50 disabled:cursor-not-allowed",
                                  showScrollingTitle && "text-transparent",
                                )}
                                style={{
                                  caretColor: "white",
                                }}
                              />
                              <ScrollingText
                                text={trackTitle}
                                className={cn(
                                  "absolute inset-0 flex items-center text-2xl font-semibold text-white pointer-events-none px-2 transition-opacity duration-150",
                                  showScrollingTitle
                                    ? "opacity-100"
                                    : "opacity-0",
                                )}
                                gradientColor="#151515"
                                align="center"
                                pauseOnHover={false}
                                isActive={showScrollingTitle}
                                onOverflowChange={setTitleOverflows}
                                ariaLabel={trackTitle}
                                gap={6}
                              />
                            </div>
                          </div>

                          {/* Track Metadata */}
                          <div
                            className="text-sm text-muted-foreground"
                            style={{
                              fontFamily: '"IBM Plex Mono", monospace',
                              fontWeight: 300,
                            }}
                          >
                            {formatDuration(track.duration)}
                            {track.key && ` • ${track.key}`}
                            {track.bpm && ` • ${track.bpm} BPM`}
                          </div>
                        </div>

                        {(() => {
                          let waveformData: number[] = [];
                          if (track.waveform) {
                            try {
                              const parsed = JSON.parse(track.waveform);
                              if (Array.isArray(parsed) && parsed.length > 0) {
                                waveformData = parsed;
                              }
                            } catch (error) {
                              console.error(
                                "[TrackDetailsModal] Failed to parse waveform:",
                                error,
                              );
                            }
                          }

                          const barCount = 120;
                          const bars: number[] = [];

                          if (waveformData.length > 0) {
                            for (let i = 0; i < barCount; i++) {
                              const index = Math.floor(
                                (i / barCount) * waveformData.length,
                              );
                              bars.push(waveformData[index]);
                            }
                          } else {
                            for (let i = 0; i < barCount; i++) {
                              bars.push(Math.random() * 60 + 20);
                            }
                          }

                          return (
                            <svg
                              width="100%"
                              height="44"
                              viewBox={`0 0 ${barCount * 2} 44`}
                              preserveAspectRatio="none"
                              className="text-white"
                            >
                              {bars.map((height, i) => {
                                const x = i * 2 + 1;
                                const amplitude = height / 100;
                                const centerY = 22;
                                const barHeight = amplitude * 32;
                                const y1 = centerY - barHeight / 2;
                                const y2 = centerY + barHeight / 2;

                                return (
                                  <line
                                    key={x}
                                    x1={x}
                                    y1={y1}
                                    x2={x}
                                    y2={y2}
                                    stroke="currentColor"
                                    opacity="0.4"
                                    strokeWidth="1"
                                    strokeLinecap="round"
                                    style={{ willChange: "opacity" }}
                                  />
                                );
                              })}
                            </svg>
                          );
                        })()}

                        {track.fileName && (
                          <p
                            className="text-sm text-muted-foreground text-center"
                            style={{
                              fontFamily: '"IBM Plex Mono", monospace',
                              fontWeight: 300,
                            }}
                          >
                            {track.fileName}
                          </p>
                        )}

                        {!isSharedView && (
                          <Button onClick={handleMoreInfo}>More info</Button>
                        )}
                        {isSharedView && allowDownloads && (
                          <Button onClick={handleDownloadSharedTrack}>
                            <Download className="mr-2 size-4" />
                            Download
                          </Button>
                        )}
                      </div>
                    </div>

                    {!isSharedView && (
                      <div className="flex flex-col p-6">
                        <h3
                          className="text-xl font-light text-white mb-4 md:mb-6"
                          style={{
                            fontFamily: '"IBM Plex Mono", monospace',
                          }}
                        >
                          Details
                        </h3>

                        <div className="flex flex-col gap-3 md:gap-4">
                          {isProjectOwned && (
                            <div className="flex flex-col">
                              <ActionButton
                                icon={Link}
                                label="Share"
                                onClick={() => {
                                  prefetchSharingData("track", trackId);
                                  setModalState("share");
                                }}
                                position="single"
                              />
                            </div>
                          )}

                          <div className="flex flex-col overflow-hidden rounded-2xl border border-white/10">
                            <ActionButton
                              icon={FileText}
                              label="Notes"
                              onClick={() => {
                                if (onOpenNotes) {
                                  handleClose();
                                  onOpenNotes();
                                }
                              }}
                              position="first"
                            />
                            {canEdit && (
                              <ActionButton
                                icon={AudioWaveform}
                                label="Replace audio"
                                onClick={handleMoreInfo}
                                position="middle"
                              />
                            )}
                            <ActionButton
                              icon={ListPlus}
                              label="Add to queue"
                              onClick={handleAddToQueue}
                              position={canDownload ? "middle" : "last"}
                            />
                            {canDownload && (
                              <ActionButton
                                icon={Download}
                                label="Export"
                                onClick={handleExport}
                                position="last"
                              />
                            )}
                          </div>

                          {isProjectOwned && (
                            <div className="flex flex-col overflow-hidden rounded-2xl border border-white/10">
                              <ActionButton
                                icon={FolderInput}
                                label={isMovingTrack ? "Moving..." : "Move"}
                                onClick={() => setIsMoveModalOpen(true)}
                                position="first"
                                disabled={isMovingTrack}
                              />
                              <ActionButton
                                icon={Copy}
                                label={
                                  isDuplicatingTrack
                                    ? "Duplicating..."
                                    : "Duplicate"
                                }
                                onClick={handleDuplicate}
                                position="last"
                                disabled={isDuplicatingTrack}
                              />
                            </div>
                          )}

                          {(isProjectOwned || (isInSharedProject && canEdit)) && (
                            <div className="flex flex-col">
                              <ActionButton
                                icon={Trash2}
                                label="Delete"
                                onClick={() => setIsDeleteModalOpen(true)}
                                variant="destructive"
                                position="single"
                              />
                            </div>
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                </motion.div>
              </motion.div>
            )}
          </AnimatePresence>

          <TrackVersionsModal
            isOpen={modalState === "versions"}
            onClose={handleClose}
            onBack={handleBackFromVersions}
            trackId={trackId}
            track={versionModalTrack}
            onUpdate={onUpdate}
            onTrackUpdate={handleTrackUpdate}
            canEdit={canEdit}
          />
        </>,
        document.body,
      )}
      <DeleteTrackModal
        isOpen={isDeleteModalOpen}
        onClose={() => {
          if (!isDeletingTrack) {
            setIsDeleteModalOpen(false);
          }
        }}
        onConfirm={handleConfirmDeleteTrack}
        trackName={track.title}
        isDeleting={isDeletingTrack}
      />
      <MoveTrackModal
        isOpen={isMoveModalOpen}
        onClose={() => {
          if (!isMovingTrack) {
            setIsMoveModalOpen(false);
          }
        }}
        onConfirm={handleConfirmMove}
        trackName={track.title}
        currentProjectId={projectId ? parseInt(projectId) : 0}
        isMoving={isMovingTrack}
      />
      <ShareModal
        isOpen={modalState === "share"}
        onClose={handleClose}
        onBack={handleBackFromShare}
        resourceType="track"
        resourceId={trackId}
        resourceName={localTrack.title}
        currentVisibility={localTrack.visibility_status || "private"}
        onUpdate={onUpdate}
        isOwned={isProjectOwned}
      />
    </>
  );
}

export default memo(TrackDetailsModal, (prevProps, nextProps) => {
  return (
    prevProps.isOpen === nextProps.isOpen &&
    prevProps.trackId === nextProps.trackId &&
    prevProps.projectId === nextProps.projectId
  );
});

interface ActionButtonProps {
  icon: React.ElementType;
  label: string;
  onClick: () => void;
  variant?: "default" | "destructive";
  position?: "first" | "middle" | "last" | "single";
  disabled?: boolean;
}

function ActionButton({
  icon: Icon,
  label,
  onClick,
  variant = "default",
  position = "single",
  disabled = false,
}: ActionButtonProps) {
  const isGrouped = position !== "single";

  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className={cn(
        "px-4 py-3 text-left transition-all border-t border-white/5 bg-white/5 hover:bg-white/10 active:bg-white/15",
        isGrouped ? "group" : "flex items-center gap-4",
        position === "first" && "border-t-0",
        position === "single" &&
          "rounded-2xl border border-white/10 active:scale-99",
        variant === "default" && "text-white",
        variant === "destructive" && "text-[rgb(235,94,94)]",
        disabled && "opacity-50 cursor-not-allowed",
      )}
    >
      <div
        className={cn(
          "flex items-center gap-4",
          isGrouped && "transition-transform group-active:scale-99",
        )}
      >
        <Icon className="size-5 shrink-0" />
        <span className="text-base font-medium">{label}</span>
      </div>
    </button>
  );
}
