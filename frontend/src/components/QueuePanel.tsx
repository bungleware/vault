import { X, MoreHorizontal, FolderOpen } from "lucide-react";
import { useAudioPlayer } from "@/contexts/AudioPlayerContext";
import { AnimatePresence, motion } from "motion/react";
import { createPortal } from "react-dom";
import { useProjectCoverImage } from "@/hooks/useProjectCoverImage";
import {
  DragDropContext,
  Droppable,
  Draggable,
  type DropResult,
} from "@hello-pangea/dnd";
import { useState, useEffect, useRef } from "react";
import { useNavigate, useRouterState } from "@tanstack/react-router";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
  DropdownMenuSeparator,
} from "@/components/ui/dropdown-menu";
import { Button } from "@/components/ui/button";

interface QueuePanelProps {
  isOpen: boolean;
  onClose: () => void;
}

interface QueueTrack {
  id: string;
  title: string;
  artist?: string | null;
  projectName?: string;
  coverUrl?: string | null;
  projectId?: string;
  projectCoverUrl?: string;
}

function QueueTrackCover({ track }: { track: QueueTrack }) {
  const projectForCover =
    track.projectId && track.projectCoverUrl
      ? ({
          public_id: track.projectId,
          cover_url: track.projectCoverUrl,
        } as any)
      : undefined;
  const { imageUrl } = useProjectCoverImage(projectForCover, "small");

  const coverUrl = imageUrl || track.coverUrl;

  if (!coverUrl) {
    return null;
  }

  return (
    <img
      src={coverUrl}
      alt={track.title}
      className="w-full h-full object-cover"
    />
  );
}

export default function QueuePanel({ isOpen, onClose }: QueuePanelProps) {
  const { queue, removeFromQueue, clearQueue, reorderQueue } = useAudioPlayer();
  const navigate = useNavigate();
  const routerState = useRouterState();
  const [openMenuIndex, setOpenMenuIndex] = useState<number | null>(null);
  const queueContentRef = useRef<HTMLDivElement | null>(null);
  const [contentHeight, setContentHeight] = useState(0);
  const shouldAnimateHeight = useRef(false);

  useEffect(() => {
    if (!isOpen) {
      shouldAnimateHeight.current = false;
    }
  }, [isOpen]);

  useEffect(() => {
    if (isOpen) {
      requestAnimationFrame(() => {
        requestAnimationFrame(() => {
          if (queueContentRef.current) {
            const wrapper = queueContentRef.current;
            const originalHeight = wrapper.style.height;
            wrapper.style.height = "auto";
            const naturalHeight = wrapper.scrollHeight;
            wrapper.style.height = originalHeight;
            setContentHeight(Math.min(naturalHeight, 500));

            shouldAnimateHeight.current = true;
          }
        });
      });
    }
  }, [queue.length, isOpen]);

  const handleClearQueue = () => {
    clearQueue();
  };

  const handleRemoveTrack = (index: number) => {
    setOpenMenuIndex(null); // Close dropdown menu
    removeFromQueue(index);
  };

  const handleGoToProject = (projectId?: string, trackId?: string) => {
    if (projectId) {
      setOpenMenuIndex(null);

      const currentPath = routerState.location.pathname;
      const targetPath = `/project/${projectId}`;

      if (currentPath === targetPath || currentPath === `${targetPath}/`) {
        if (trackId) {
          const trackElement = document.querySelector(
            `[data-track-id="${trackId}"]`,
          );
          if (trackElement) {
            trackElement.scrollIntoView({
              behavior: "smooth",
              block: "center",
            });
          }
        }
        onClose();
      } else {
        if (trackId) {
          sessionStorage.setItem("scrollToTrack", trackId);
        }

        navigate({
          to: "/project/$projectId",
          params: { projectId },
        });
        setTimeout(() => {
          onClose();
        }, 100);
      }
    }
  };

  const handleDragEnd = (result: DropResult) => {
    if (!result.destination) {
      return;
    }

    const sourceIndex = result.source.index;
    const destIndex = result.destination.index;

    if (sourceIndex === destIndex) {
      return;
    }

    reorderQueue(sourceIndex, destIndex);
  };

  return createPortal(
    <AnimatePresence>
      {isOpen && (
        <>
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.1 }}
            className="fixed inset-0 z-119 bg-black/20"
            onClick={onClose}
          />

          <motion.div
            initial={{ opacity: 0, y: 5, filter: "blur(8px)" }}
            animate={{ opacity: 1, y: 0, filter: "blur(0px)" }}
            exit={{ opacity: 0, y: 5, filter: "blur(4px)" }}
            transition={{
              type: "spring",
              stiffness: 700,
              damping: 40,
            }}
            className="fixed bottom-[145px] left-1/2 -translate-x-1/2 z-120 w-[calc(100%-1rem)] sm:w-[calc(100%-3rem)] max-w-[800px]"
            onClick={(e) => e.stopPropagation()}
          >
            <div
              className="relative flex max-h-[500px] w-full flex-col overflow-hidden rounded-3xl text-white shadow-2xl border border-[#353333]"
              style={{
                background: "linear-gradient(0deg, #151515 0%, #1D1D1D 100%)",
              }}
            >
              <div className="flex w-full items-center justify-between gap-5 p-5">
                <div className="flex items-center gap-3">
                  <Button
                    aria-label="Close queue manager"
                    className="h-8 w-8 rounded-lg bg-[#191919] border border-[#353333] p-0 text-center hover:bg-[#252525] transition-all duration-200 flex items-center justify-center"
                    type="button"
                    onClick={onClose}
                  >
                    <X className="size-3.5" />
                  </Button>
                  <h3 className="text-lg font-semibold">Queue</h3>
                  {queue.length > 0 && (
                    <span className="text-sm text-white/40">
                      {queue.length} {queue.length === 1 ? "track" : "tracks"}
                    </span>
                  )}
                </div>
                {queue.length > 0 && (
                  <Button
                    className="bg-[#191919] border border-[#353333] rounded-2xl px-3 py-1 text-white text-xs h-auto hover:bg-[#252525] transition-all duration-200"
                    onClick={handleClearQueue}
                  >
                    Clear
                  </Button>
                )}
              </div>

              <motion.div
                ref={queueContentRef}
                initial={{ height: "auto" }}
                animate={{
                  height: shouldAnimateHeight.current ? contentHeight : "auto",
                }}
                transition={{
                  height: {
                    type: "spring",
                    stiffness: 450,
                    damping: 35,
                    bounce: 0,
                  },
                }}
                className="overflow-y-auto px-2 hide-scrollbar"
              >
                {queue.length === 0 ? (
                  <div className="flex flex-col text-center items-center justify-center pb-14">
                    <p className="text-white/40">No tracks in queue</p>
                  </div>
                ) : (
                  <DragDropContext onDragEnd={handleDragEnd}>
                    <Droppable
                      droppableId="queue"
                      renderClone={(provided, _snapshot, rubric) => {
                        const track = queue[rubric.source.index];
                        return (
                          <div
                            ref={provided.innerRef}
                            {...provided.draggableProps}
                            {...provided.dragHandleProps}
                            className="relative flex items-center justify-between gap-3 rounded-2xl p-3 bg-[#1D1D1D] shadow-lg ring-1 ring-white/20 text-white cursor-grabbing"
                            style={{
                              ...provided.draggableProps.style,
                              width: "calc(min(100vw - 1rem, 800px) - 20px)",
                              maxWidth: "780px",
                            }}
                          >
                            <div className="flex min-w-0 flex-1 items-center justify-start gap-4">
                              <div className="relative h-11 w-11 shrink-0 overflow-hidden rounded-lg bg-[#333333] border border-[rgba(53,51,51,0.2)]">
                                <QueueTrackCover track={track} />
                              </div>
                              <div className="flex max-w-full flex-col text-left min-w-0">
                                <span className="text-sm font-semibold line-clamp-1 break-all text-white">
                                  {track.title}
                                </span>
                                <span className="text-xs text-white/40 line-clamp-1 break-all">
                                  {(track.artist &&
                                  track.artist.trim().length > 0
                                    ? track.artist
                                    : track.projectName) || "Unknown Artist"}
                                </span>
                              </div>
                            </div>
                          </div>
                        );
                      }}
                    >
                      {(provided) => (
                        <div
                          {...provided.droppableProps}
                          ref={provided.innerRef}
                          className="pb-2"
                        >
                          {queue.map((track, index) => (
                            <Draggable
                              key={`${track.id}-${index}`}
                              draggableId={`${track.id}-${index}`}
                              index={index}
                            >
                              {(provided, snapshot) => (
                                <div
                                  ref={provided.innerRef}
                                  {...provided.draggableProps}
                                  {...provided.dragHandleProps}
                                  className={`relative flex w-full items-center justify-between gap-3 rounded-2xl p-3 mb-1 bg-white/5 hover:bg-white/10 transition-colors group cursor-grab active:cursor-grabbing ${
                                    snapshot.isDragging ? "opacity-50" : ""
                                  }`}
                                  style={{
                                    ...provided.draggableProps.style,
                                    touchAction: "none",
                                  }}
                                >
                                  <div className="flex min-w-0 flex-1 items-center justify-start gap-4">
                                    <div className="relative h-11 w-11 shrink-0 overflow-hidden rounded-lg bg-[#333333] border border-[rgba(53,51,51,0.2)]">
                                      <QueueTrackCover track={track} />
                                    </div>

                                    <div className="flex max-w-full flex-col text-left min-w-0">
                                      <span className="text-sm font-semibold line-clamp-1 break-all">
                                        {track.title}
                                      </span>
                                      <span className="text-xs text-white/40 line-clamp-1 break-all">
                                        {(track.artist &&
                                        track.artist.trim().length > 0
                                          ? track.artist
                                          : track.projectName) ||
                                          "Unknown Artist"}
                                        {track.projectName &&
                                          track.artist &&
                                          track.artist.trim().length > 0 &&
                                          ` • ${track.projectName}`}
                                      </span>
                                    </div>
                                  </div>

                                  <div className="shrink-0">
                                    <DropdownMenu
                                      open={openMenuIndex === index}
                                      onOpenChange={(open) =>
                                        setOpenMenuIndex(open ? index : null)
                                      }
                                    >
                                      <DropdownMenuTrigger asChild>
                                        <Button
                                          variant="ghost"
                                          size="icon-sm"
                                          className="h-7 w-7 shrink-0 rounded-lg hover:bg-white/10 transition-all opacity-70 hover:opacity-100"
                                          onClick={(e) => e.stopPropagation()}
                                        >
                                          <MoreHorizontal className="size-4" />
                                        </Button>
                                      </DropdownMenuTrigger>
                                      <DropdownMenuContent
                                        align="end"
                                        className="w-48 border-muted bg-background z-1001"
                                      >
                                        <DropdownMenuItem
                                          onSelect={() =>
                                            handleGoToProject(
                                              track.projectId,
                                              track.id,
                                            )
                                          }
                                          disabled={!track.projectId}
                                        >
                                          <FolderOpen className="ml-1 mr-1.5 size-4.5" />
                                          Go to project
                                        </DropdownMenuItem>
                                        <DropdownMenuSeparator />
                                        <DropdownMenuItem
                                          variant="destructive"
                                          onSelect={() =>
                                            handleRemoveTrack(index)
                                          }
                                        >
                                          <X className="ml-1 mr-1.5 size-4.5" />
                                          Remove from queue
                                        </DropdownMenuItem>
                                      </DropdownMenuContent>
                                    </DropdownMenu>
                                  </div>
                                </div>
                              )}
                            </Draggable>
                          ))}
                          {provided.placeholder}
                        </div>
                      )}
                    </Droppable>
                  </DragDropContext>
                )}
              </motion.div>
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>,
    document.body,
  );
}
