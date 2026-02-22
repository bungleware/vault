import { DotIcon, Play, Pause, Users } from "lucide-react";
import { Button } from "@/components/ui/button";
import AlbumCover from "@/components/AlbumCover";
import TrackDetailsModal from "@/components/modals/TrackDetailsModal";
import BaseModal from "@/components/modals/BaseModal";
import MoveProjectModal from "@/components/modals/MoveProjectModal";
import NotesPanel from "@/components/NotesPanel";
import LinkNotAvailable from "@/components/LinkNotAvailable";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { Filter } from "virtual:refractionFilter?width=48&height=48&radius=16&bezelWidth=12&glassThickness=40&refractiveIndex=1.45&bezelType=convex_squircle";
import {
  useState,
  useEffect,
  useLayoutEffect,
  useMemo,
  useCallback,
  useRef,
} from "react";
import {
  motion,
  useMotionValue,
  useSpring,
  useTransform,
  AnimatePresence,
} from "motion/react";
import { useTrack } from "@/hooks/useTracks";
import { useProjects } from "@/hooks/useProjects";
import { useAudioPlayer } from "@/contexts/AudioPlayerContext";
import { useQueryClient, useQuery } from "@tanstack/react-query";
import { trackKeys } from "@/hooks/useTracks";
import type { Track, Project } from "@/types/api";
import { formatTrackDuration, formatDurationLong } from "@/lib/duration";
import * as sharingApi from "@/api/sharing";
import { updateTrack } from "@/api/tracks";

function formatDate(dateString: string | undefined | null) {
  if (!dateString) return "Unknown";

  const date = new Date(dateString);

  if (Number.isNaN(date.getTime())) return "Unknown";

  const currentYear = new Date().getFullYear();
  const dateYear = date.getFullYear();

  const monthShort = date.toLocaleDateString("en-US", { month: "short" });
  const day = date.getDate();

  if (dateYear === currentYear) {
    return `${monthShort} ${day}`;
  } else {
    return `${monthShort} ${day}, ${dateYear}`;
  }
}

export const Route = createFileRoute("/shared-track/$trackId/")({
  component: SharedTrackPage,
});

function SharedTrackPage() {
  const navigate = useNavigate();
  const { trackId } = Route.useParams();
  const { data: track, isLoading: trackLoading } = useTrack(trackId);

  const { data: ownedProjects = [] } = useProjects();

  const { data: sharedProjects = [] } = useQuery({
    queryKey: ["shared-projects"],
    queryFn: sharingApi.listProjectsSharedWithMe,
    staleTime: 5 * 60 * 1000,
  });

  const project = useMemo(() => {
    if (!track?.project_id) return undefined;
    const allProjects = [...ownedProjects, ...sharedProjects];
    const foundProject = allProjects.find((p) => p.id === track.project_id);

    if (!foundProject && track.project_id) {
      return {
        id: track.project_id,
        user_id: track.user_id,
        public_id: "", // We don't have this, but we'll handle it
        name: track.project_name || "Unknown Project",
        description: null,
        cover_url: track.project_cover_url || null,
        folder_id: null,
        visibility_status: "private" as const,
        allow_editing: false,
        allow_downloads: true,
        created_at: track.created_at,
        updated_at: track.updated_at,
      } as Project;
    }

    return foundProject;
  }, [
    track?.project_id,
    track?.user_id,
    track?.created_at,
    track?.updated_at,
    ownedProjects,
    sharedProjects,
  ]);

  const projectLoading = false;
  const queryClient = useQueryClient();
  let projectCoverImage: string | undefined;
  if (track && track.project_cover_url) {
    let coverUrl = track.project_cover_url;
    // Add size parameter for optimized image
    if (!coverUrl.includes("size=")) {
      coverUrl = `${coverUrl}${coverUrl.includes("?") ? "&" : "?"}size=medium`;
    }
    projectCoverImage = coverUrl;
  }
  const {
    play,
    pause,
    resume,
    isPlaying,
    currentTrack,
    previewProgress,
    addToQueue,
  } = useAudioPlayer();

  const titleInputRef = useRef<HTMLInputElement>(null);
  const [trackTitle, setTrackTitle] = useState("");
  const [selectedTrack, setSelectedTrack] = useState<Track | null>(null);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [showCoverPanel, setShowCoverPanel] = useState(false);
  const [coverColorsReady, setCoverColorsReady] = useState(false);
  const [isNotesOpen, setIsNotesOpen] = useState(false);
  const [isSmallScreen, setIsSmallScreen] = useState(false);
  const [modalInitialState, setModalInitialState] = useState<
    "details" | "versions" | "share" | undefined
  >();
  const [isMoveModalOpen, setIsMoveModalOpen] = useState(false);
  const [isMovingTrack, setIsMovingTrack] = useState(false);
  const [currentFolderId, setCurrentFolderId] = useState<number | null>(null);

  const canEdit = track?.can_edit ?? false;

  useEffect(() => {
    if (track) {
      setTrackTitle(String(track.title));
    }
  }, [track?.public_id, track?.title]);

  useEffect(() => {
    const mediaQuery = window.matchMedia("(max-width: 768px)");
    setIsSmallScreen(mediaQuery.matches);

    const handleChange = (e: MediaQueryListEvent) => {
      setIsSmallScreen(e.matches);
    };

    mediaQuery.addEventListener("change", handleChange);
    return () => mediaQuery.removeEventListener("change", handleChange);
  }, []);

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

  useEffect(() => {
    const timer = setTimeout(() => {
      playButtonBlurBase.set(3);
    }, 500);
    return () => clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleSaveTrackTitle = async () => {
    if (!track || !canEdit || trackTitle === track.title) return;

    try {
      await updateTrack(track.public_id, { title: trackTitle });

      queryClient.invalidateQueries({
        queryKey: trackKeys.detail(track.public_id),
      });
      queryClient.invalidateQueries({ queryKey: ["shared-tracks"] });
      queryClient.invalidateQueries({ queryKey: ["shared-projects"] });

      if (track.project_id) {
        queryClient.invalidateQueries({
          queryKey: trackKeys.list(track.project_id),
        });
      }
    } catch (error) {
      const { toast } = await import("@/routes/__root");
      toast.error("Failed to update track title");
      setTrackTitle(String(track.title)); // Revert on error
    }
  };

  const trackDetailsData = useMemo(() => {
    if (!track) return null;
    return {
      title: String(track.title),
      duration: formatTrackDuration(track.active_version_duration_seconds),
      key: track.key || undefined,
      bpm: track.bpm || undefined,
      fileName: `${String(track.title).toLowerCase().replace(/\s+/g, "_")}.wav`,
      active_version_id: track.active_version_id,
      waveform: track.waveform || undefined,
      versionId: track.active_version_id ?? undefined,
      visibility_status: track.visibility_status || "private",
    };
  }, [track]);

  useLayoutEffect(() => {
    setShowCoverPanel(false);
    setCoverColorsReady(false);
  }, [trackId]);

  useEffect(() => {
    if (project && !projectLoading && coverColorsReady) {
      const timer = setTimeout(() => {
        setShowCoverPanel(true);
      }, 50);
      return () => clearTimeout(timer);
    }
  }, [project, projectLoading, coverColorsReady]);

  useEffect(() => {
    const handleOpenNotes = () => {
      setIsNotesOpen(true);
    };

    window.addEventListener("open-track-notes", handleOpenNotes);
    return () =>
      window.removeEventListener("open-track-notes", handleOpenNotes);
  }, []);

  useEffect(() => {
    if (!track) {
      setCurrentFolderId(null);
      return;
    }

    const folderId = track.folder_id ?? null;
    setCurrentFolderId(folderId);
  }, [track]);

  const handleExport = useCallback(async () => {
    if (!track?.active_version_id) return;

    if (!track.can_download) {
      const { toast } = await import("@/routes/__root");
      toast.error("Downloads are not allowed for this track");
      return;
    }

    try {
      const { downloadTrack } = await import("@/api/tracks");
      await downloadTrack(track.public_id, track.active_version_id);
    } catch (error) {
      const { toast } = await import("@/routes/__root");
      toast.error("Failed to download track");
      console.error("Failed to download track:", error);
    }
  }, [track]);

  useEffect(() => {
    const handleRename = () => {
      if (track && canEdit) {
        setTimeout(() => {
          if (titleInputRef.current) {
            const input = titleInputRef.current;
            input.focus();
            requestAnimationFrame(() => {
              if (titleInputRef.current) {
                const length = titleInputRef.current.value.length;
                titleInputRef.current.setSelectionRange(length, length);
              }
            });
          }
        }, 200);
      }
    };

    const handleMove = () => {
      if (track) {
        setIsMoveModalOpen(true);
      }
    };

    const handleAddToQueue = () => {
      if (!track) return;
      addToQueue({
        id: track.public_id,
        title: String(track.title),
        artist: track.artist || undefined,
        projectName: project?.name || "Unknown Project",
        coverUrl: projectCoverImage,
        projectId: project?.public_id,
        projectCoverUrl: project?.cover_url ?? undefined,
        waveform: track.waveform,
        versionId: track.active_version_id ?? undefined,
      });
      const { toast } = require("@/routes/__root");
      toast.success(`Added "${track.title}" to queue`);
    };

    window.addEventListener("track-rename", handleRename);
    window.addEventListener("track-move", handleMove);
    window.addEventListener("track-export", handleExport);
    window.addEventListener("track-add-to-queue", handleAddToQueue);

    return () => {
      window.removeEventListener("track-rename", handleRename);
      window.removeEventListener("track-move", handleMove);
      window.removeEventListener("track-export", handleExport);
      window.removeEventListener("track-add-to-queue", handleAddToQueue);
    };
  }, [track, project, projectCoverImage, addToQueue, canEdit, handleExport]);

  const handleConfirmMove = async (folderId: number | null) => {
    if (isMovingTrack || !track) return;
    setIsMovingTrack(true);
    try {
      const { organizeSharedTrack } = await import("@/api/organization");
      await organizeSharedTrack(track.id, { folder_id: folderId });
      setIsMoveModalOpen(false);
      setCurrentFolderId(folderId);
      queryClient.invalidateQueries({ queryKey: ["shared-tracks"] });
      if (folderId) {
        const { folderKeys } = await import("@/hooks/useFolders");
        queryClient.invalidateQueries({
          queryKey: folderKeys.contents(folderId),
        });
      }
      queryClient.invalidateQueries({ queryKey: ["folders"] });
    } catch (error) {
      const { toast } = await import("@/routes/__root");
      toast.error("Failed to organize track");
      console.error("Failed to organize track:", error);
    } finally {
      setIsMovingTrack(false);
    }
  };

  const projectName = useMemo(() => {
    if (project?.name) return project.name;
    if (track && track.project_name) return track.project_name;
    return "Unknown Project";
  }, [project?.name, track]);

  useEffect(() => {
    if (!track || !projectCoverImage) return;

    const shouldAutoplay = sessionStorage.getItem("autoplaySharedTrack");
    if (shouldAutoplay !== track.public_id) return;

    sessionStorage.removeItem("autoplaySharedTrack");

    const currentTrackExists =
      currentTrack && currentTrack.id === track.public_id;
    if (currentTrackExists && isPlaying) return;

    play(
      {
        id: track.public_id,
        title: String(track.title),
        artist: track.artist || undefined,
        projectName: projectName,
        coverUrl: projectCoverImage,
        projectId: project?.public_id || "",
        projectCoverUrl: project?.cover_url ?? undefined,
        waveform: track.waveform,
        versionId: track.active_version_id ?? undefined,
        isSharedTrack: true,
      },
      [
        {
          id: track.public_id,
          title: String(track.title),
          artist: track.artist || undefined,
          projectName: projectName,
          coverUrl: projectCoverImage,
          projectId: project?.public_id || "",
          projectCoverUrl: project?.cover_url ?? undefined,
          waveform: track.waveform,
          versionId: track.active_version_id ?? undefined,
          isSharedTrack: true,
        },
      ],
      true,
      false,
      [],
    );
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [track?.public_id]);

  const handlePlayPause = () => {
    if (!track) return;

    const currentTrackExists =
      currentTrack && currentTrack.id === track.public_id;

    if (currentTrackExists) {
      if (isPlaying) {
        pause();
      } else {
        resume();
      }
      return;
    }

    play(
      {
        id: track.public_id,
        title: String(track.title),
        artist: track.artist || undefined,
        projectName: projectName,
        coverUrl: projectCoverImage,
        projectId: project?.public_id || "",
        projectCoverUrl: project?.cover_url ?? undefined,
        waveform: track.waveform,
        versionId: track.active_version_id ?? undefined,
        isSharedTrack: true,
      },
      [
        {
          id: track.public_id,
          title: String(track.title),
          artist: track.artist || undefined,
          projectName: projectName,
          coverUrl: projectCoverImage,
          projectId: project?.public_id || "",
          projectCoverUrl: project?.cover_url ?? undefined,
          waveform: track.waveform,
          versionId: track.active_version_id ?? undefined,
          isSharedTrack: true,
        },
      ],
      true,
      false,
      [],
    );
  };

  const handleMoreClick = useCallback(() => {
    if (track) {
      setSelectedTrack(track);
      setIsModalOpen(true);
    }
  }, [track]);

  const handleCloseModal = useCallback(() => {
    setIsModalOpen(false);
    setSelectedTrack(null);
    setModalInitialState(undefined);
  }, []);

  if (!trackLoading && !projectLoading && !track) {
    return <LinkNotAvailable />;
  }

  if (!track) {
    return null;
  }

  const duration = formatDurationLong(
    track.active_version_duration_seconds || 0,
  );
  const isTrackPlaying = isPlaying && currentTrack?.id === track.public_id;

  return (
    <>
      <div className="mx-auto max-w-7xl px-6 md:pt-30 pt-30 pb-40 relative">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-5 relative">
          <motion.div
            initial={false}
            animate={{
              x: isNotesOpen && !isSmallScreen ? "-100%" : 0,
              opacity:
                isNotesOpen && !isSmallScreen ? 0 : showCoverPanel ? 1 : 0,
            }}
            transition={{ duration: 0.4, ease: [0.32, 0.72, 0, 1] }}
            className="flex items-start justify-center overflow-visible pl-5 pr-22 md:sticky md:self-start pt-2 top-30"
          >
            <div className="relative w-full md:max-w-[24rem]">
              <AlbumCover
                imageUrl={projectCoverImage || undefined}
                title={projectName}
                className="w-full"
                onColorsReady={() => {
                  setCoverColorsReady(true);
                }}
                isPlaying={isTrackPlaying}
                playbackProgress={previewProgress}
              />
            </div>
          </motion.div>

          <motion.div
            initial={false}
            animate={{
              x: isNotesOpen && !isSmallScreen ? "-100%" : 0,
              opacity: showCoverPanel ? 1 : 0,
            }}
            transition={{ duration: 0.4, ease: [0.32, 0.72, 0, 1] }}
            className="flex flex-col text-white pt-10 md:pt-0 md:pr-5 md:max-w-lg md:-ml-10"
          >
            <div className="mb-4 -space-y-1">
              <div className="flex items-center justify-between relative z-20">
                <input
                  ref={titleInputRef}
                  type="text"
                  tabIndex={0}
                  value={trackTitle}
                  onChange={(e) => setTrackTitle(e.target.value)}
                  onBlur={handleSaveTrackTitle}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") {
                      e.currentTarget.blur();
                    }
                  }}
                  disabled={!canEdit}
                  className="text-3xl font-semibold bg-transparent border-none p-0 m-0 h-auto outline-none text-white placeholder:text-white/50 w-full focus:outline-none focus:ring-0 disabled:cursor-default"
                  placeholder="Track title"
                />
              </div>
              <div className="flex items-center text-muted-foreground text-md gap-2 relative z-10">
                <div className="flex items-center gap-1">
                  <Users className="w-3 h-3 shrink-0 text-muted-foreground" />
                  <span>{track.artist || "Unknown Artist"}</span>
                </div>
                <DotIcon className="w-4 shrink-0" />
                <span>{projectName}</span>
                <DotIcon className="w-4 shrink-0" />
                <span>{duration}</span>
              </div>
            </div>

            <div className="mb-6">
              <div className="bg-linear-to-b from-[#232323] to-[#201f1f] border border-[#353333] rounded-3xl p-6">
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <span className="text-[#848484] text-sm">Date Added</span>
                    <span className="text-white text-sm">
                      {formatDate(track.created_at)}
                    </span>
                  </div>
                  {track.key && (
                    <div className="flex items-center justify-between">
                      <span className="text-[#848484] text-sm">Key</span>
                      <span className="text-white text-sm">{track.key}</span>
                    </div>
                  )}
                  {track.bpm && (
                    <div className="flex items-center justify-between">
                      <span className="text-[#848484] text-sm">BPM</span>
                      <span className="text-white text-sm">{track.bpm}</span>
                    </div>
                  )}
                  <div className="flex items-center justify-between">
                    <span className="text-[#848484] text-sm">Duration</span>
                    <span className="text-white text-sm">
                      {formatTrackDuration(
                        track.active_version_duration_seconds,
                      )}
                    </span>
                  </div>
                </div>
              </div>
            </div>

            <div className="flex gap-2 mb-6">
              <div className="flex items-center gap-2 shrink-0">
                <Filter
                  id="shared-track-play-button-filter"
                  blur={playButtonBlur}
                  scaleRatio={playButtonScaleRatio}
                  specularOpacity={playButtonSpecularOpacity}
                  specularSaturation={playButtonSpecularSaturation}
                />

                <motion.button
                  type="button"
                  aria-label={isTrackPlaying ? "Pause" : "Play"}
                  className="shadow-md size-12 rounded-2xl flex items-center justify-center disabled:opacity-50 disabled:cursor-not-allowed"
                  style={{
                    backdropFilter: "url(#shared-track-play-button-filter)",
                    backgroundColor: playButtonBackgroundColor,
                    scale: playButtonScaleSpring,
                  }}
                  onClick={handlePlayPause}
                  onMouseDown={() => playButtonPointerDown.set(1)}
                  onMouseUp={() => playButtonPointerDown.set(0)}
                  onMouseLeave={() => playButtonPointerDown.set(0)}
                >
                  {isTrackPlaying ? (
                    <Pause className="size-5" fill="white" />
                  ) : (
                    <Play className="size-5" fill="white" />
                  )}
                </motion.button>
              </div>

              <Button
                onClick={handleMoreClick}
                className="flex-1 h-12 text-base font-semibold active:scale-99"
              >
                Track Details
              </Button>
              <Button
                onClick={() => {
                  setIsNotesOpen(true);
                }}
                className="flex-1 h-12 text-base font-semibold active:scale-99"
              >
                Notes
              </Button>
            </div>
          </motion.div>

          {!isSmallScreen && (
            <AnimatePresence>
              {isNotesOpen && (
                <motion.div
                  initial={{ opacity: 0, x: "100%" }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: "100%" }}
                  transition={{ duration: 0.4, ease: [0.32, 0.72, 0, 1] }}
                  className="absolute right-6 top-0 bottom-0 w-[calc(50%-1.25rem)] pt-10 md:pt-0"
                >
                  <div className="md:sticky md:top-31 md:self-start backdrop-blur-sm rounded-2xl p-6 border-white/10">
                    <NotesPanel
                      mode="track"
                      selectedTrack={track}
                      onClose={() => {
                        setIsNotesOpen(false);
                      }}
                    />
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          )}
        </div>
      </div>
      <div
        className="fixed bottom-0 left-0 right-0 h-[120px] z-100 pointer-events-none"
        style={{
          background:
            "linear-gradient(to top, #181818 20%, rgba(24, 24, 24, 0.95) 25%, rgba(24, 24, 24, 0.85) 30%, rgba(24, 24, 24, 0.7) 45%, rgba(24, 24, 24, 0.5) 60%, rgba(24, 24, 24, 0.3) 75%, rgba(24, 24, 24, 0.1) 90%, transparent 100%)",
        }}
      />
      {selectedTrack && trackDetailsData && (
        <TrackDetailsModal
          isOpen={isModalOpen}
          onClose={handleCloseModal}
          trackId={selectedTrack.public_id}
          track={trackDetailsData}
          onUpdate={() => {
            queryClient.invalidateQueries({
              queryKey: trackKeys.detail(selectedTrack.public_id),
            });
            queryClient.invalidateQueries({
              queryKey: ["shared-tracks"],
            });
            queryClient.invalidateQueries({
              queryKey: ["shared-projects"],
            });
            navigate({ to: "/" });
          }}
          projectName={projectName}
          artist={selectedTrack.artist}
          coverUrl={projectCoverImage}
          projectId={track.project_public_id || project?.public_id}
          projectCoverUrl={project?.cover_url ?? undefined}
          isProjectOwned={false}
          canEdit={track.can_edit ?? false}
          allowDownloads={track.can_download ?? false}
          isInSharedProject={
            !!project &&
            sharedProjects.some((p) => p.id === project.id && p.allow_editing)
          }
          onOpenNotes={() => {
            setIsNotesOpen(true);
          }}
          initialModalState={modalInitialState}
          shouldFocusTitle={modalInitialState === "details"}
        />
      )}

      {isSmallScreen && (
        <BaseModal
          isOpen={isNotesOpen}
          onClose={() => {
            setIsNotesOpen(false);
          }}
          maxWidth="lg"
        >
          <div className="p-6 min-h-[300px]">
            <NotesPanel
              mode="track"
              selectedTrack={track}
              onClose={() => {
                setIsNotesOpen(false);
              }}
            />
          </div>
        </BaseModal>
      )}

      {track && (
        <MoveProjectModal
          isOpen={isMoveModalOpen}
          onClose={() => {
            if (!isMovingTrack) {
              setIsMoveModalOpen(false);
            }
          }}
          onConfirm={handleConfirmMove}
          projectName={track.title}
          currentFolderId={currentFolderId}
          isMoving={isMovingTrack}
        />
      )}
    </>
  );
}
