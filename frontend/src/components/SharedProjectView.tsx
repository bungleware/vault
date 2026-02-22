import { useState, useEffect, useLayoutEffect, useMemo } from "react";
import { DotIcon, Play, Pause, MoreHorizontal, Download } from "lucide-react";
import AlbumCover from "@/components/AlbumCover";
import TrackListItem from "@/components/TrackListItem";
import TrackDetailsModal from "@/components/modals/TrackDetailsModal";
import MusicPlayer from "@/components/MusicPlayer";
import { motion, useMotionValue, useSpring, useTransform } from "motion/react";
import { Filter } from "virtual:refractionFilter?width=48&height=48&radius=16&bezelWidth=12&glassThickness=40&refractiveIndex=1.45&bezelType=convex_squircle";
import { formatTrackDuration, formatDurationLong } from "@/lib/duration";
import type { Track } from "@/types/api";
import { useAudioPlayer } from "@/contexts/AudioPlayerContext";
import { useAuth } from "@/contexts/AuthContext";
import { env } from "@/env";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { toast } from "@/routes/__root";

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

interface SharedProjectViewProps {
  project: any;
  tracks: Track[];
  shareToken: string;
  allowDownloads?: boolean;
}

export default function SharedProjectView({
  project,
  tracks,
  shareToken,
  allowDownloads = false,
}: SharedProjectViewProps) {
  const [selectedTrack, setSelectedTrack] = useState<Track | null>(null);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [showTracksPanel, setShowTracksPanel] = useState(false);
  const [showCoverPanel, setShowCoverPanel] = useState(false);
  const [coverColorsReady, setCoverColorsReady] = useState(false);

  const { isAuthenticated } = useAuth();

  const audioPlayerContext = useAudioPlayer();

  const API_BASE_URL = env.VITE_API_URL || "";
  const projectCoverImage = project.cover_url
    ? `${API_BASE_URL}/api/share/${shareToken}/cover?size=medium`
    : null;

  const isPlaying = audioPlayerContext.isPlaying;
  const currentTrack = audioPlayerContext.currentTrack;
  const previewProgress = audioPlayerContext.previewProgress;

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
  }, []);

  useLayoutEffect(() => {
    if (!isAuthenticated) {
      audioPlayerContext.setShareToken(shareToken);
    }
    return () => {
      if (!isAuthenticated) {
        audioPlayerContext.setShareToken(null);
      }
    };
  }, [isAuthenticated, shareToken, audioPlayerContext.setShareToken]);

  useEffect(() => {
    if (project) {
      const timer = setTimeout(() => setShowTracksPanel(true), 50);
      return () => clearTimeout(timer);
    }
  }, [project]);

  useEffect(() => {
    if (project && coverColorsReady) {
      const timer = setTimeout(() => {
        setShowCoverPanel(true);
      }, 50);
      return () => clearTimeout(timer);
    }
  }, [project, coverColorsReady]);

  const totalDuration = useMemo(() => {
    const total = tracks.reduce((sum, track) => {
      return sum + (track.active_version_duration_seconds || 0);
    }, 0);
    return formatDurationLong(total);
  }, [tracks]);

  const handlePlayPause = () => {
    if (tracks.length === 0) return;

    const isCurrentProjectTrack =
      currentTrack && tracks.some((t) => t.public_id === currentTrack.id);

    if (isPlaying && isCurrentProjectTrack) {
      audioPlayerContext.pause();
    } else if (!isPlaying && isCurrentProjectTrack) {
      audioPlayerContext.resume();
    } else {
      audioPlayerContext.clearQueue();

      const projectTracks = tracks.map((t) => ({
        id: t.public_id,
        title: String(t.title),
        artist: t.artist,
        projectName: String(project.name),
        coverUrl: projectCoverImage,
        projectId: project.public_id,
        projectCoverUrl: undefined,
        waveform: t.waveform ?? undefined,
        lossy_transcoding_status: t.lossy_transcoding_status ?? undefined,
        versionId: t.active_version_id ?? undefined,
      }));

      if (projectTracks.length > 0) {
        const remainingTracks = projectTracks.slice(1);
        audioPlayerContext.play(
          projectTracks[0],
          projectTracks,
          true,
          false,
          remainingTracks,
        );
      }
    }
  };

  const handleTrackClick = (track: Track) => {
    setSelectedTrack(track);
    setIsModalOpen(true);
  };

  const handleTrackPlay = (track: Track) => {
    audioPlayerContext.clearQueue();

    const clickedIndex = tracks.findIndex(
      (t) => t.public_id === track.public_id,
    );

    const tracksAfterClicked =
      clickedIndex >= 0 ? tracks.slice(clickedIndex + 1) : [];

    const reorderedTracks =
      clickedIndex >= 0
        ? [...tracks.slice(clickedIndex), ...tracks.slice(0, clickedIndex)]
        : tracks;

    const projectTracks = reorderedTracks.map((t) => ({
      id: t.public_id,
      title: String(t.title),
      artist: t.artist,
      projectName: String(project.name),
      coverUrl: projectCoverImage,
      projectId: project.public_id,
      projectCoverUrl: undefined,
      waveform: t.waveform ?? undefined,
      lossy_transcoding_status: t.lossy_transcoding_status ?? undefined,
      versionId: t.active_version_id ?? undefined,
    }));

    const queueTracks = tracksAfterClicked.map((t) => ({
      id: t.public_id,
      title: String(t.title),
      artist: t.artist,
      projectName: String(project.name),
      coverUrl: projectCoverImage,
      projectId: project.public_id,
      projectCoverUrl: undefined,
      waveform: t.waveform ?? undefined,
      lossy_transcoding_status: t.lossy_transcoding_status ?? undefined,
      versionId: t.active_version_id ?? undefined,
    }));

    if (projectTracks.length > 0) {
      audioPlayerContext.play(
        projectTracks[0],
        projectTracks,
        true,
        false,
        queueTracks,
      );
    }
  };

  const handleDownloadProject = async () => {
    if (!allowDownloads) {
      toast.error("Downloads are not allowed for this project");
      return;
    }

    try {
      const toastId = toast.loading("Preparing download...");
      const downloadUrl = `/api/share/${shareToken}/download`;

      const response = await fetch(downloadUrl);

      if (!response.ok) {
        throw new Error(`Download failed: ${response.statusText}`);
      }

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${project.name}.zip`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);

      toast.dismiss(toastId);
      toast.success("Download started");
    } catch (error) {
      toast.dismiss();
      toast.error("Failed to download project");
      console.error("Failed to download project:", error);
    }
  };

  if (!project) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="text-white text-lg">Loading...</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background">
      <header className="fixed top-0 left-0 right-0 z-50 flex items-center justify-between bg-linear-to-b from-background from-30% to-transparent text-white md:p-10 p-6">
        <div className="flex items-center">
          <div className="text-2xl font-medium">{"{ vault }"}</div>
        </div>
        <div className="flex items-center gap-2.5">
          {allowDownloads && (
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="default" size="icon-lg">
                  <MoreHorizontal strokeWidth={3} className="size-4.5" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent
                align="end"
                sideOffset={8}
                className="w-44 border-muted bg-background"
              >
                <DropdownMenuItem onSelect={handleDownloadProject}>
                  <Download className="ml-1 mr-1.5 size-4.5" />
                  Download project
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          )}
        </div>
      </header>

      <div className="mx-auto max-w-7xl px-6 md:pt-30 pt-30 pb-40 relative">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-5 relative">
          <motion.div
            initial={false}
            animate={{
              opacity: showCoverPanel ? 1 : 0,
            }}
            transition={{ duration: 0.4, ease: [0.32, 0.72, 0, 1] }}
            className="flex items-start justify-center overflow-visible pl-5 pr-22 md:sticky md:self-start pt-2 top-30"
          >
            <div className="relative w-full md:max-w-[24rem]">
              <AlbumCover
                imageUrl={projectCoverImage || undefined}
                title={String(project.name)}
                className="w-full"
                showUploadOverlay={false}
                onColorsReady={() => {
                  setCoverColorsReady(true);
                }}
                isPlaying={
                  isPlaying && currentTrack
                    ? tracks.some((t) => t.public_id === currentTrack.id)
                    : false
                }
                playbackProgress={previewProgress}
              />
            </div>
          </motion.div>

          <motion.div
            initial={false}
            animate={{
              opacity: showTracksPanel ? 1 : 0,
            }}
            transition={{ duration: 0.4, ease: [0.32, 0.72, 0, 1] }}
            className="flex flex-col text-white pt-10 md:pt-0 md:pr-5 md:max-w-lg md:-ml-10"
          >
            <div className="mb-4 -space-y-1">
              <div className="flex items-center justify-between relative z-20">
                <h1 className="text-3xl font-semibold text-white">
                  {project.name}
                </h1>
                <div className="flex items-center gap-2 shrink-0">
                  <Filter
                    id="project-play-button-filter"
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
                    className="shadow-md size-12 rounded-2xl flex items-center justify-center disabled:opacity-50 disabled:cursor-not-allowed"
                    style={{
                      backdropFilter: "url(#project-play-button-filter)",
                      backgroundColor: playButtonBackgroundColor as any,
                      scale: playButtonScaleSpring,
                    }}
                    onClick={handlePlayPause}
                    disabled={tracks.length === 0}
                    onMouseDown={() => playButtonPointerDown.set(1)}
                    onMouseUp={() => playButtonPointerDown.set(0)}
                    onMouseLeave={() => playButtonPointerDown.set(0)}
                  >
                    {isPlaying &&
                    currentTrack &&
                    tracks.some((t) => t.public_id === currentTrack.id) ? (
                      <Pause className="size-5" fill="white" />
                    ) : (
                      <Play className="size-5" fill="white" />
                    )}
                  </motion.button>
                </div>
              </div>
              <div className="flex items-center text-muted-foreground text-md gap-0 relative z-10">
                <span>{project.author_override || "Unknown artist"}</span>
                <DotIcon className="w-4 shrink-0" />
                <span>{tracks.length} tracks</span>
                <DotIcon className="w-4 shrink-0" />
                <span>{totalDuration}</span>
              </div>
            </div>

            {tracks.length === 0 ? (
              <div className="text-center py-12 text-muted-foreground">
                <p className="text-lg">No tracks yet</p>
                <p className="text-sm mt-2">This project is empty</p>
              </div>
            ) : (
              <div>
                {tracks
                  .filter((track) => track)
                  .map((track, index) => (
                    <div key={track.public_id} className="relative rounded-2xl">
                      <TrackListItem
                        id={track.public_id}
                        index={index}
                        trackNumber={index + 1}
                        title={String(track.title)}
                        dateAdded={String(formatDate(track.created_at))}
                        duration={formatTrackDuration(
                          track.active_version_duration_seconds,
                        )}
                        isPlaying={Boolean(
                          isPlaying && currentTrack?.id === track.public_id,
                        )}
                        isTranscoding={Boolean(
                          track.lossy_transcoding_status &&
                            track.lossy_transcoding_status !== "completed",
                        )}
                        onClick={() => handleTrackPlay(track)}
                        onMoreClick={() => handleTrackClick(track)}
                        isShared={track.visibility_status === "public"}
                        isSharedWithUsers={(track as any).is_shared}
                        isDraggable={false}
                      />
                    </div>
                  ))}
              </div>
            )}
          </motion.div>
        </div>
      </div>

      {selectedTrack && (
        <TrackDetailsModal
          isOpen={isModalOpen}
          onClose={() => {
            setIsModalOpen(false);
            setSelectedTrack(null);
          }}
          trackId={selectedTrack.public_id}
          track={{
            title: selectedTrack.title,
            duration: formatTrackDuration(
              selectedTrack.active_version_duration_seconds,
            ),
            key: selectedTrack.key,
            bpm: selectedTrack.bpm,
            fileName: undefined,
            active_version_id: selectedTrack.active_version_id,
            waveform: selectedTrack.waveform,
            visibility_status: selectedTrack.visibility_status,
          }}
          projectName={project.name}
          artist={selectedTrack.artist || undefined}
          coverUrl={projectCoverImage}
          projectId={project.public_id}
          projectCoverUrl={project.cover_url}
          isSharedView={true}
          shareToken={shareToken}
          allowDownloads={allowDownloads}
        />
      )}

      <MusicPlayer />
    </div>
  );
}
