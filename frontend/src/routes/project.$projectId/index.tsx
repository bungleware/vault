import { DotIcon, Shuffle, Play, Pause, LinkIcon, Users } from "lucide-react";
import { Button } from "@/components/ui/button";
import AlbumCover from "@/components/AlbumCover";
import NotesPanel from "@/components/NotesPanel";
import LinkNotAvailable from "@/components/LinkNotAvailable";
import { createFileRoute } from "@tanstack/react-router";
import { Filter } from "virtual:refractionFilter?width=48&height=48&radius=16&bezelWidth=12&glassThickness=40&refractiveIndex=1.45&bezelType=convex_squircle";
import {
  useState,
  useEffect,
  useLayoutEffect,
  useRef,
  useMemo,
  useCallback,
} from "react";
import type React from "react";
import { motion, AnimatePresence } from "motion/react";
import type { DropResult } from "@hello-pangea/dnd";
import { useProject, projectKeys } from "@/hooks/useProjects";
import { useTracks } from "@/hooks/useTracks";
import { useAuth } from "@/contexts/AuthContext";
import { useAudioPlayer } from "@/contexts/AudioPlayerContext";
import { toast } from "@/routes/__root";
import { uploadTrack, reorderTracks } from "@/api/tracks";
import { uploadVersion } from "@/api/versions";
import { useMutation, useQueryClient, useQuery } from "@tanstack/react-query";
import { trackKeys } from "@/hooks/useTracks";
import * as sharingApi from "@/api/sharing";
import { uploadProjectCover, fetchProjectCover } from "@/api/projects";
import { useProjectCoverImage } from "@/hooks/useProjectCoverImage";
import type { Track, VisibilityStatus } from "@/types/api";
import { formatTrackDuration, formatDurationLong } from "@/lib/duration";

import { usePlayButtonAnimation } from "@/hooks/usePlayButtonAnimation";
import { useProjectSearch } from "@/hooks/useProjectSearch";
import { useFileDragUpload } from "@/hooks/useFileDragUpload";
import { useScrollToTrack } from "@/hooks/useScrollToTrack";
import { useProjectEditing } from "@/hooks/useProjectEditing";
import { ProjectModals } from "@/components/ProjectModals";
import { ProjectTrackList } from "@/components/ProjectTrackList";
import {
  mapTrackToPlayerTrack,
  mapTracksToPlayerTracks,
} from "@/hooks/useProjectUtils";

export const Route = createFileRoute("/project/$projectId/")({
  component: ProjectPage,
});

function ProjectPage() {
  const { projectId } = Route.useParams();
  const { user } = useAuth();
  const { data: project, isLoading: projectLoading } = useProject(projectId);
  const { data: apiTracks = [], isLoading: tracksLoading } = useTracks(
    project ? project.id : null,
  );
  const isProjectOwned = project && user ? project.user_id === user.id : true;

  const { data: sharedProjects = [] } = useQuery({
    queryKey: ["shared-projects"],
    queryFn: sharingApi.listProjectsSharedWithMe,
    staleTime: 5 * 60 * 1000,
  });

  const isInSharedProject =
    !!project && sharedProjects.some((p) => p.id === project.id);

  const sharedProject = project
    ? sharedProjects.find((p) => p.id === project.id)
    : null;

  const getCanEdit = (track: Track | null) => {
    if (isProjectOwned) return true;
    if (isInSharedProject && sharedProject?.allow_editing) return true;
    if (track && (track as any).can_edit) return true;
    return false;
  };

  const canEditProject =
    isProjectOwned || (isInSharedProject && sharedProject?.allow_editing);

  const queryClient = useQueryClient();
  const { imageUrl: projectCoverImage } = useProjectCoverImage(
    project,
    "large",
  );
  const coverInputRef = useRef<HTMLInputElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const {
    play,
    pause,
    isPlaying,
    currentTrack,
    previewProgress,
    clearQueue,
    addProjectToQueue,
    setProjectTracks,
    toggleShuffle,
    isShuffled,
  } = useAudioPlayer();

  const tracks = useMemo(() => apiTracks || [], [apiTracks]);

  const playButton = usePlayButtonAnimation();

  const editing = useProjectEditing({
    project: project ?? undefined,
    username: user?.username,
    sharedByUsername: sharedProject?.shared_by_username,
  });

  const [showTracksPanel, setShowTracksPanel] = useState(false);
  const [showCoverPanel, setShowCoverPanel] = useState(false);
  const [coverColorsReady, setCoverColorsReady] = useState(false);
  const [isSmallScreen, setIsSmallScreen] = useState(false);

  const [selectedTrack, setSelectedTrack] = useState<Track | null>(null);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [isCoverModalOpen, setIsCoverModalOpen] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [isVersionsModalOpen, setIsVersionsModalOpen] = useState(false);
  const [versionUploadTrack, setVersionUploadTrack] = useState<Track | null>(
    null,
  );
  const [isNotesOpen, setIsNotesOpen] = useState(false);
  const [notesTrack, setNotesTrack] = useState<Track | null>(null);
  const [_isDragging, setIsDragging] = useState(false);

  const handleTrackClickRef = useRef<(track: Track) => void>(() => {});

  const memoizedOnTrackClick = useCallback(
    (track: Track) => handleTrackClickRef.current(track),
    [],
  );

  const search = useProjectSearch({
    tracks,
    onTrackClick: memoizedOnTrackClick,
    isPlaying,
    currentTrackId: currentTrack?.id,
    pause,
  });

  const scrollToTrack = useScrollToTrack({
    projectId,
    tracks,
    showTracksPanel,
    isGlobalSearchOpen: search.isGlobalSearchOpen,
    onTrackClick: memoizedOnTrackClick,
  });

  const handleTrackClick = useCallback(
    (track: Track) => {
      scrollToTrack.setFadeHighlightedTrackId(null);
      search.setSelectedTrackIndexMain(-1);
      search.setSelectedSearchIndex(-1);

      if (isNotesOpen) {
        setNotesTrack(track);
      }

      if (!project) return;

      const clickedIndex = tracks.findIndex(
        (t) => t.public_id === track.public_id,
      );
      const tracksAfter =
        clickedIndex >= 0 ? tracks.slice(clickedIndex + 1) : [];

      play(
        mapTrackToPlayerTrack(track, project, projectCoverImage),
        mapTracksToPlayerTracks(tracks, project, projectCoverImage),
        true,
        false,
        mapTracksToPlayerTracks(tracksAfter, project, projectCoverImage),
      );
    },
    [
      tracks,
      project,
      projectCoverImage,
      play,
      isNotesOpen,
      scrollToTrack,
      search,
    ],
  );

  handleTrackClickRef.current = handleTrackClick;

  const handleUpload = useCallback(
    async (files: File[]) => {
      if (!project) return;
      if (!canEditProject) {
        toast.error("You don't have permission to add tracks to this project");
        return;
      }

      setIsUploading(true);
      let successCount = 0;
      let failCount = 0;

      for (const file of files) {
        try {
          await uploadTrack(file, project.id);
          successCount++;
        } catch (error) {
          console.error(`Failed to upload ${file.name}:`, error);
          failCount++;
        }
      }

      setIsUploading(false);
      queryClient.invalidateQueries({ queryKey: trackKeys.list(project.id) });

      if (successCount > 0) {
        toast.success(
          `Successfully uploaded ${successCount} track${successCount > 1 ? "s" : ""}`,
        );
      }
      if (failCount > 0) {
        toast.error(
          `Failed to upload ${failCount} track${failCount > 1 ? "s" : ""}`,
        );
      }
    },
    [project, canEditProject, queryClient],
  );

  const handleVersionUpload = useCallback(
    async (trackId: string, file: File) => {
      try {
        await uploadVersion(trackId, file);
        toast.success("Version uploaded successfully");

        if (project) {
          queryClient.invalidateQueries({
            queryKey: trackKeys.list(project.id),
          });
        }

        const track = tracks.find((t) => t.public_id === trackId);
        if (track) {
          setVersionUploadTrack(track);
          setIsVersionsModalOpen(true);
        }
      } catch (error) {
        console.error("Failed to upload version:", error);
        toast.error("Failed to upload version");
      }
    },
    [project, queryClient, tracks],
  );

  const handleFileInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(e.target.files || []);
    if (files.length > 0) {
      handleUpload(files);
    }
    e.target.value = "";
  };

  const fileDrag = useFileDragUpload({
    onUploadFiles: handleUpload,
    onUploadVersion: handleVersionUpload,
  });

  const coverUploadMutation = useMutation({
    mutationFn: ({ projectId, file }: { projectId: string; file: File }) =>
      uploadProjectCover(projectId, file),
    onSuccess: (_data, variables) => {
      setCoverColorsReady(false);
      queryClient.invalidateQueries({
        queryKey: projectKeys.detail(variables.projectId),
      });
      queryClient.invalidateQueries({ queryKey: projectKeys.list() });
      toast.success("Cover updated");
    },
    onError: () => toast.error("Failed to update cover"),
  });

  const handleCoverFileChange = async (
    event: React.ChangeEvent<HTMLInputElement>,
  ) => {
    if (!project) return;
    const file = event.target.files?.[0];
    if (!file) return;

    try {
      await coverUploadMutation.mutateAsync({
        projectId: project.public_id,
        file,
      });
    } catch (error) {
      console.error("Failed to upload cover", error);
    } finally {
      event.target.value = "";
    }
  };

  const handleExportCover = async () => {
    if (!project?.cover_url) return;

    try {
      const blob = await fetchProjectCover(
        project.public_id,
        project.cover_url,
        "source",
      );
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `${project.name}-cover.jpg`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
      toast.success("Cover art downloaded");
    } catch (error) {
      console.error("Failed to export cover", error);
      toast.error("Failed to download cover art");
    }
  };

  const handleDragStart = useCallback(() => {
    setIsDragging(true);
  }, []);

  const handleDragEnd = useCallback(
    async (result: DropResult) => {
      setIsDragging(false);

      if (!canEditProject) {
        toast.error("You don't have permission to reorder tracks");
        return;
      }

      if (
        !result.destination ||
        result.destination.index === result.source.index
      ) {
        return;
      }

      if (!project) {
        toast.error("Project not found");
        return;
      }

      const currentTracks = queryClient.getQueryData<Track[]>(
        trackKeys.list(project.id),
      );
      if (!currentTracks) return;

      const items = Array.from(currentTracks);
      const [reorderedItem] = items.splice(result.source.index, 1);
      items.splice(result.destination.index, 0, reorderedItem);

      const trackOrders = items.map((track, index) => ({
        id: track.id,
        order: index,
      }));

      queryClient.setQueryData(trackKeys.list(project.id), items);

      if (currentTrack && items.some((t) => t.public_id === currentTrack.id)) {
        setProjectTracks(
          mapTracksToPlayerTracks(items, project, projectCoverImage),
        );

        const currentTrackIndex = items.findIndex(
          (t) => t.public_id === currentTrack.id,
        );
        const tracksAfter =
          currentTrackIndex >= 0 ? items.slice(currentTrackIndex + 1) : [];

        clearQueue();
        if (tracksAfter.length > 0) {
          addProjectToQueue(
            mapTracksToPlayerTracks(tracksAfter, project, projectCoverImage),
          );
        }
      }

      try {
        await reorderTracks(trackOrders);
      } catch (error) {
        console.error("Failed to update track order:", error);
        toast.error("Failed to save track order");

        queryClient.setQueryData(trackKeys.list(project.id), currentTracks);

        if (
          currentTrack &&
          currentTracks.some((t) => t.public_id === currentTrack.id)
        ) {
          setProjectTracks(
            mapTracksToPlayerTracks(currentTracks, project, projectCoverImage),
          );

          const currentTrackIndex = currentTracks.findIndex(
            (t) => t.public_id === currentTrack.id,
          );
          const tracksAfter =
            currentTrackIndex >= 0
              ? currentTracks.slice(currentTrackIndex + 1)
              : [];

          clearQueue();
          if (tracksAfter.length > 0) {
            addProjectToQueue(
              mapTracksToPlayerTracks(tracksAfter, project, projectCoverImage),
            );
          }
        }
      }
    },
    [
      project,
      queryClient,
      currentTrack,
      projectCoverImage,
      setProjectTracks,
      clearQueue,
      addProjectToQueue,
      canEditProject,
    ],
  );

  const handlePlayPause = () => {
    if (tracks.length === 0 || !project) return;

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
      const tracksAfter = trackIndex >= 0 ? tracks.slice(trackIndex + 1) : [];

      play(
        mapTrackToPlayerTrack(trackToPlay, project, projectCoverImage),
        mapTracksToPlayerTracks(tracks, project, projectCoverImage),
        true,
        false,
        mapTracksToPlayerTracks(tracksAfter, project, projectCoverImage),
      );
    }
  };

  const handleMoreClick = useCallback((track: Track) => {
    scrollToTrack.setFadeHighlightedTrackId(null);
    search.setSelectedTrackIndexMain(-1);
    search.setSelectedSearchIndex(-1);
    setSelectedTrack(track);
    setIsModalOpen(true);
  }, []);

  const handleCloseModal = useCallback(() => {
    setIsModalOpen(false);
    setSelectedTrack(null);
  }, []);

  useEffect(() => {
    const mediaQuery = window.matchMedia("(max-width: 768px)");
    setIsSmallScreen(mediaQuery.matches);
    const handleChange = (e: MediaQueryListEvent) =>
      setIsSmallScreen(e.matches);
    mediaQuery.addEventListener("change", handleChange);
    return () => mediaQuery.removeEventListener("change", handleChange);
  }, []);

  useEffect(() => {
    if (!notesTrack) return;
    const trackIndex = tracks.findIndex(
      (t) => t.public_id === notesTrack.public_id,
    );
    if (trackIndex === -1) {
      setNotesTrack(tracks.length > 0 ? tracks[0] : null);
    } else {
      const updatedTrack = tracks[trackIndex];
      if (updatedTrack && updatedTrack !== notesTrack) {
        setNotesTrack(updatedTrack);
      }
    }
  }, [tracks, notesTrack]);

  useEffect(() => {
    setShowTracksPanel(false);
    if (project && !projectLoading && !tracksLoading) {
      const timer = setTimeout(() => setShowTracksPanel(true), 50);
      return () => clearTimeout(timer);
    }
  }, [projectId, projectLoading, tracksLoading]);

  useLayoutEffect(() => {
    setShowCoverPanel(false);
    setCoverColorsReady(false);
  }, [projectId]);

  useEffect(() => {
    if (project && !projectLoading && coverColorsReady) {
      const timer = setTimeout(() => setShowCoverPanel(true), 50);
      return () => clearTimeout(timer);
    }
  }, [project, projectLoading, coverColorsReady]);

  useEffect(() => {
    if (selectedTrack && tracks.length > 0) {
      const updatedTrack = tracks.find(
        (t) => t.public_id === selectedTrack.public_id,
      );
      if (updatedTrack) {
        setSelectedTrack(updatedTrack);
      }
    }
  }, [tracks]);

  useEffect(() => {
    const handleNotesEvent = () => {
      setNotesTrack(null);
      setIsNotesOpen(true);
    };
    window.addEventListener("project-notes", handleNotesEvent);
    return () => window.removeEventListener("project-notes", handleNotesEvent);
  }, []);

  const trackDetailsData = useMemo(() => {
    if (!selectedTrack) return null;
    return {
      title: String(selectedTrack.title),
      duration: formatTrackDuration(
        selectedTrack.active_version_duration_seconds,
      ),
      key: selectedTrack.key || undefined,
      bpm: selectedTrack.bpm || undefined,
      fileName: `${String(selectedTrack.title).toLowerCase().replace(/\s+/g, "_")}.wav`,
      active_version_id: selectedTrack.active_version_id,
      waveform: selectedTrack.waveform || undefined,
      visibility_status: (selectedTrack.visibility_status ||
        "private") as VisibilityStatus,
    };
  }, [selectedTrack]);

  const totalDurationSeconds = useMemo(
    () =>
      tracks.reduce((sum, track) => {
        const duration = track.active_version_duration_seconds;
        if (typeof duration === "number" && Number.isFinite(duration)) {
          return sum + duration;
        }
        return sum;
      }, 0),
    [tracks],
  );
  const totalDuration = formatDurationLong(totalDurationSeconds);

  const preventSpacebarDefault = useCallback((e: React.KeyboardEvent) => {
    if (e.code === "Space") e.preventDefault();
  }, []);

  const blurOnClick = useCallback((e: React.MouseEvent<HTMLButtonElement>) => {
    e.currentTarget.blur();
  }, []);

  if (!projectLoading && !tracksLoading && !project) {
    return <LinkNotAvailable />;
  }

  if (!project) {
    return null;
  }

  return (
    <>
      <div
        className="mx-auto max-w-7xl px-6 md:pt-30 pt-30 pb-40 relative"
        onDragEnter={fileDrag.handlePageDragEnter}
        onDragLeave={fileDrag.handlePageDragLeave}
        onDragOver={fileDrag.handlePageDragOver}
        onDrop={fileDrag.handlePageDrop}
        onClick={search.handleBackgroundClick}
      >
        <div
          className={`fixed inset-0 z-1000 pointer-events-none transition-opacity backdrop-blur-sm duration-200 ${
            fileDrag.isFileDragging
              ? "opacity-100"
              : "opacity-0 pointer-events-none"
          }`}
        >
          <div className="absolute inset-4 border-2 border-dashed border-white/40 rounded-3xl bg-black/30 flex items-center justify-center">
            <div className="text-center relative">
              <div
                className="absolute inset-0 -inset-x-20 -inset-y-25 rounded-full pointer-events-none"
                style={{
                  background:
                    "radial-gradient(ellipse at center, #111 0%, #111 40%, transparent 70%)",
                }}
              />
              <p className="text-xl font-medium text-white relative">
                Drop to upload tracks
              </p>
              <p className="text-sm text-white/70 mt-1 relative">
                Drop on a track to add as a new version
              </p>
            </div>
          </div>
        </div>

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
                title={String(project.name)}
                className="w-full"
                onUploadClick={() => setIsCoverModalOpen(true)}
                showUploadOverlay={canEditProject}
                onColorsReady={() => setCoverColorsReady(true)}
                isPlaying={
                  isPlaying && currentTrack
                    ? tracks.some((t) => t.public_id === currentTrack.id)
                    : false
                }
                playbackProgress={previewProgress}
              />
              <input
                ref={coverInputRef}
                type="file"
                accept="image/png,image/jpeg,image/webp"
                className="hidden"
                onChange={handleCoverFileChange}
              />
            </div>
          </motion.div>

          <motion.div
            initial={false}
            animate={{
              x: isNotesOpen && !isSmallScreen ? "-100%" : 0,
              opacity: showTracksPanel ? 1 : 0,
            }}
            transition={{ duration: 0.4, ease: [0.32, 0.72, 0, 1] }}
            className="flex flex-col text-white pt-10 md:pt-0 md:pr-5 md:max-w-lg md:-ml-10"
          >
            <div className="mb-4 -space-y-1">
              <div className="flex items-center justify-between relative z-20">
                <input
                  ref={editing.titleInputRef}
                  type="text"
                  tabIndex={0}
                  value={editing.projectName}
                  onChange={(e) => editing.setProjectName(e.target.value)}
                  onBlur={editing.handleSaveProjectName}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") e.currentTarget.blur();
                  }}
                  className="text-3xl font-semibold bg-transparent border-none p-0 m-0 h-auto outline-none text-white placeholder:text-white/50 w-full focus:outline-none focus:ring-0"
                  placeholder="Project name"
                />
                <div className="flex items-center gap-2 shrink-0">
                  <Button
                    variant="ghost"
                    size="icon"
                    onClick={(e) => {
                      toggleShuffle();
                      blurOnClick(e);
                    }}
                    onKeyDown={preventSpacebarDefault}
                    className={`transition-colors ${isShuffled ? "text-amber-400" : "text-white hover:text-gray-300"}`}
                    aria-label="Shuffle"
                    aria-pressed={isShuffled}
                  >
                    <Shuffle className="size-5" />
                  </Button>

                  <Filter
                    id="project-play-button-filter"
                    blur={playButton.blur}
                    scaleRatio={playButton.scaleRatio}
                    specularOpacity={playButton.specularOpacity}
                    specularSaturation={playButton.specularSaturation}
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
                      backgroundColor: playButton.backgroundColor,
                      scale: playButton.scaleSpring,
                    }}
                    onClick={handlePlayPause}
                    disabled={tracks.length === 0}
                    onMouseDown={() => playButton.pointerDown.set(1)}
                    onMouseUp={() => playButton.pointerDown.set(0)}
                    onMouseLeave={() => playButton.pointerDown.set(0)}
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
                {(isInSharedProject || (project as any).is_shared) && (
                  <Users className="w-3 h-3 mr-1.5 shrink-0" />
                )}
                {project.visibility_status !== "private" && (
                  <LinkIcon className="w-4 h-4 mr-2 shrink-0" />
                )}
                <span
                  ref={editing.authorMeasureRef}
                  className="absolute invisible whitespace-pre text-muted-foreground text-md"
                  aria-hidden="true"
                >
                  {editing.projectAuthor ||
                    sharedProject?.shared_by_username ||
                    user?.username ||
                    "Author name"}
                </span>
                <input
                  ref={editing.authorInputRef}
                  value={editing.projectAuthor}
                  onChange={(e) => editing.setProjectAuthor(e.target.value)}
                  onFocus={() => editing.setIsEditingAuthor(true)}
                  onBlur={() => {
                    editing.setIsEditingAuthor(false);
                    editing.handleSaveProjectAuthor();
                  }}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") e.currentTarget.blur();
                  }}
                  className="bg-transparent border-none p-0 m-0 h-auto outline-none text-muted-foreground placeholder:text-muted-foreground/50 cursor-text focus:outline-none focus:ring-0 shrink-0"
                  placeholder={
                    sharedProject?.shared_by_username ||
                    user?.username ||
                    "Author name"
                  }
                  disabled={isInSharedProject}
                  style={{
                    width:
                      editing.authorInputWidth > 0
                        ? `${editing.authorInputWidth}px`
                        : "auto",
                  }}
                />
                <DotIcon className="w-4 shrink-0" />
                <span>{tracks.length} tracks</span>
                <DotIcon className="w-4 shrink-0" />
                <span>{totalDuration}</span>
              </div>
            </div>

            <ProjectTrackList
              tracks={tracks}
              filteredTracks={search.filteredTracks}
              project={project}
              isSearchOpen={search.isSearchOpen}
              searchQuery={search.searchQuery}
              setSearchQuery={search.setSearchQuery}
              setIsSearchOpen={search.setIsSearchOpen}
              selectedSearchIndex={search.selectedSearchIndex}
              setSelectedSearchIndex={search.setSelectedSearchIndex}
              searchInputRef={search.searchInputRef}
              onTrackClick={handleTrackClick}
              selectedTrackIndexMain={search.selectedTrackIndexMain}
              fadeHighlightedTrackId={scrollToTrack.fadeHighlightedTrackId}
              isUploading={isUploading}
              canEdit={!!canEditProject}
              fileInputRef={fileInputRef}
              isPlaying={isPlaying}
              currentTrackId={currentTrack?.id}
              onDragStart={handleDragStart}
              onDragEnd={handleDragEnd}
              dropTargetTrackId={fileDrag.dropTargetTrackId}
              handleTrackDragEnter={fileDrag.handleTrackDragEnter}
              handleTrackDragLeave={fileDrag.handleTrackDragLeave}
              handlePageDragOver={fileDrag.handlePageDragOver}
              handleTrackDrop={fileDrag.handleTrackDrop}
              onMoreClick={handleMoreClick}
              isDraggable={!!canEditProject}
            />

            <input
              ref={fileInputRef}
              type="file"
              accept="audio/*"
              multiple
              className="hidden"
              onChange={handleFileInputChange}
            />
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
                  <div className="md:sticky md:top-31 md:self-start backdrop-blur-sm rounded-2xl p-6  border-white/10">
                    {notesTrack ? (
                      <NotesPanel
                        mode="track"
                        selectedTrack={notesTrack}
                        onClose={() => {
                          setIsNotesOpen(false);
                          setNotesTrack(null);
                        }}
                      />
                    ) : (
                      <NotesPanel
                        mode="project"
                        project={project}
                        onClose={() => setIsNotesOpen(false)}
                      />
                    )}
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

      <ProjectModals
        selectedTrack={selectedTrack}
        trackDetailsData={trackDetailsData}
        isModalOpen={isModalOpen}
        onCloseModal={handleCloseModal}
        project={project}
        projectCoverImage={projectCoverImage}
        isProjectOwned={isProjectOwned}
        canEditTrack={getCanEdit}
        isInSharedProject={isInSharedProject}
        projectAllowsDownloads={
          isProjectOwned ||
          (isInSharedProject && !!sharedProject?.allow_downloads)
        }
        onTrackUpdate={() =>
          queryClient.invalidateQueries({
            queryKey: trackKeys.list(project.id),
          })
        }
        onOpenNotes={(track) => {
          setNotesTrack(track);
          setIsNotesOpen(true);
        }}
        versionUploadTrack={versionUploadTrack}
        isVersionsModalOpen={isVersionsModalOpen}
        onCloseVersionsModal={() => {
          setIsVersionsModalOpen(false);
          setVersionUploadTrack(null);
        }}
        onBackFromVersions={() => {
          setIsVersionsModalOpen(false);
          setSelectedTrack(versionUploadTrack);
          setIsModalOpen(true);
          setVersionUploadTrack(null);
        }}
        isCoverModalOpen={isCoverModalOpen}
        onCloseCoverModal={() => setIsCoverModalOpen(false)}
        onLibraryClick={() => coverInputRef.current?.click()}
        onExportCover={handleExportCover}
        hasExistingCover={!!project.cover_url}
        canEditCover={!!canEditProject}
        canDownloadCover={
          isProjectOwned ||
          (isInSharedProject && !!sharedProject?.allow_downloads)
        }
        isSmallScreen={isSmallScreen}
        isNotesOpen={isNotesOpen}
        onCloseNotes={() => {
          setIsNotesOpen(false);
          setNotesTrack(null);
        }}
        notesTrack={notesTrack}
        isGlobalSearchOpen={search.isGlobalSearchOpen}
        onCloseGlobalSearch={() => search.setIsGlobalSearchOpen(false)}
      />
    </>
  );
}
