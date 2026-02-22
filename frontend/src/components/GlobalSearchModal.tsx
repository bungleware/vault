import { useState, useEffect, useMemo, useRef } from "react";
import { useNavigate } from "@tanstack/react-router";
import { SearchIcon, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useProjects } from "@/hooks/useProjects";
import { useProjectCoverImage } from "@/hooks/useProjectCoverImage";
import type { Project } from "@/types/api";
import fuzzysort from "fuzzysort";
import { motion, AnimatePresence } from "motion/react";
import { createPortal } from "react-dom";
import { useQuery } from "@tanstack/react-query";
import * as tracksApi from "@/api/tracks";
import * as sharingApi from "@/api/sharing";

function ProjectSearchCover({ project }: { project: Project }) {
  const { imageUrl } = useProjectCoverImage(project, "small");

  if (!imageUrl) {
    return (
      <div className="w-full h-full bg-linear-to-br from-white/10 to-white/5 flex items-center justify-center">
        <span className="text-xs text-white/30">
          {project.name?.charAt(0)?.toUpperCase()}
        </span>
      </div>
    );
  }

  return (
    <img
      src={imageUrl}
      alt={project.name}
      className="w-full h-full object-cover"
    />
  );
}

function TrackSearchCover({ track }: { track: any }) {
  const pseudoProject = track.project_public_id
    ? ({
        public_id: track.project_public_id,
        cover_url: track.cover_url,
      } as Project)
    : undefined;

  const { imageUrl } = useProjectCoverImage(pseudoProject, "small");

  if (!imageUrl) {
    return (
      <div className="w-full h-full bg-linear-to-br from-white/10 to-white/5 flex items-center justify-center rounded-full">
        <span className="text-xs text-white/30">
          {track.title?.charAt(0)?.toUpperCase()}
        </span>
      </div>
    );
  }

  return (
    <img
      src={imageUrl}
      alt={track.title}
      className="w-full h-full object-cover"
      style={{
        WebkitMaskImage:
          "radial-gradient(circle, transparent 0%, transparent 19%, black 20%, black 100%)",
        maskImage:
          "radial-gradient(circle, transparent 0%, transparent 19%, black 20%, black 100%)",
      }}
    />
  );
}

interface GlobalSearchModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export default function GlobalSearchModal({
  isOpen,
  onClose,
}: GlobalSearchModalProps) {
  const navigate = useNavigate();
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedSearchIndex, setSelectedSearchIndex] = useState(-1);
  const searchInputRef = useRef<HTMLInputElement>(null);

  const [showMineOnly, setShowMineOnly] = useState(false);
  const [showType, setShowType] = useState<"all" | "projects" | "tracks">(
    "all",
  );

  const { data: allProjects = [] } = useProjects();

  const { data: allAccessibleTracks = [] } = useQuery({
    queryKey: ["all-accessible-tracks"],
    queryFn: () => tracksApi.searchTracks("", 10000), // Empty query = all tracks, high limit
    staleTime: 5 * 60 * 1000,
  });

  const { data: sharedProjectsData = [] } = useQuery({
    queryKey: ["shared-projects"],
    queryFn: sharingApi.listProjectsSharedWithMe,
    staleTime: 5 * 60 * 1000,
  });

  const { data: sharedTracksData = [] } = useQuery({
    queryKey: ["shared-tracks"],
    queryFn: sharingApi.listTracksSharedWithMe,
    staleTime: 5 * 60 * 1000,
  });

  const searchData = useMemo(() => {
    const projectIdToPublicId = new Map<number, string>();
    allProjects.forEach((p: any) => {
      projectIdToPublicId.set(p.id, p.public_id);
    });
    (sharedProjectsData || []).forEach((p: any) => {
      projectIdToPublicId.set(p.id, p.public_id);
    });

    const myProjects = allProjects
      .filter((p: any) => !p.shared_by_username)
      .map((p: any) => ({
        ...p,
        type: "project" as const,
        isMine: true,
        searchText: p.name,
      }));

    const sharedProjects = (sharedProjectsData || []).map((p: any) => ({
      ...p,
      type: "project" as const,
      isMine: false,
      searchText: p.name,
    }));

    const seenProjectIds = new Set<string>();
    const deduplicatedProjects = [...myProjects, ...sharedProjects].filter(
      (p) => {
        if (seenProjectIds.has(p.public_id)) return false;
        seenProjectIds.add(p.public_id);
        return true;
      },
    );

    const accessibleTracks = allAccessibleTracks.map((t: any) => {
      const projectPublicId = projectIdToPublicId.get(t.project_id);
      const isShared = t.is_shared === 1 || t.is_shared === true;
      return {
        ...t,
        type: "track" as const,
        isMine: !isShared,
        searchText: t.title,
        cover_url: projectPublicId
          ? `/api/projects/${projectPublicId}/cover`
          : undefined,
        project_public_id: projectPublicId,
      };
    });

    const individualSharedTracks = (sharedTracksData || []).map((t: any) => {
      return {
        ...t,
        type: "track" as const,
        isMine: false, // These are shared with me
        isIndividuallyShared: true,
        searchText: t.title,
        project_public_id: t.cover_url
          ? t.cover_url.split("/")[3] // Extract public_id from /api/projects/{public_id}/cover
          : undefined,
      };
    });

    const allTracks = [...accessibleTracks, ...individualSharedTracks];

    const seenTrackIds = new Set<string>();
    const deduplicatedTracks = allTracks.filter((t) => {
      if (seenTrackIds.has(t.public_id)) return false;
      seenTrackIds.add(t.public_id);
      return true;
    });

    return [...deduplicatedProjects, ...deduplicatedTracks];
  }, [allProjects, sharedProjectsData, allAccessibleTracks, sharedTracksData]);

  const filteredResults = useMemo(() => {
    const hasFilters = showMineOnly || showType !== "all" || searchQuery.trim();
    if (!hasFilters) {
      return [];
    }

    let results = searchData;

    if (showMineOnly) {
      results = results.filter((item) => item.isMine);
    }

    if (showType === "projects") {
      results = results.filter((item) => item.type === "project");
    } else if (showType === "tracks") {
      results = results.filter((item) => item.type === "track");
    }

    if (searchQuery.trim()) {
      const fuzzyResults = fuzzysort.go(searchQuery, results, {
        key: "searchText",
        threshold: -10000,
      });
      return fuzzyResults.map((result) => result.obj);
    }

    return results;
  }, [searchData, searchQuery, showMineOnly, showType]);

  useEffect(() => {
    if (!isOpen) return;

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        onClose();
        setSearchQuery("");
        setSelectedSearchIndex(-1);
      } else if (e.key === "ArrowDown") {
        e.preventDefault();
        setSelectedSearchIndex((prev) =>
          prev < filteredResults.length - 1 ? prev + 1 : 0,
        );
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        setSelectedSearchIndex((prev) =>
          prev > 0 ? prev - 1 : filteredResults.length - 1,
        );
      } else if (e.key === "Enter" && selectedSearchIndex >= 0) {
        e.preventDefault();
        if (filteredResults[selectedSearchIndex]) {
          handleItemSelect(filteredResults[selectedSearchIndex]);
        }
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isOpen, filteredResults, selectedSearchIndex]);

  useEffect(() => {
    if (isOpen && searchInputRef.current) {
      searchInputRef.current.focus();
    }
  }, [isOpen]);

  useEffect(() => {
    if (!isOpen) {
      setShowMineOnly(false);
      setShowType("all");
      setSearchQuery("");
      setSelectedSearchIndex(-1);
    }
  }, [isOpen]);

  useEffect(() => {
    if (isOpen && filteredResults.length > 0) {
      setSelectedSearchIndex(0);
    } else {
      setSelectedSearchIndex(-1);
    }
  }, [filteredResults.length, isOpen]);

  useEffect(() => {
    if (isOpen && selectedSearchIndex >= 0) {
      const element = document.querySelector(
        `[data-search-index="${selectedSearchIndex}"]`,
      );
      if (element) {
        const container = element.closest(".hide-scrollbar") as HTMLElement;
        if (container) {
          const containerRect = container.getBoundingClientRect();
          const elementRect = element.getBoundingClientRect();
          const targetScroll =
            container.scrollTop +
            (elementRect.top - containerRect.top) -
            containerRect.height / 2 +
            elementRect.height / 2;

          const startScroll = container.scrollTop;
          const distance = targetScroll - startScroll;
          const duration = 150; // faster animation
          let start: number | null = null;

          const animateScroll = (timestamp: number) => {
            if (start === null) start = timestamp;
            const elapsed = timestamp - start;
            const progress = Math.min(elapsed / duration, 1);

            const easeProgress =
              progress < 0.5
                ? 2 * progress * progress
                : -1 + (4 - 2 * progress) * progress;

            container.scrollTop = startScroll + distance * easeProgress;

            if (progress < 1) {
              requestAnimationFrame(animateScroll);
            }
          };

          requestAnimationFrame(animateScroll);
        }
      }
    }
  }, [selectedSearchIndex, isOpen]);

  const handleItemSelect = (item: any) => {
    onClose();
    setSearchQuery("");
    setSelectedSearchIndex(-1);

    if (item.type === "project") {
      navigate({
        to: "/project/$projectId",
        params: { projectId: item.public_id },
      });
    } else if (item.type === "track") {
      if (item.isIndividuallyShared) {
        sessionStorage.setItem("autoplaySharedTrack", item.public_id);
        navigate({
          to: "/shared-track/$trackId",
          params: { trackId: item.public_id },
        });
      } else {
        if (item.project_public_id) {
          sessionStorage.setItem("scrollToTrackAndPlay", item.public_id);
          navigate({
            to: "/project/$projectId",
            params: { projectId: item.project_public_id },
          });
        }
      }
    }
  };

  return createPortal(
    <AnimatePresence>
      {isOpen && (
        <>
          {/* Backdrop */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.1 }}
            className="fixed inset-0 z-1000 bg-black/80"
            onClick={() => {
              onClose();
              setSearchQuery("");
              setSelectedSearchIndex(-1);
            }}
          />

          {/* Search Panel - Parent Container (Fixed Height, Centered on large screens, top-15vh on small) */}
          <motion.div
            initial={{ opacity: 0, y: -8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            transition={{ duration: 0.1 }}
            className="fixed z-1001 w-full max-w-2xl left-1/2 -translate-x-1/2 top-[9vh] sm:top-1/2 sm:-translate-y-1/2 h-[585px] max-h-[calc(100vh-4rem)] px-4 sm:px-0"
            onClick={() => {
              onClose();
              setSearchQuery("");
              setSelectedSearchIndex(-1);
            }}
          >
            {/* Inner Content Container (Aligned to Top) */}
            <div className="flex flex-col justify-start h-full">
              <div
                className="border border-[#292828] rounded-3xl shadow-2xl overflow-hidden"
                style={{
                  background: "linear-gradient(0deg, #151515 0%, #1D1D1D 100%)",
                }}
                onClick={(e) => e.stopPropagation()}
              >
                <div className="p-6">
                  <div className="relative mb-4">
                    <SearchIcon className="absolute left-3 top-1/2 -translate-y-1/2 size-4 text-muted-foreground" />
                    <Input
                      ref={searchInputRef}
                      type="text"
                      placeholder="Search projects and tracks..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="pl-9 pr-9 h-12 focus-visible:ring-0 focus-visible:ring-offset-0 shadow-none rounded-2xl text-base! border-0 text-white bg-transparent"
                    />
                    {searchQuery && (
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => setSearchQuery("")}
                        className="absolute right-1 top-1/2 -translate-y-1/2 size-8"
                      >
                        <X className="size-4" />
                      </Button>
                    )}
                  </div>

                  {/* Filter buttons */}
                  <div className="flex gap-2 mb-4">
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => {
                        setShowMineOnly(!showMineOnly);
                        searchInputRef.current?.focus();
                      }}
                      className={`rounded-xl px-3 h-8 text-sm transition-colors ${
                        showMineOnly
                          ? "bg-white/15 text-white hover:bg-white/20"
                          : "bg-transparent text-white/50 hover:bg-white/5 hover:text-white/70"
                      }`}
                    >
                      Mine
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => {
                        setShowType(
                          showType === "projects" ? "all" : "projects",
                        );
                        searchInputRef.current?.focus();
                      }}
                      className={`rounded-xl px-3 h-8 text-sm transition-colors ${
                        showType === "projects"
                          ? "bg-white/15 text-white hover:bg-white/20"
                          : "bg-transparent text-white/50 hover:bg-white/5 hover:text-white/70"
                      }`}
                    >
                      Projects
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => {
                        setShowType(showType === "tracks" ? "all" : "tracks");
                        searchInputRef.current?.focus();
                      }}
                      className={`rounded-xl px-3 h-8 text-sm transition-colors ${
                        showType === "tracks"
                          ? "bg-white/15 text-white hover:bg-white/20"
                          : "bg-transparent text-white/50 hover:bg-white/5 hover:text-white/70"
                      }`}
                    >
                      Tracks
                    </Button>
                  </div>

                  {/* Results */}
                  <div className="max-h-[46vh] overflow-y-auto hide-scrollbar px-1 py-1">
                    {filteredResults.length === 0 ? (
                      <div className="flex flex-col items-center justify-center text-center min-h-20">
                        {searchQuery.trim() ? (
                          <div className="text-muted-foreground">
                            <p className="text-lg">No results found</p>
                          </div>
                        ) : (
                          <div>
                            <p className="text-xl font-semibold text-white mb-1">
                              Search anything
                            </p>
                            <p className="text-sm text-white/50">
                              Search your library by title or artist
                            </p>
                          </div>
                        )}
                      </div>
                    ) : (
                      <div className="space-y-1">
                        {filteredResults.map((item: any, index: number) => (
                          <button
                            key={
                              item.type === "project"
                                ? item.public_id
                                : `track-${item.public_id}`
                            }
                            onClick={() => handleItemSelect(item)}
                            className={`w-full flex items-center gap-4 rounded-2xl p-3 ${
                              selectedSearchIndex === index
                                ? "bg-white/5 ring-1 ring-white/10"
                                : "hover:bg-white/5 hover:ring-1 hover:ring-white/10"
                            }`}
                            data-search-index={index}
                          >
                            {/* Artwork/Cover */}
                            {item.type === "project" ? (
                              <div className="relative h-14 w-14 shrink-0 overflow-hidden rounded-xl bg-[#333333] border border-[rgba(53,51,51,0.2)]">
                                <ProjectSearchCover project={item} />
                              </div>
                            ) : (
                              <div className="relative h-14 w-14 shrink-0 rounded-full bg-[#1a1a1a] overflow-hidden border border-[rgba(124,124,124,0.3)]">
                                <TrackSearchCover track={item} />
                              </div>
                            )}

                            {/* Item info */}
                            <div className="flex flex-col text-left min-w-0">
                              <span className="text-base font-semibold text-white line-clamp-1 break-all">
                                {item.type === "project"
                                  ? item.name
                                  : item.title}
                              </span>
                              <span className="text-sm text-white/40 line-clamp-1 break-all">
                                {item.type === "project"
                                  ? item.author_override ||
                                    item.owner_username ||
                                    item.shared_by_username ||
                                    "Unknown"
                                  : item.artist ||
                                    item.shared_by_username ||
                                    item.project_name ||
                                    "Unknown Artist"}
                              </span>
                            </div>
                          </button>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>,
    document.body,
  );
}
