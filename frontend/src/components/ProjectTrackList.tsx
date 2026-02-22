import type React from "react";
import { Search, X, PlusIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { motion, AnimatePresence } from "motion/react";
import {
  DragDropContext,
  Droppable,
  type DropResult,
  type DroppableProvided,
} from "@hello-pangea/dnd";
import TrackListItem from "@/components/TrackListItem";
import type { Track } from "@/types/api";
import { formatDate } from "@/hooks/useProjectUtils";
import { formatTrackDuration } from "@/lib/duration";

interface ProjectTrackListProps {
  tracks: Track[];
  filteredTracks: Track[];
  project: { name: string; public_id: string; is_shared?: boolean };

  // Search
  isSearchOpen: boolean;
  searchQuery: string;
  setSearchQuery: (query: string) => void;
  setIsSearchOpen: (open: boolean) => void;
  selectedSearchIndex: number;
  setSelectedSearchIndex: (index: number | ((prev: number) => number)) => void;
  searchInputRef: React.RefObject<HTMLInputElement | null>;
  onTrackClick: (track: Track) => void;

  selectedTrackIndexMain: number;
  fadeHighlightedTrackId: string | null;

  isUploading: boolean;
  canEdit: boolean;
  fileInputRef: React.RefObject<HTMLInputElement | null>;

  isPlaying: boolean;
  currentTrackId: string | undefined;

  onDragStart: () => void;
  onDragEnd: (result: DropResult) => void;

  dropTargetTrackId: string | null;
  handleTrackDragEnter: (e: React.DragEvent, trackId: string) => void;
  handleTrackDragLeave: (e: React.DragEvent) => void;
  handlePageDragOver: (e: React.DragEvent) => void;
  handleTrackDrop: (e: React.DragEvent, trackId: string) => void;

  onMoreClick: (track: Track) => void;
  isDraggable: boolean;
}

export function ProjectTrackList({
  tracks,
  filteredTracks,
  project,
  isSearchOpen,
  searchQuery,
  setSearchQuery,
  setIsSearchOpen,
  selectedSearchIndex,
  setSelectedSearchIndex,
  searchInputRef,
  onTrackClick,
  selectedTrackIndexMain,
  fadeHighlightedTrackId,
  isUploading,
  canEdit,
  fileInputRef,
  isPlaying,
  currentTrackId,
  onDragStart,
  onDragEnd,
  dropTargetTrackId,
  handleTrackDragEnter,
  handleTrackDragLeave,
  handlePageDragOver,
  handleTrackDrop,
  onMoreClick,
  isDraggable,
}: ProjectTrackListProps) {
  return (
    <>
      <AnimatePresence>
        {isSearchOpen && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: "auto" }}
            exit={{ opacity: 0, height: 0 }}
            transition={{ duration: 0.2, ease: [0.32, 0.72, 0, 1] }}
            className="overflow-hidden"
          >
            <div className="relative mb-4">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 size-4 text-muted-foreground" />
              <Input
                ref={searchInputRef}
                type="text"
                placeholder="Search tracks..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Escape") {
                    setSearchQuery("");
                    setIsSearchOpen(false);
                    setSelectedSearchIndex(-1);
                  } else if (e.key === "ArrowDown") {
                    e.preventDefault();
                    setSelectedSearchIndex((prev: number) =>
                      prev < filteredTracks.length - 1 ? prev + 1 : 0,
                    );
                  } else if (e.key === "ArrowUp") {
                    e.preventDefault();
                    setSelectedSearchIndex((prev: number) =>
                      prev > 0 ? prev - 1 : filteredTracks.length - 1,
                    );
                  } else if (e.key === "Enter") {
                    e.preventDefault();
                    if (
                      selectedSearchIndex >= 0 &&
                      filteredTracks[selectedSearchIndex]
                    ) {
                      const selectedTrack = filteredTracks[selectedSearchIndex];
                      setSearchQuery("");
                      setIsSearchOpen(false);
                      setSelectedSearchIndex(-1);
                      onTrackClick(selectedTrack);
                    } else {
                      setSearchQuery("");
                      setIsSearchOpen(false);
                      setSelectedSearchIndex(-1);
                    }
                  }
                }}
                className="pl-9 pr-9 h-12 focus-visible:ring-0 focus-visible:ring-offset-0 shadow-none rounded-2xl text-base! border-0"
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
          </motion.div>
        )}
      </AnimatePresence>

      {canEdit && (
        <Button
          onClick={() => fileInputRef.current?.click()}
          disabled={isUploading}
          className="w-full mb-6 h-12 text-base font-semibold active:scale-99"
        >
          <PlusIcon className="size-5 mr-2" />
          {isUploading ? "Uploading..." : "Add Tracks"}
        </Button>
      )}

      {tracks.length === 0 ? (
        <div className="text-center py-12 text-muted-foreground">
          <p className="text-lg">No tracks yet</p>
          <p className="text-sm mt-2">Click "Add Tracks" to get started</p>
        </div>
      ) : filteredTracks.length === 0 && searchQuery.trim() ? (
        <div className="text-center py-12 text-muted-foreground">
          <p className="text-lg">No tracks match your search</p>
          <p className="text-sm mt-2">Try a different search term</p>
        </div>
      ) : (
        <DragDropContext onDragStart={onDragStart} onDragEnd={onDragEnd}>
          <Droppable droppableId="tracks">
            {(provided: DroppableProvided) => (
              <div {...provided.droppableProps} ref={provided.innerRef}>
                {filteredTracks.map((track, index) => (
                  <div
                    key={track.public_id}
                    data-track-drop-zone
                    onDragEnter={(e) =>
                      handleTrackDragEnter(e, track.public_id)
                    }
                    onDragLeave={handleTrackDragLeave}
                    onDragOver={handlePageDragOver}
                    onDrop={(e) => handleTrackDrop(e, track.public_id)}
                    className={`relative rounded-2xl transition-[background-color,box-shadow] duration-700 ${
                      dropTargetTrackId === track.public_id
                        ? "ring-1 ring-white/50 ring-offset-2 ring-offset-background"
                        : ""
                    } ${
                      isSearchOpen && selectedSearchIndex === index
                        ? "bg-white/5 ring-1 ring-white/10"
                        : ""
                    } ${
                      !isSearchOpen && selectedTrackIndexMain === index
                        ? "bg-white/5 ring-1 ring-white/10"
                        : ""
                    } ${
                      fadeHighlightedTrackId === track.public_id
                        ? "bg-white/15 ring-1 ring-white/30"
                        : ""
                    }`}
                  >
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
                        isPlaying && currentTrackId === track.public_id,
                      )}
                      isTranscoding={
                        track.lossy_transcoding_status !== "completed" &&
                        track.lossy_transcoding_status !== null &&
                        track.lossy_transcoding_status !== undefined
                      }
                      onClick={() => onTrackClick(track)}
                      onMoreClick={() => onMoreClick(track)}
                      isShared={track.visibility_status === "public"}
                      isSharedWithUsers={
                        (track as any).is_shared && !(project as any).is_shared
                      }
                      isDraggable={isDraggable}
                    />
                  </div>
                ))}
                {provided.placeholder}
              </div>
            )}
          </Droppable>
        </DragDropContext>
      )}
    </>
  );
}
