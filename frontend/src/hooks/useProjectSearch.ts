import { useState, useEffect, useRef, useMemo, useCallback } from "react";
import fuzzysort from "fuzzysort";
import type { Track } from "@/types/api";

interface UseProjectSearchOptions {
  tracks: Track[];
  onTrackClick: (track: Track) => void;
  isPlaying: boolean;
  currentTrackId: string | undefined;
  pause: () => void;
}

export function useProjectSearch({
  tracks,
  onTrackClick,
  isPlaying,
  currentTrackId,
  pause,
}: UseProjectSearchOptions) {
  const [isSearchOpen, setIsSearchOpen] = useState(false);
  const [isGlobalSearchOpen, setIsGlobalSearchOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedSearchIndex, setSelectedSearchIndex] = useState(-1);
  const [selectedTrackIndexMain, setSelectedTrackIndexMain] = useState(-1);
  const searchInputRef = useRef<HTMLInputElement>(null);

  const filteredTracks = useMemo(() => {
    if (!searchQuery.trim()) return tracks;

    const results = fuzzysort.go(searchQuery, tracks, {
      key: "title",
      threshold: -10000,
    });

    return results.map((result) => result.obj);
  }, [tracks, searchQuery]);

  useEffect(() => {
    if (isSearchOpen && searchInputRef.current) {
      searchInputRef.current.focus();
    }
  }, [isSearchOpen]);

  useEffect(() => {
    if (isSearchOpen) {
      setSelectedTrackIndexMain(-1);
    }
  }, [isSearchOpen]);

  useEffect(() => {
    if (isSearchOpen && searchQuery.trim()) {
      setSelectedSearchIndex(0);
    }
  }, [searchQuery, isSearchOpen]);

  useEffect(() => {
    if (
      isSearchOpen &&
      selectedSearchIndex >= 0 &&
      filteredTracks[selectedSearchIndex]
    ) {
      const trackId = filteredTracks[selectedSearchIndex].public_id;
      const element = document.querySelector(`[data-track-id="${trackId}"]`);
      if (element) {
        element.scrollIntoView({ behavior: "smooth", block: "center" });
      }
    }
  }, [selectedSearchIndex, isSearchOpen, filteredTracks]);

  useEffect(() => {
    if (
      !isSearchOpen &&
      selectedTrackIndexMain >= 0 &&
      tracks[selectedTrackIndexMain]
    ) {
      const trackId = tracks[selectedTrackIndexMain].public_id;
      const element = document.querySelector(`[data-track-id="${trackId}"]`);
      if (element) {
        element.scrollIntoView({ behavior: "smooth", block: "center" });
      }
    }
  }, [selectedTrackIndexMain, isSearchOpen, tracks]);

  useEffect(() => {
    const handleSearchEvent = () => {
      setIsSearchOpen((prev) => !prev);
    };

    window.addEventListener("project-search", handleSearchEvent);
    return () =>
      window.removeEventListener("project-search", handleSearchEvent);
  }, []);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && !e.shiftKey && e.code === "KeyF") {
        e.preventDefault();
        setIsGlobalSearchOpen((prev) => !prev);
        return;
      }

      if (e.altKey && e.code === "KeyF") {
        e.preventDefault();
        setIsSearchOpen((prev) => !prev);
        return;
      }

      if (
        e.target instanceof HTMLInputElement ||
        e.target instanceof HTMLTextAreaElement
      ) {
        return;
      }

      if (
        e.code === "KeyS" &&
        !e.shiftKey &&
        !e.metaKey &&
        !e.ctrlKey &&
        !e.altKey
      ) {
        e.preventDefault();
        setIsSearchOpen((prev) => !prev);
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (
        e.target instanceof HTMLInputElement ||
        e.target instanceof HTMLTextAreaElement
      ) {
        return;
      }

      if (!isSearchOpen && tracks.length > 0) {
        if (e.key === "ArrowDown") {
          e.preventDefault();
          setSelectedTrackIndexMain((prev) =>
            prev < tracks.length - 1 ? prev + 1 : 0,
          );
        } else if (e.key === "ArrowUp") {
          e.preventDefault();
          setSelectedTrackIndexMain((prev) =>
            prev > 0 ? prev - 1 : tracks.length - 1,
          );
        } else if (e.key === "Enter" && selectedTrackIndexMain >= 0) {
          e.preventDefault();
          const selectedTrack = tracks[selectedTrackIndexMain];
          if (isPlaying && currentTrackId === selectedTrack.public_id) {
            pause();
          } else {
            onTrackClick(selectedTrack);
          }
        } else if (e.key === "Escape") {
          e.preventDefault();
          setSelectedTrackIndexMain(-1);
        }
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [
    isSearchOpen,
    tracks,
    selectedTrackIndexMain,
    onTrackClick,
    isPlaying,
    currentTrackId,
    pause,
  ]);

  const handleBackgroundClick = useCallback((e: React.MouseEvent) => {
    const target = e.target as HTMLElement;
    const isTrackClick = target.closest("[data-track-id]");
    const isButtonClick = target.closest('button, input, [role="button"]');

    if (!isTrackClick && !isButtonClick) {
      setSelectedTrackIndexMain(-1);
      setSelectedSearchIndex(-1);
    }
  }, []);

  return {
    isSearchOpen,
    setIsSearchOpen,
    isGlobalSearchOpen,
    setIsGlobalSearchOpen,
    searchQuery,
    setSearchQuery,
    selectedSearchIndex,
    setSelectedSearchIndex,
    selectedTrackIndexMain,
    setSelectedTrackIndexMain,
    searchInputRef,
    filteredTracks,
    handleBackgroundClick,
  };
}
