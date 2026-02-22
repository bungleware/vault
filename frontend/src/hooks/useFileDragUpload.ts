import { useState, useRef, useCallback } from "react";
import type React from "react";

interface UseFileDragUploadOptions {
  onUploadFiles: (files: File[]) => void;
  onUploadVersion: (trackId: string, file: File) => void;
}

export function useFileDragUpload({
  onUploadFiles,
  onUploadVersion,
}: UseFileDragUploadOptions) {
  const [isFileDragging, setIsFileDragging] = useState(false);
  const [dropTargetTrackId, setDropTargetTrackId] = useState<string | null>(
    null,
  );
  const dragCounterRef = useRef(0);

  const handlePageDragEnter = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    dragCounterRef.current++;

    if (e.dataTransfer.types.includes("Files")) {
      setIsFileDragging(true);
    }
  }, []);

  const handlePageDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    dragCounterRef.current--;

    if (dragCounterRef.current === 0) {
      setIsFileDragging(false);
      setDropTargetTrackId(null);
    }
  }, []);

  const handlePageDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
  }, []);

  const handlePageDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      e.stopPropagation();
      dragCounterRef.current = 0;
      setIsFileDragging(false);
      setDropTargetTrackId(null);

      const files = Array.from(e.dataTransfer.files).filter((file) =>
        file.type.startsWith("audio/") || file.type.startsWith("video/"),
      );

      if (files.length > 0) {
        onUploadFiles(files);
      }
    },
    [onUploadFiles],
  );

  const handleTrackDragEnter = useCallback(
    (e: React.DragEvent, trackId: string) => {
      e.preventDefault();
      e.stopPropagation();
      if (e.dataTransfer.types.includes("Files")) {
        setDropTargetTrackId(trackId);
      }
    },
    [],
  );

  const handleTrackDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    const relatedTarget = e.relatedTarget as HTMLElement;
    if (!relatedTarget?.closest("[data-track-drop-zone]")) {
      setDropTargetTrackId(null);
    }
  }, []);

  const handleTrackDrop = useCallback(
    (e: React.DragEvent, trackId: string) => {
      e.preventDefault();
      e.stopPropagation();
      dragCounterRef.current = 0;
      setIsFileDragging(false);
      setDropTargetTrackId(null);

      const files = Array.from(e.dataTransfer.files).filter((file) =>
        file.type.startsWith("audio/") || file.type.startsWith("video/"),
      );

      if (files.length > 0) {
        onUploadVersion(trackId, files[0]);
      }
    },
    [onUploadVersion],
  );

  return {
    isFileDragging,
    dropTargetTrackId,
    handlePageDragEnter,
    handlePageDragLeave,
    handlePageDragOver,
    handlePageDrop,
    handleTrackDragEnter,
    handleTrackDragLeave,
    handleTrackDrop,
  };
}
