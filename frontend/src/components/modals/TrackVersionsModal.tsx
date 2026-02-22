import {
  ChevronLeft,
  X,
  Play,
  Pause,
  MoreHorizontal,
  Plus,
  Pencil,
  Download,
  Trash2,
  Loader2,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useEffect, useState, useRef, useCallback, useMemo } from "react";
import { createPortal } from "react-dom";
import { AnimatePresence, motion } from "motion/react";
import * as Popover from "@radix-ui/react-popover";
import KeySelector from "@/components/modals/KeySelector";
import BPMSelector from "@/components/modals/BPMSelector";
import { updateTrack } from "@/api/tracks";
import { toast } from "@/routes/__root";
import {
  getVersions,
  uploadVersion,
  updateVersion,
  activateVersion,
  deleteVersion,
  downloadVersion,
} from "@/api/versions";
import type { VersionWithMetadata } from "@/types/api";
import { useAudioPlayer } from "@/contexts/AudioPlayerContext";
import DeleteVersionModal from "./DeleteVersionModal";
import { formatTrackDuration } from "@/lib/duration";
import { env } from "@/env";
import { getStreamUrl } from "@/api/media";

const SAVE_DEBOUNCE_MS = 500;
const TAP_TEMPO_DEBOUNCE_MS = 1200;
const PREVIEW_WAVEFORM_HEIGHT = 39;
const PREVIEW_WAVEFORM_BARS = 120;

interface TrackVersionsModalProps {
  isOpen: boolean;
  onClose: () => void;
  onBack: () => void;
  trackId: string;
  track: {
    title: string;
    key?: string | null;
    bpm?: number | null;
    active_version_id?: number | null;
  };
  onUpdate?: () => void;
  onTrackUpdate?: (updates: {
    active_version_id?: number;
    title?: string;
  }) => void;
  showBackdrop?: boolean;
  canEdit?: boolean;
}

export default function TrackVersionsModal({
  isOpen,
  onClose,
  onBack,
  trackId,
  track,
  onUpdate,
  onTrackUpdate,
  showBackdrop = false,
  canEdit = true,
}: TrackVersionsModalProps) {
  const { currentTrack, isPlaying, pause, play, clearPreloadedAudio } =
    useAudioPlayer();
  const [internalOpen, setInternalOpen] = useState(false);
  const [editedKey, setEditedKey] = useState<string | undefined>(
    track.key || undefined,
  );
  const [editedBpm, setEditedBpm] = useState<number | undefined>(
    track.bpm || undefined,
  );
  const [, setIsSaving] = useState(false);
  const [versions, setVersions] = useState<VersionWithMetadata[]>([]);
  const [isLoadingVersions, setIsLoadingVersions] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [activeVersionId, setActiveVersionId] = useState<number | null>(
    track.active_version_id || null,
  );
  const fileInputRef = useRef<HTMLInputElement>(null);
  const tapTimesRef = useRef<number[]>([]);
  const tapFlashTimeoutRef = useRef<number | null>(null);
  const [isTapFlashing, setIsTapFlashing] = useState(false);
  const [isDesktop, setIsDesktop] = useState(false);
  const bpmSaveTimeoutRef = useRef<number | null>(null);
  const keySaveTimeoutRef = useRef<number | null>(null);
  const pendingBpmRef = useRef<number | undefined | null>(null);
  const pendingKeyRef = useRef<string | undefined | null>(null);
  const [deleteVersionTarget, setDeleteVersionTarget] = useState<{
    id: number;
    name: string;
  } | null>(null);
  const [isDeletingVersion, setIsDeletingVersion] = useState(false);
  const [editingVersionId, setEditingVersionId] = useState<number | null>(null);
  const [editingVersionName, setEditingVersionName] = useState("");
  const versionInputRefs = useRef<Map<number, HTMLInputElement>>(new Map());
  const [trackTitle, setTrackTitle] = useState(track.title);
  const closeTimeoutRef = useRef<number | null>(null);
  const previewAudioRef = useRef<HTMLAudioElement>(null);
  const previewAudioVersionRef = useRef<number | null>(null);
  const previewWaveformRef = useRef<HTMLDivElement>(null);
  const pendingPreviewSeekRef = useRef<number | null>(null);
  const [isPreviewPlaying, setIsPreviewPlaying] = useState(false);
  const [previewDuration, setPreviewDuration] = useState(0);
  const [previewProgress, setPreviewProgress] = useState(0);
  const [isPreviewDragging, setIsPreviewDragging] = useState(false);

  const loadVersions = useCallback(async () => {
    setIsLoadingVersions(true);
    try {
      const data = await getVersions(trackId);
      setVersions(data);
      setActiveVersionId((currentActiveVersionId) => {
        if (
          currentActiveVersionId !== null &&
          data.some((version) => version.id === currentActiveVersionId)
        ) {
          return currentActiveVersionId;
        }

        if (
          track.active_version_id !== undefined &&
          track.active_version_id !== null &&
          data.some((version) => version.id === track.active_version_id)
        ) {
          return track.active_version_id;
        }

        return data[0]?.id ?? null;
      });
    } catch (error) {
      console.error("Failed to load versions:", error);
      toast.error("Failed to load versions");
    } finally {
      setIsLoadingVersions(false);
    }
  }, [trackId, track.active_version_id]);

  useEffect(() => {
    if (isOpen) {
      loadVersions();
    }
  }, [isOpen, loadVersions]);

  useEffect(() => {
    if (isOpen) {
      if (closeTimeoutRef.current !== null) {
        clearTimeout(closeTimeoutRef.current);
        closeTimeoutRef.current = null;
      }
      setInternalOpen(true);
      setEditedKey(track.key || undefined);
      setEditedBpm(track.bpm || undefined);
      setActiveVersionId(track.active_version_id || null);
      setTrackTitle(track.title);
    }
  }, [isOpen, track.key, track.bpm, track.active_version_id, track.title]);

  useEffect(() => {
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        handleClose();
      }
    };

    if (internalOpen) {
      document.addEventListener("keydown", handleEscape);
      document.body.style.overflow = "hidden";
    }

    return () => {
      document.removeEventListener("keydown", handleEscape);
      document.body.style.overflow = "unset";
    };
  }, [internalOpen]);

  useEffect(() => {
    if (typeof window === "undefined") return;

    const mediaQuery = window.matchMedia("(min-width: 768px)");
    const handleMediaChange = (event: MediaQueryListEvent) => {
      setIsDesktop(event.matches);
    };

    setIsDesktop(mediaQuery.matches);

    if (typeof mediaQuery.addEventListener === "function") {
      mediaQuery.addEventListener("change", handleMediaChange);
    } else {
      mediaQuery.addListener(handleMediaChange);
    }

    return () => {
      if (typeof mediaQuery.removeEventListener === "function") {
        mediaQuery.removeEventListener("change", handleMediaChange);
      } else {
        mediaQuery.removeListener(handleMediaChange);
      }
    };
  }, []);

  useEffect(() => {
    if (!internalOpen) {
      tapTimesRef.current = [];
      setIsTapFlashing(false);
    }
  }, [internalOpen]);

  useEffect(() => {
    return () => {
      if (tapFlashTimeoutRef.current) {
        window.clearTimeout(tapFlashTimeoutRef.current);
      }
    };
  }, []);

  useEffect(() => {
    return () => {
      if (bpmSaveTimeoutRef.current) {
        window.clearTimeout(bpmSaveTimeoutRef.current);
      }
      if (keySaveTimeoutRef.current) {
        window.clearTimeout(keySaveTimeoutRef.current);
      }
      if (closeTimeoutRef.current) {
        clearTimeout(closeTimeoutRef.current);
      }
      const previewAudio = previewAudioRef.current;
      if (previewAudio) {
        previewAudio.pause();
      }
    };
  }, []);

  const buildVersionPreviewStreamUrl = useCallback(
    async (versionId: number) => {
      const apiBaseUrl = env.VITE_API_URL || "";
      const signed = await getStreamUrl(trackId, {
        quality: "lossy",
        versionId,
      });
      return `${apiBaseUrl}${signed.url}`;
    },
    [trackId],
  );

  const [pendingAction, setPendingAction] = useState<"close" | "back" | null>(
    null,
  );

  const handleClose = () => {
    const previewAudio = previewAudioRef.current;
    if (previewAudio) {
      previewAudio.pause();
      previewAudio.currentTime = 0;
    }
    setIsPreviewPlaying(false);
    setPreviewProgress(0);
    pendingPreviewSeekRef.current = null;
    setPendingAction("close");
    setInternalOpen(false);
  };

  const handleBack = () => {
    const previewAudio = previewAudioRef.current;
    if (previewAudio) {
      previewAudio.pause();
      previewAudio.currentTime = 0;
    }
    setIsPreviewPlaying(false);
    setPreviewProgress(0);
    pendingPreviewSeekRef.current = null;
    setPendingAction("back");
    setInternalOpen(false);
  };

  const persistTrackUpdate = useCallback(
    async (
      updates: { bpm?: number | undefined; key?: string | undefined },
      {
        error,
        logContext,
      }: { success: string; error: string; logContext: string },
    ) => {
      if (!canEdit) return;

      setIsSaving(true);
      try {
        await updateTrack(trackId, updates);
        onUpdate?.();
      } catch (updateError) {
        toast.error(error);
        console.error(`[TrackVersionsModal] ${logContext}:`, updateError);
      } finally {
        setIsSaving(false);
      }
    },
    [trackId, onUpdate, canEdit],
  );

  const handleSaveBpm = useCallback(
    (newBpm?: number | null, options?: { debounceMs?: number }) => {
      const debounceMs = options?.debounceMs ?? SAVE_DEBOUNCE_MS;
      const normalizedBpm =
        typeof newBpm === "number" && !Number.isNaN(newBpm)
          ? newBpm
          : undefined;

      setEditedBpm(normalizedBpm);
      pendingBpmRef.current = normalizedBpm;

      if (bpmSaveTimeoutRef.current) {
        window.clearTimeout(bpmSaveTimeoutRef.current);
      }

      bpmSaveTimeoutRef.current = window.setTimeout(() => {
        if (pendingBpmRef.current === null) {
          return;
        }

        const valueToSave = pendingBpmRef.current;
        pendingBpmRef.current = null;

        persistTrackUpdate(
          { bpm: valueToSave ?? undefined },
          {
            success: "BPM updated successfully",
            error: "Failed to update BPM",
            logContext: "Failed to update BPM",
          },
        );
      }, debounceMs);
    },
    [persistTrackUpdate],
  );

  const handleSaveKey = useCallback(
    (newKey?: string | null) => {
      const normalizedKey = newKey || undefined;
      setEditedKey(normalizedKey);
      pendingKeyRef.current = normalizedKey;

      if (keySaveTimeoutRef.current) {
        window.clearTimeout(keySaveTimeoutRef.current);
      }

      keySaveTimeoutRef.current = window.setTimeout(() => {
        if (pendingKeyRef.current === null) {
          return;
        }

        const keyValue = pendingKeyRef.current;
        pendingKeyRef.current = null;

        persistTrackUpdate(
          { key: keyValue ?? undefined },
          {
            success: "Key updated successfully",
            error: "Failed to update key",
            logContext: "Failed to update key",
          },
        );
      }, SAVE_DEBOUNCE_MS);
    },
    [persistTrackUpdate],
  );

  const handleAddVersion = async (files: FileList | null) => {
    if (!files || files.length === 0) return;

    const file = files[0];
    setIsUploading(true);

    try {
      await uploadVersion(trackId, file);

      await loadVersions();
      onUpdate?.();
    } catch (error) {
      toast.error("Failed to upload version");
      console.error("Failed to upload version:", error);
    } finally {
      setIsUploading(false);
    }
  };

  const handleTapTempo = useCallback(() => {
    if (typeof window === "undefined") return;

    const now = performance.now();
    tapTimesRef.current = tapTimesRef.current.filter(
      (time) => now - time <= 6000,
    );
    tapTimesRef.current.push(now);

    setIsTapFlashing(true);
    if (tapFlashTimeoutRef.current) {
      window.clearTimeout(tapFlashTimeoutRef.current);
    }
    tapFlashTimeoutRef.current = window.setTimeout(() => {
      setIsTapFlashing(false);
    }, 160);

    if (tapTimesRef.current.length < 2) {
      return;
    }

    const intervals = tapTimesRef.current
      .slice(1)
      .map((time, index) => time - tapTimesRef.current[index]);
    const avgInterval =
      intervals.reduce((sum, interval) => sum + interval, 0) / intervals.length;

    if (avgInterval <= 0) return;

    const computedBpm = Math.round(60000 / avgInterval);
    const boundedBpm = Math.max(40, Math.min(240, computedBpm));

    if (boundedBpm === editedBpm) {
      return;
    }

    handleSaveBpm(boundedBpm, { debounceMs: TAP_TEMPO_DEBOUNCE_MS });
  }, [editedBpm, handleSaveBpm]);

  useEffect(() => {
    if (!internalOpen || !isDesktop) {
      return;
    }

    const handleSpaceKey = (event: KeyboardEvent) => {
      if (event.code !== "Space" && event.key !== " ") {
        return;
      }

      const target = event.target as HTMLElement | null;
      if (
        target &&
        (target.tagName === "INPUT" ||
          target.tagName === "TEXTAREA" ||
          target.isContentEditable)
      ) {
        return;
      }

      event.preventDefault();
      handleTapTempo();
    };

    window.addEventListener("keydown", handleSpaceKey);

    return () => {
      window.removeEventListener("keydown", handleSpaceKey);
    };
  }, [internalOpen, isDesktop, handleTapTempo]);

  const handleRenameVersion = (versionId: number, currentName: string) => {
    setEditingVersionId(versionId);
    setEditingVersionName(currentName);

    setTimeout(() => {
      const input = versionInputRefs.current.get(versionId);
      if (input) {
        input.focus();
        requestAnimationFrame(() => {
          const inputElement = versionInputRefs.current.get(versionId);
          if (inputElement) {
            const length = inputElement.value.length;
            inputElement.setSelectionRange(length, length);
          }
        });
      }
    }, 200);
  };

  const handleSaveVersionName = async (
    versionId: number,
    originalName: string,
  ) => {
    const trimmedName = editingVersionName.trim();

    setEditingVersionId(null);
    setEditingVersionName("");

    if (!trimmedName || trimmedName === originalName) {
      return;
    }

    try {
      await updateVersion(versionId, { version_name: trimmedName });
      await loadVersions();
      onUpdate?.();
    } catch (error) {
      toast.error("Failed to rename version");
      console.error("Failed to rename version:", error);
    }
  };

  const handleActivateVersion = async (versionId: number) => {
    try {
      await activateVersion(versionId);
      setActiveVersionId(versionId);
      onTrackUpdate?.({ active_version_id: versionId });

      if (currentTrack?.id === trackId) {
        clearPreloadedAudio();

        pause();

        setTimeout(() => {
          const updatedTrack = { ...currentTrack, versionId };
          play(updatedTrack, undefined, false, true);
        }, 100);
      }

      await loadVersions();
      onUpdate?.();
    } catch (error) {
      toast.error("Failed to activate version");
      console.error("Failed to activate version:", error);
    }
  };

  const handleDeleteVersion = (versionId: number, versionName: string) => {
    setDeleteVersionTarget({ id: versionId, name: versionName });
  };

  const confirmDeleteVersion = async () => {
    if (!deleteVersionTarget) return;
    setIsDeletingVersion(true);
    try {
      await deleteVersion(deleteVersionTarget.id);

      await loadVersions();
      onUpdate?.();
      setDeleteVersionTarget(null);
    } catch (error: any) {
      const errorMessage = error?.message || "Failed to delete version";
      toast.error(errorMessage);
      console.error("Failed to delete version:", error);
    } finally {
      setIsDeletingVersion(false);
    }
  };

  const handleDownloadVersion = async (versionId: number) => {
    try {
      await downloadVersion(trackId, versionId);
      toast.success("Download started");
    } catch (error) {
      toast.error("Failed to download version");
      console.error("Failed to download version:", error);
    }
  };

  const handleSaveTrackTitle = async () => {
    if (trackTitle === track.title) return;
    if (!canEdit) return;

    try {
      await updateTrack(trackId, { title: trackTitle });
      onTrackUpdate?.({ title: trackTitle });
      onUpdate?.();
    } catch (error) {
      toast.error("Failed to update track title");
      console.error("Failed to update track title:", error);
      setTrackTitle(track.title);
    }
  };

  const formatFileSize = (bytes?: number | null): string => {
    if (!bytes) return "";
    const units = ["B", "KB", "MB", "GB"];
    let size = bytes;
    let unitIndex = 0;
    while (size >= 1024 && unitIndex < units.length - 1) {
      size /= 1024;
      unitIndex++;
    }
    return `${size.toFixed(1)} ${units[unitIndex]}`;
  };

  const formatDate = (dateString: string): string => {
    const date = new Date(dateString);
    return date.toLocaleDateString("en-US", {
      month: "short",
      day: "numeric",
      year: "numeric",
    });
  };

  const activeVersion = versions.find((v) => v.id === activeVersionId);
  const waveformBars = useMemo(() => {
    let waveformData: number[] = [];
    if (activeVersion?.waveform) {
      try {
        const parsed = JSON.parse(activeVersion.waveform);
        if (Array.isArray(parsed) && parsed.length > 0) {
          waveformData = parsed;
        }
      } catch (error) {
        console.error("[TrackVersionsModal] Failed to parse waveform:", error);
      }
    }

    const bars: number[] = [];
    if (waveformData.length > 0) {
      for (let i = 0; i < PREVIEW_WAVEFORM_BARS; i++) {
        const index = Math.floor((i / PREVIEW_WAVEFORM_BARS) * waveformData.length);
        bars.push(waveformData[index]);
      }
      return bars;
    }

    for (let i = 0; i < PREVIEW_WAVEFORM_BARS; i++) {
      bars.push(Math.random() * 60 + 20);
    }
    return bars;
  }, [activeVersion?.id, activeVersion?.waveform]);

  const effectivePreviewDuration =
    previewDuration > 0 ? previewDuration : (activeVersion?.duration_seconds ?? 0);
  const previewProgressPercent =
    effectivePreviewDuration > 0
      ? Math.max(0, Math.min(100, (previewProgress / effectivePreviewDuration) * 100))
      : 0;

  const seekPreviewFromClientX = useCallback(
    (clientX: number) => {
      const waveformElement = previewWaveformRef.current;
      if (!waveformElement || effectivePreviewDuration <= 0) {
        return;
      }

      const rect = waveformElement.getBoundingClientRect();
      const x = clientX - rect.left;
      const percentage = Math.max(0, Math.min(1, x / rect.width));
      const seekTime = percentage * effectivePreviewDuration;
      pendingPreviewSeekRef.current = seekTime;
      setPreviewProgress(seekTime);
    },
    [effectivePreviewDuration],
  );

  const handlePreviewPlayToggle = useCallback(async () => {
    if (!activeVersionId) return;

    const previewAudio = previewAudioRef.current;
    if (!previewAudio) return;

    if (previewAudioVersionRef.current !== activeVersionId) {
      try {
        const targetSrc = await buildVersionPreviewStreamUrl(activeVersionId);
        previewAudio.src = targetSrc;
        previewAudio.load();
        previewAudioVersionRef.current = activeVersionId;
      } catch (error) {
        console.error("[TrackVersionsModal] Failed to load preview URL", error);
        return;
      }
    }

    if (previewAudio.paused) {
      if (isPlaying && currentTrack) {
        pause();
      }
      try {
        await previewAudio.play();
      } catch (error) {
        console.error("[TrackVersionsModal] Failed to start preview playback:", error);
      }
      return;
    }

    previewAudio.pause();
  }, [
    activeVersionId,
    buildVersionPreviewStreamUrl,
    currentTrack,
    isPlaying,
    pause,
  ]);

  useEffect(() => {
    const previewAudio = previewAudioRef.current;
    if (!internalOpen || !previewAudio) return;

    const handlePlay = () => setIsPreviewPlaying(true);
    const handlePause = () => setIsPreviewPlaying(false);
    const handleEnded = () => {
      setIsPreviewPlaying(false);
      pendingPreviewSeekRef.current = null;
      setPreviewProgress(0);
    };
    const handleLoadedMetadata = () => {
      if (Number.isFinite(previewAudio.duration) && previewAudio.duration > 0) {
        setPreviewDuration(previewAudio.duration);
      }
    };
    const handleTimeUpdate = () => {
      if (!isPreviewDragging && pendingPreviewSeekRef.current === null) {
        setPreviewProgress(previewAudio.currentTime || 0);
      }
    };

    previewAudio.addEventListener("play", handlePlay);
    previewAudio.addEventListener("pause", handlePause);
    previewAudio.addEventListener("ended", handleEnded);
    previewAudio.addEventListener("loadedmetadata", handleLoadedMetadata);
    previewAudio.addEventListener("timeupdate", handleTimeUpdate);

    return () => {
      previewAudio.removeEventListener("play", handlePlay);
      previewAudio.removeEventListener("pause", handlePause);
      previewAudio.removeEventListener("ended", handleEnded);
      previewAudio.removeEventListener("loadedmetadata", handleLoadedMetadata);
      previewAudio.removeEventListener("timeupdate", handleTimeUpdate);
    };
  }, [internalOpen, isPreviewDragging]);

  useEffect(() => {
    const previewAudio = previewAudioRef.current;
    if (!previewAudio || !internalOpen || !activeVersionId) return;

    if (previewAudioVersionRef.current !== activeVersionId) {
      (async () => {
        try {
          const targetSrc = await buildVersionPreviewStreamUrl(activeVersionId);
          if (!previewAudio) return;
          previewAudio.pause();
          previewAudio.src = targetSrc;
          previewAudio.load();
          previewAudioVersionRef.current = activeVersionId;
          setIsPreviewPlaying(false);
          setPreviewProgress(0);
          pendingPreviewSeekRef.current = null;
        } catch (error) {
          console.error("[TrackVersionsModal] Failed to load preview URL", error);
        }
      })();
    }
  }, [activeVersionId, buildVersionPreviewStreamUrl, internalOpen]);

  useEffect(() => {
    if (!internalOpen) {
      const previewAudio = previewAudioRef.current;
      if (previewAudio) {
        previewAudio.pause();
      }
      previewAudioVersionRef.current = null;
      setIsPreviewPlaying(false);
      setPreviewProgress(0);
      setPreviewDuration(0);
      pendingPreviewSeekRef.current = null;
    }
  }, [internalOpen]);

  useEffect(() => {
    if (!isPreviewDragging) return;

    const handleMouseMove = (event: MouseEvent) => {
      event.preventDefault();
      seekPreviewFromClientX(event.clientX);
    };
    const handleTouchMove = (event: TouchEvent) => {
      event.preventDefault();
      if (event.touches.length > 0) {
        seekPreviewFromClientX(event.touches[0].clientX);
      }
    };
    const commitSeek = (clientX: number) => {
      const previewAudio = previewAudioRef.current;
      if (!previewAudio) return;

      seekPreviewFromClientX(clientX);
      const seekTime = pendingPreviewSeekRef.current;
      if (seekTime === null) return;
      previewAudio.currentTime = seekTime;
      pendingPreviewSeekRef.current = null;
    };
    const handleMouseUp = (event: MouseEvent) => {
      setIsPreviewDragging(false);
      commitSeek(event.clientX);
    };
    const handleTouchEnd = (event: TouchEvent) => {
      setIsPreviewDragging(false);
      if (event.changedTouches.length > 0) {
        commitSeek(event.changedTouches[0].clientX);
      } else {
        pendingPreviewSeekRef.current = null;
      }
    };

    document.body.style.userSelect = "none";
    document.addEventListener("mousemove", handleMouseMove);
    document.addEventListener("mouseup", handleMouseUp);
    document.addEventListener("touchmove", handleTouchMove, { passive: false });
    document.addEventListener("touchend", handleTouchEnd);

    return () => {
      document.body.style.userSelect = "";
      document.removeEventListener("mousemove", handleMouseMove);
      document.removeEventListener("mouseup", handleMouseUp);
      document.removeEventListener("touchmove", handleTouchMove);
      document.removeEventListener("touchend", handleTouchEnd);
    };
  }, [isPreviewDragging, seekPreviewFromClientX]);

  const metadataString = activeVersion
    ? [
        activeVersion.source_file_size
          ? formatFileSize(activeVersion.source_file_size)
          : null,
        activeVersion.source_format?.toUpperCase(),
      ]
        .filter(Boolean)
        .join(" · ")
    : "";

  return (
    <>
      {createPortal(
        <>
          <style>{`
        @supports (animation-timeline: scroll()) {
          @property --ft {
            syntax: '<length>';
            inherits: false;
            initial-value: 0px;
          }
          @property --fb {
            syntax: '<length>';
            inherits: false;
            initial-value: 40px;
          }
          .scroll-fade-y {
            mask-image: linear-gradient(
              to bottom,
              transparent 0,
              #000 var(--ft),
              #000 calc(100% - var(--fb)),
              transparent 100%
            );
            mask-size: 100% 100%;
            mask-repeat: no-repeat;
            animation: t 1s linear both, b 1s linear both;
            animation-timeline: scroll(self), scroll(self);
            animation-range: 0% 12%, 88% 100%;
          }
          @keyframes t {
            from { --ft: 0px; }
            to { --ft: 40px; }
          }
          @keyframes b {
            from { --fb: 40px; }
            to { --fb: 0px; }
          }
        }
      `}</style>
          <AnimatePresence
            onExitComplete={() => {
              if (!internalOpen && pendingAction) {
                if (pendingAction === "close") {
                  onClose();
                } else if (pendingAction === "back") {
                  onBack();
                }
                setPendingAction(null);
              }
            }}
          >
            {internalOpen && (
              <motion.div
                key="versions-modal"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.15 }}
                className="fixed inset-0 z-1000 flex items-center justify-center p-4"
              >
                <div
                  className={`absolute inset-0 ${showBackdrop ? "bg-black/80" : ""}`}
                  onClick={handleClose}
                />

                <motion.div
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: 8 }}
                  transition={{ duration: 0.15 }}
                  className="relative z-10 w-full max-w-md border border-[#292828] rounded-[34px] shadow-2xl overflow-hidden"
                  style={{
                    background:
                      "linear-gradient(0deg, #151515 0%, #1D1D1D 100%)",
                  }}
                  onClick={(e) => e.stopPropagation()}
                >
                  <audio
                    ref={previewAudioRef}
                    preload="metadata"
                    crossOrigin="anonymous"
                  />
                  <div className="flex flex-col h-[720px] relative">
                    <div className="flex items-center justify-between p-6 pb-4">
                      <Button
                        size="icon-lg"
                        onClick={handleBack}
                        className="shrink-0"
                      >
                        <ChevronLeft className="size-5" />
                      </Button>
                      <div className="flex-1" />
                      <Button
                        size="icon-lg"
                        onClick={handleClose}
                        className="shrink-0"
                      >
                        <X className="size-5" />
                      </Button>
                    </div>

                    <div className="flex flex-col items-center gap-3 px-6">
                      <input
                        type="text"
                        value={trackTitle}
                        onChange={(e) => setTrackTitle(e.target.value)}
                        onBlur={handleSaveTrackTitle}
                        onKeyDown={(e) => {
                          if (e.key === "Enter") {
                            e.currentTarget.blur();
                          }
                        }}
                        className="text-2xl font-semibold text-white text-center bg-transparent border-none outline-none focus:outline-none w-full"
                        style={{
                          caretColor: "white",
                        }}
                      />

                      <div className="flex flex-wrap items-center justify-center gap-3">
                        <div
                          className="flex items-center gap-2 text-sm text-[#8f8f8f]"
                          style={{
                            fontFamily: '"IBM Plex Mono", monospace',
                            fontWeight: 300,
                          }}
                        >
                          <span>Key:</span>
                          <Popover.Root>
                            <Popover.Trigger asChild>
                              <button
                                type="button"
                                className="px-2 py-1 bg-[#2e2e2e] border border-[#3e3e3e] rounded-md hover:bg-[#3e3e3e] transition-colors cursor-pointer min-w-[86px]"
                              >
                                {editedKey || track.key || "Not set"}
                              </button>
                            </Popover.Trigger>
                            <Popover.Portal>
                              <Popover.Content
                                side="bottom"
                                align="center"
                                sideOffset={8}
                                className="z-1001 w-[440px] bg-[#1a1a1a] border border-[#353333] rounded-3xl shadow-2xl overflow-hidden p-5 data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95 data-[side=bottom]:slide-in-from-top-2"
                              >
                                <div className="flex flex-col gap-4">
                                  <div className="flex items-center justify-between">
                                    <h3 className="text-lg font-semibold text-white">
                                      Select Key
                                    </h3>
                                    <Popover.Close asChild>
                                      <Button
                                        size="icon-sm"
                                        variant="ghost"
                                        className="h-7 w-7"
                                      >
                                        <X className="size-4" />
                                      </Button>
                                    </Popover.Close>
                                  </div>

                                  <KeySelector
                                    value={editedKey}
                                    onChange={(key) => {
                                      handleSaveKey(key);
                                    }}
                                  />
                                </div>
                              </Popover.Content>
                            </Popover.Portal>
                          </Popover.Root>
                        </div>

                        <div
                          className="flex items-center gap-2 text-sm text-[#8f8f8f]"
                          style={{
                            fontFamily: '"IBM Plex Mono", monospace',
                            fontWeight: 300,
                          }}
                        >
                          <span>BPM:</span>
                          <Popover.Root>
                            <Popover.Trigger asChild>
                              <button
                                type="button"
                                className="px-2 py-1 bg-[#2e2e2e] border border-[#3e3e3e] rounded-md hover:bg-[#3e3e3e] transition-colors cursor-pointer min-w-[86px]"
                              >
                                {editedBpm || track.bpm || "Not set"}
                              </button>
                            </Popover.Trigger>
                            <Popover.Portal>
                              <Popover.Content
                                side="bottom"
                                align="center"
                                sideOffset={8}
                                className="z-1001 bg-[#1a1a1a] border border-[#353333] rounded-2xl shadow-2xl p-3 data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95 data-[side=bottom]:slide-in-from-top-2"
                              >
                                <BPMSelector
                                  value={editedBpm}
                                  onChange={handleSaveBpm}
                                  onClose={() => {}}
                                />
                              </Popover.Content>
                            </Popover.Portal>
                          </Popover.Root>
                        </div>

                        <div className="flex items-center">
                          <button
                            className={`h-8 rounded-lg border border-[#3a3a3a] bg-[#1f1f1f] px-4 text-[11px] font-semibold uppercase tracking-[0.2em] text-white transition-all duration-150 hover:bg-[#262626] active:bg-[#2b2b2b] ${
                              isTapFlashing
                                ? "ring-1 ring-white/40 shadow-[0_0_10px_rgba(255,255,255,0.2)]"
                                : ""
                            } focus:outline-none`}
                            onClick={handleTapTempo}
                          >
                            Tap
                          </button>
                        </div>
                      </div>

                      {internalOpen && (
                        <>
                          <p
                            className="hidden md:block text-xs text-[#8f8f8f] text-center"
                            style={{
                              fontFamily: '"IBM Plex Mono", monospace',
                              fontWeight: 300,
                            }}
                          >
                            Tap the button or press spacebar to detect the BPM.
                          </p>
                          <p
                            className="md:hidden text-xs text-[#8f8f8f] text-center"
                            style={{
                              fontFamily: '"IBM Plex Mono", monospace',
                              fontWeight: 300,
                            }}
                          >
                            Tap the button to set the BPM from your rhythm.
                          </p>
                        </>
                      )}

                      {metadataString && (
                        <p
                          className="text-sm text-[#7a7a7a] text-center"
                          style={{
                            fontFamily: '"IBM Plex Mono", monospace',
                            fontWeight: 300,
                          }}
                        >
                          {metadataString}
                        </p>
                      )}
                    </div>
                    <div className="flex items-center gap-4 px-6 mt-6">
                      <Button
                        size="icon-lg"
                        className="shrink-0"
                        onClick={handlePreviewPlayToggle}
                        disabled={!activeVersionId}
                      >
                        {isPreviewPlaying ? (
                          <Pause className="size-5 fill-current" />
                        ) : (
                          <Play className="size-5 fill-current" />
                        )}
                      </Button>

                      <div
                        ref={previewWaveformRef}
                        className="relative flex-1 h-[39px] cursor-pointer"
                        onMouseDown={(event) => {
                          setIsPreviewDragging(true);
                          seekPreviewFromClientX(event.clientX);
                        }}
                        onTouchStart={(event) => {
                          setIsPreviewDragging(true);
                          if (event.touches.length > 0) {
                            seekPreviewFromClientX(event.touches[0].clientX);
                          }
                        }}
                      >
                        <svg
                          width="100%"
                          height={String(PREVIEW_WAVEFORM_HEIGHT)}
                          viewBox={`0 0 ${PREVIEW_WAVEFORM_BARS * 2} ${PREVIEW_WAVEFORM_HEIGHT}`}
                          preserveAspectRatio="none"
                          className="text-white"
                        >
                          {waveformBars.map((height, i) => {
                            const x = i * 2 + 1;
                            const amplitude = height / 100;
                            const centerY = PREVIEW_WAVEFORM_HEIGHT / 2;
                            const barHeight = amplitude * 28;
                            const y1 = centerY - barHeight / 2;
                            const y2 = centerY + barHeight / 2;
                            const barPercent = (x / (PREVIEW_WAVEFORM_BARS * 2)) * 100;
                            const isPassed = barPercent <= previewProgressPercent;

                            return (
                              <line
                                key={x}
                                x1={x}
                                y1={y1}
                                x2={x}
                                y2={y2}
                                stroke={isPassed ? "white" : "currentColor"}
                                opacity={isPassed ? "1" : "0.4"}
                                strokeWidth="1"
                                strokeLinecap="round"
                              />
                            );
                          })}
                        </svg>
                        <div
                          className="absolute top-0 bottom-0 w-0.5 bg-amber-400 rounded-full pointer-events-none"
                          style={{
                            left: `${previewProgressPercent}%`,
                            transform: "translateX(-50%)",
                          }}
                        />
                      </div>
                    </div>

                    <div className="scroll-fade-y flex flex-col gap-3 px-6 mt-8 pt-3 pb-25 overflow-y-auto flex-1 scrollbar-thin scrollbar-track-transparent scrollbar-thumb-white/10 hover:scrollbar-thumb-white/20">
                      {isLoadingVersions ? null : versions.length === 0 ? (
                        <div className="flex items-center justify-center py-8 text-white/50">
                          No versions found
                        </div>
                      ) : (
                        versions.map((version) => {
                          const isActive = version.id === activeVersionId;
                          const durationLabel = formatTrackDuration(
                            version.duration_seconds,
                          );
                          return (
                            <div
                              key={version.id}
                              className={`relative border border-[#676767] rounded-[15px] p-5 transition-all cursor-pointer hover:border-[#d2d2d2] ${
                                isActive ? "bg-white/5" : ""
                              }`}
                              onClick={() =>
                                !isActive && handleActivateVersion(version.id)
                              }
                            >
                              {isActive && (
                                <div
                                  className="absolute top-0 left-0 translate-x-1/4 -translate-y-1/2 px-2 py-1 bg-[#151414] border border-[#595959] rounded-[7px] text-[10px] text-white"
                                  style={{
                                    fontFamily: '"IBM Plex Mono", monospace',
                                    fontWeight: 300,
                                  }}
                                >
                                  Active Version
                                </div>
                              )}

                              <div
                                className={"flex items-center justify-between"}
                              >
                                <div className="flex flex-col gap-1">
                                  {editingVersionId === version.id ? (
                                    <input
                                      ref={(el) => {
                                        if (el) {
                                          versionInputRefs.current.set(
                                            version.id,
                                            el,
                                          );
                                        } else {
                                          versionInputRefs.current.delete(
                                            version.id,
                                          );
                                        }
                                      }}
                                      type="text"
                                      value={editingVersionName}
                                      onChange={(e) =>
                                        setEditingVersionName(e.target.value)
                                      }
                                      onBlur={() =>
                                        handleSaveVersionName(
                                          version.id,
                                          version.version_name,
                                        )
                                      }
                                      onKeyDown={(e) => {
                                        if (e.key === "Enter") {
                                          e.currentTarget.blur();
                                        } else if (e.key === "Escape") {
                                          setEditingVersionId(null);
                                          setEditingVersionName("");
                                        }
                                      }}
                                      onClick={(e) => e.stopPropagation()}
                                      className="text-sm text-white bg-transparent border-none outline-none focus:outline-none p-0 m-0"
                                      style={{
                                        fontFamily:
                                          '"IBM Plex Mono", monospace',
                                        fontWeight: 300,
                                        caretColor: "white",
                                      }}
                                    />
                                  ) : (
                                    <p
                                      className="text-sm text-white"
                                      style={{
                                        fontFamily:
                                          '"IBM Plex Mono", monospace',
                                        fontWeight: 300,
                                      }}
                                    >
                                      {version.version_name}
                                    </p>
                                  )}
                                  <p
                                    className="text-xs text-[#7a7a7a]"
                                    style={{
                                      fontFamily: '"IBM Plex Mono", monospace',
                                      fontWeight: 300,
                                    }}
                                  >
                                    {formatDate(version.created_at)}
                                    {version.source_file_size &&
                                      ` · ${formatFileSize(version.source_file_size)}`}
                                    {durationLabel && ` · ${durationLabel}`}
                                    {version.lossy_transcoding_status ===
                                      "pending" && " · Transcoding..."}
                                  </p>
                                </div>

                                <div onClick={(e) => e.stopPropagation()}>
                                  <DropdownMenu>
                                    <DropdownMenuTrigger asChild>
                                      <Button
                                        size="icon-sm"
                                        variant="ghost"
                                        className="shrink-0 h-5 rounded-md hover:bg-white/10"
                                      >
                                        <MoreHorizontal className="size-4 text-white" />
                                      </Button>
                                    </DropdownMenuTrigger>
                                    <DropdownMenuContent
                                      align="center"
                                      side="top"
                                      className="w-44 border-muted bg-background z-1001"
                                    >
                                      <DropdownMenuItem
                                        onSelect={() =>
                                          handleRenameVersion(
                                            version.id,
                                            version.version_name,
                                          )
                                        }
                                      >
                                        <Pencil className="ml-1 mr-1.5 size-4.5" />
                                        Rename
                                      </DropdownMenuItem>
                                      <DropdownMenuItem
                                        onSelect={() =>
                                          handleDownloadVersion(version.id)
                                        }
                                      >
                                        <Download className="ml-1 mr-1.5 size-4.5" />
                                        Export version
                                      </DropdownMenuItem>
                                      <DropdownMenuSeparator />
                                      <DropdownMenuItem
                                        variant="destructive"
                                        onSelect={() =>
                                          handleDeleteVersion(
                                            version.id,
                                            version.version_name,
                                          )
                                        }
                                      >
                                        <Trash2 className="ml-1 mr-1.5 size-4.5" />
                                        Delete version
                                      </DropdownMenuItem>
                                    </DropdownMenuContent>
                                  </DropdownMenu>
                                </div>
                              </div>
                            </div>
                          );
                        })
                      )}
                    </div>

                    <div
                      className="absolute bottom-0 left-0 right-0 h-[140px] z-10 pointer-events-none rounded-bl-[33px] rounded-br-[33px]"
                      style={{
                        background:
                          "linear-gradient(to top, #151515 50%, rgba(21, 21, 21, 1) 55%, rgba(21, 21, 21, 0.85) 60%, rgba(21, 21, 21, 0.7) 65%, rgba(21, 21, 21, 0.6) 70%, rgba(21, 21, 21, 0.3) 75%, rgba(21, 21, 21, 0.1) 90%, transparent 100%)",
                      }}
                    />

                    <input
                      ref={fileInputRef}
                      type="file"
                      accept="audio/*,video/mp4,video/quicktime,video/x-matroska,video/x-msvideo,video/webm"
                      className="hidden"
                      onChange={(e) => handleAddVersion(e.target.files)}
                    />

                    <div className="absolute bottom-0 left-0 right-0 flex items-center gap-4 px-6 pb-6 z-20">
                      <Button
                        className="flex-1 bg-[#1e1e1e] border border-[#2e2e2e] hover:bg-[#252525] active:bg-[#2a2a2a] text-white rounded-xl h-[41px]"
                        onClick={() => fileInputRef.current?.click()}
                        disabled={isUploading || !canEdit}
                      >
                        {isUploading ? (
                          <>
                            <Loader2 className="size-4 mr-2 animate-spin" />
                            <span className="text-sm font-semibold">
                              Uploading...
                            </span>
                          </>
                        ) : (
                          <>
                            <Plus className="size-4 mr-2" />
                            <span className="text-sm font-semibold">Add</span>
                          </>
                        )}
                      </Button>
                      <Button
                        onClick={handleClose}
                        variant={"hot"}
                        className="flex-1 bg-[#e0e0e0] hover:bg-[#d5d5d5] active:bg-[#cacaca] text-black rounded-xl h-[41px]"
                      >
                        <span className="text-sm font-semibold">Done</span>
                      </Button>
                    </div>
                  </div>
                </motion.div>
              </motion.div>
            )}
          </AnimatePresence>
        </>,
        document.body,
      )}
      <DeleteVersionModal
        isOpen={!!deleteVersionTarget}
        onClose={() => {
          if (!isDeletingVersion) {
            setDeleteVersionTarget(null);
          }
        }}
        onConfirm={confirmDeleteVersion}
        versionName={deleteVersionTarget?.name ?? ""}
        isDeleting={isDeletingVersion}
      />
    </>
  );
}
