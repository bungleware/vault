import {
  PlayIcon,
  PauseIcon,
  Volume2Icon,
  Volume1Icon,
  VolumeXIcon,
  ListIcon,
  ShuffleIcon,
  RepeatIcon,
  Repeat1Icon,
} from "lucide-react";
import type React from "react";
import { useState, useEffect, useMemo, useRef, useCallback } from "react";
import { motion, useMotionValue, useSpring, useTransform } from "motion/react";
import { Filter } from "virtual:refractionFilter?width=20&height=32&radius=10&bezelWidth=12&glassThickness=50&refractiveIndex=1.48&bezelType=convex_squircle";
import { useAudioPlayer } from "../contexts/AudioPlayerContext";
import QueuePanel from "./QueuePanel";
import ScrollingText from "./ScrollingText";
import {
  AnimatedSkipBackIcon,
  AnimatedSkipForwardIcon,
  type AnimatedIconHandle,
} from "./AnimatedSkipIcons";
import { useProjectCoverImage } from "../hooks/useProjectCoverImage";
import { useNavigate, useRouterState } from "@tanstack/react-router";

interface MusicPlayerProps {
  hideControls?: boolean;
}

export default function MusicPlayer({
  hideControls = false,
}: MusicPlayerProps) {
  const navigate = useNavigate();
  const routerState = useRouterState();
  const {
    currentTrack,
    audioUrl,
    isPlaying,
    pause,
    resume,
    nextTrack,
    previousTrack,
    playFromQueue,
    loopMode,
    toggleLoop,
    isShuffled,
    toggleShuffle,
    queue,
    onPlayingChange,
    onDurationChange,
    onProgressUpdate,
    onEnded,
    audioPlayerRef,
    getPreloadedAudio,
    clearPreloadedAudio,
  } = useAudioPlayer();

  const projectForCover =
    currentTrack?.projectId && currentTrack?.projectCoverUrl
      ? ({
          public_id: currentTrack.projectId,
          cover_url: currentTrack.projectCoverUrl,
        } as any)
      : undefined;
  const { imageUrl: retainedCoverUrl } = useProjectCoverImage(
    projectForCover,
    "small",
  );

  const coverUrl = retainedCoverUrl || currentTrack?.coverUrl;

  const INITIAL_VOLUME = 100;
  const VOLUME_STORAGE_KEY = "vault-volume";
  const SHOW_QUEUE_BADGE = false;
  const WAVEFORM_VIEWBOX_HEIGHT = 120;
  const WAVEFORM_BAR_WIDTH = 0.8;
  const WAVEFORM_BAR_RADIUS = 2;
  const WAVEFORM_BAR_GAP = 2;
  const WAVEFORM_BAR_X_OFFSET = 0.1;
  const [isVolumeHovered, setIsVolumeHovered] = useState(false);
  const [isVolumePopupOpen, setIsVolumePopupOpen] = useState(false);
  const [isMobileScreen, setIsMobileScreen] = useState(false);
  const [isCurrentTimeHovered, setIsCurrentTimeHovered] = useState(false);
  const [isDurationHovered, setIsDurationHovered] = useState(false);

  const [volumePercentage, setVolumePercentage] = useState(() => {
    try {
      const savedVolume = localStorage.getItem(VOLUME_STORAGE_KEY);
      return savedVolume ? parseInt(savedVolume, 10) : INITIAL_VOLUME;
    } catch {
      return INITIAL_VOLUME;
    }
  });
  const [previousVolumeBeforeMute, setPreviousVolumeBeforeMute] = useState<
    number | null
  >(null);
  const [isDragging, setIsDragging] = useState(false);
  const [isVolumeDragging, setIsVolumeDragging] = useState(false);
  const [isQueueOpen, setIsQueueOpen] = useState(false);
  const [showPlayer, setShowPlayer] = useState(false);
  const [, setCurrentTime] = useState(0);
  const [duration, setDuration] = useState(0);
  const [previewProgress, setPreviewProgress] = useState(0);
  const waveformRef = useRef<HTMLDivElement | null>(null);
  const audioRef = useRef<HTMLAudioElement | null>(null);
  const rafIdRef = useRef<number | null>(null);
  const pendingSeekPositionRef = useRef<number | null>(null);
  const skipBackRef = useRef<AnimatedIconHandle>(null);
  const skipForwardRef = useRef<AnimatedIconHandle>(null);

  const volumeThumbWidth = isMobileScreen ? 28 : 20;
  const volumeThumbHeight = isMobileScreen ? 40 : 32;
  const volumeSliderHeight = 128;
  const volumeTrackWidth = isMobileScreen ? 10 : 6;
  const VOLUME_SCALE_REST = 0.6;
  const VOLUME_SCALE_DRAG = 1;
  const volumeThumbHeightRest = volumeThumbHeight * VOLUME_SCALE_REST;

  const volumeSliderTrackRef = useRef<HTMLDivElement | null>(null);
  const volumeSliderThumbRef = useRef<HTMLDivElement | null>(null);
  const volumeControlRef = useRef<HTMLDivElement | null>(null);

  const volumePointerDown = useMotionValue(0);
  const volumeThumbY = useMotionValue(0);
  const volumeIsUp = useTransform(
    () => (volumePointerDown.get() > 0.5 ? 1 : 0) as number,
  );

  const volumeBlur = useMotionValue(0.3);
  const volumeSpecularOpacity = useMotionValue(0.6);
  const volumeSpecularSaturation = useMotionValue(12);
  const volumeRefractionBase = useMotionValue(1.1);
  const volumePressMultiplier = useTransform(
    volumeIsUp as any,
    [0, 1],
    [0.4, 0.9],
  );
  const volumeScaleRatio = useSpring(
    useTransform(
      [volumePressMultiplier, volumeRefractionBase],
      ([m, base]) => (Number(m) || 0) * (Number(base) || 0),
    ),
  );

  const volumeScaleSpring = useSpring(
    useTransform(
      volumeIsUp as any,
      [0, 1],
      [VOLUME_SCALE_REST, VOLUME_SCALE_DRAG],
    ),
    {
      damping: 80,
      stiffness: 2000,
    },
  );

  const volumeBackgroundOpacity = useSpring(
    useTransform(volumeIsUp as any, [0, 1], [1, 0.1]),
    {
      damping: 80,
      stiffness: 2000,
    },
  );

  const volumeBackgroundColor = useTransform(
    volumeBackgroundOpacity,
    (op) => `rgba(255, 255, 255, ${op})`,
  );

  const preventSpacebarDefault = useCallback((e: React.KeyboardEvent) => {
    if (e.code === "Space") {
      e.preventDefault();
    }
  }, []);

  const blurOnClick = useCallback((e: React.MouseEvent<HTMLButtonElement>) => {
    e.currentTarget.blur();
  }, []);

  const handlePlayPause = useCallback(() => {
    if (isPlaying) {
      pause();
    } else if (currentTrack) {
      resume();
    } else if (queue.length > 0) {
      playFromQueue();
    }
  }, [isPlaying, pause, resume, currentTrack, queue.length, playFromQueue]);

  const handleTrackTitleClick = useCallback(() => {
    if (!currentTrack?.id) return;

    if (currentTrack.isSharedTrack) {
      navigate({
        to: "/shared-track/$trackId",
        params: { trackId: currentTrack.id },
      });
      return;
    }

    if (currentTrack.projectId) {
      const currentPath = routerState.location.pathname;
      const targetPath = `/project/${currentTrack.projectId}`;

      if (currentPath === targetPath || currentPath === `${targetPath}/`) {
        window.dispatchEvent(
          new CustomEvent("scroll-to-track", {
            detail: { trackId: currentTrack.id },
          }),
        );
      } else {
        sessionStorage.setItem("scrollToTrack", currentTrack.id);

        navigate({
          to: "/project/$projectId",
          params: { projectId: currentTrack.projectId },
        });
      }
    }
  }, [
    currentTrack?.id,
    currentTrack?.projectId,
    currentTrack?.isSharedTrack,
    navigate,
    routerState.location.pathname,
  ]);

  const toggleMute = useCallback(() => {
    if (volumePercentage > 0) {
      setPreviousVolumeBeforeMute(volumePercentage);
      setVolumePercentage(0);
      if (audioRef.current) {
        audioRef.current.volume = 0;
      }
    } else {
      const restoreVolume = previousVolumeBeforeMute ?? 50;
      setVolumePercentage(restoreVolume);
      if (audioRef.current) {
        audioRef.current.volume = restoreVolume / 100;
      }
      setPreviousVolumeBeforeMute(null);
    }
  }, [volumePercentage, previousVolumeBeforeMute]);

  const getVolumeIcon = useCallback(() => {
    if (volumePercentage === 0) {
      return VolumeXIcon;
    } else if (volumePercentage <= 50) {
      return Volume1Icon;
    } else {
      return Volume2Icon;
    }
  }, [volumePercentage]);

  const VolumeIcon = getVolumeIcon();

  useEffect(() => {
    const y0 = -volumeThumbHeightRest / 3;
    const y100 =
      volumeSliderHeight - volumeThumbHeight + volumeThumbHeightRest / 3;
    const targetY = y100 - (volumePercentage / 100) * (y100 - y0);
    volumeThumbY.set(targetY);
  }, []);

  useEffect(() => {
    if (audioRef.current) {
      audioRef.current.volume = volumePercentage / 100;
    }
  }, [volumePercentage]);

  useEffect(() => {
    try {
      localStorage.setItem(VOLUME_STORAGE_KEY, volumePercentage.toString());
    } catch (error) {
      console.error("Failed to save volume to localStorage:", error);
    }
  }, [volumePercentage]);

  useEffect(() => {
    const mediaQuery = window.matchMedia("(max-width: 640px)");

    const handleChange = (e: MediaQueryListEvent | MediaQueryList) => {
      setIsMobileScreen(e.matches);
    };

    handleChange(mediaQuery);
    mediaQuery.addEventListener("change", handleChange);

    return () => {
      mediaQuery.removeEventListener("change", handleChange);
    };
  }, []);

  useEffect(() => {
    if (!isMobileScreen || !isVolumePopupOpen) return;

    const handleClickOutside = (event: MouseEvent) => {
      if (
        volumeControlRef.current &&
        !volumeControlRef.current.contains(event.target as Node)
      ) {
        setIsVolumePopupOpen(false);
      }
    };

    document.addEventListener("mousedown", handleClickOutside);
    return () => {
      document.removeEventListener("mousedown", handleClickOutside);
    };
  }, [isMobileScreen, isVolumePopupOpen]);

  useEffect(() => {
    const hasContent = currentTrack || queue.length > 0;

    if (hasContent && !showPlayer) {
      const timer = setTimeout(() => setShowPlayer(true), 50);
      return () => clearTimeout(timer);
    } else if (!hasContent) {
      setShowPlayer(false);
    }
  }, [currentTrack, queue.length, showPlayer]);

  useEffect(() => {
    if (currentTrack) {
      const artist =
        typeof currentTrack.artist === "string" &&
        currentTrack.artist.trim().length > 0
          ? currentTrack.artist
          : currentTrack.projectName || "Unknown Artist";
      document.title = `${currentTrack.title} - ${artist}`;
    } else if (queue.length > 0) {
      const nextTrack = queue[0];
      const artist =
        typeof nextTrack.artist === "string" &&
        nextTrack.artist.trim().length > 0
          ? nextTrack.artist
          : nextTrack.projectName || "Unknown Artist";
      document.title = `${nextTrack.title} - ${artist}`;
    } else {
      document.title = "{vault}";
    }
  }, [currentTrack, queue]);

  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.code !== "Space" || event.repeat) {
        return;
      }
      const target = event.target as HTMLElement | null;
      if (target) {
        const tagName = target.tagName;
        const isEditable =
          target.getAttribute("contenteditable") === "true" ||
          tagName === "INPUT" ||
          tagName === "TEXTAREA" ||
          tagName === "BUTTON";
        if (isEditable) {
          return;
        }
      }
      event.preventDefault();
      handlePlayPause();
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [handlePlayPause]);

  useEffect(() => {
    const audio = audioRef.current;
    if (!audio) return;

    const handlePlay = () => onPlayingChange(true);
    const handlePause = () => onPlayingChange(false);
    const handleEnded = () => onEnded();
    const handleLoadedMetadata = () => {
      setDuration(audio.duration);
      onDurationChange(audio.duration);
    };

    // Handle timeupdate for iOS Safari compatibility
    const handleTimeUpdate = () => {
      if (!Number.isNaN(audio.currentTime)) {
        const actualTime = audio.currentTime;
        const audioDuration =
          !Number.isNaN(audio.duration) && audio.duration > 0
            ? audio.duration
            : 0;

        const clampedTime = Math.min(actualTime, audioDuration);
        setCurrentTime(clampedTime);

        if (pendingSeekPositionRef.current === null && !isDragging) {
          setPreviewProgress(clampedTime);
        }
      }
    };

    audio.addEventListener("play", handlePlay);
    audio.addEventListener("pause", handlePause);
    audio.addEventListener("ended", handleEnded);
    audio.addEventListener("loadedmetadata", handleLoadedMetadata);
    audio.addEventListener("timeupdate", handleTimeUpdate);

    return () => {
      audio.removeEventListener("play", handlePlay);
      audio.removeEventListener("pause", handlePause);
      audio.removeEventListener("ended", handleEnded);
      audio.removeEventListener("loadedmetadata", handleLoadedMetadata);
      audio.removeEventListener("timeupdate", handleTimeUpdate);
    };
  }, [onPlayingChange, onEnded, onDurationChange, isDragging]);

  useEffect(() => {
    const updateTime = () => {
      if (!audioRef.current) {
        rafIdRef.current = requestAnimationFrame(updateTime);
        return;
      }

      const a = audioRef.current;
      const audioDuration =
        !Number.isNaN(a.duration) && a.duration > 0 ? a.duration : 0;

      if (pendingSeekPositionRef.current !== null) {
        const preview = Math.min(pendingSeekPositionRef.current, audioDuration);
        setPreviewProgress(preview);
      } else if (!isDragging) {
        const actualTime = !Number.isNaN(a.currentTime) ? a.currentTime : 0;
        const clampedTime = Math.min(actualTime, audioDuration);
        setPreviewProgress(clampedTime);
      }

      rafIdRef.current = requestAnimationFrame(updateTime);
    };

    rafIdRef.current = requestAnimationFrame(updateTime);

    return () => {
      if (rafIdRef.current !== null) {
        cancelAnimationFrame(rafIdRef.current);
        rafIdRef.current = null;
      }
    };
  }, [isDragging]);

  useEffect(() => {
    onProgressUpdate(previewProgress);
    // onProgressUpdate is omitted from deps because it's memoized with useCallback and never changes
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [previewProgress]);

  useEffect(() => {
    if (!audioUrl || !audioRef.current) return;

    const audio = audioRef.current;
    const currentSrc = audio.src;
    const newSrc = audioUrl;

    if (currentSrc !== newSrc) {
      const preloadedAudio = getPreloadedAudio();
      if (preloadedAudio && preloadedAudio.src === audioUrl) {
        clearPreloadedAudio();
      }

      audio.src = audioUrl;
      audio.volume = volumePercentage / 100;
      audio.load();

      if (isPlaying) {
        const handleLoadedData = () => {
          audio.play().catch((error) => {
            console.error("Failed to play:", error);
          });
        };

        audio.addEventListener("loadeddata", handleLoadedData, { once: true });

        const handleCanPlay = () => {
          if (audio.paused && audio.readyState >= 2) {
            audio.play().catch((error) => {
              console.error("Failed to play:", error);
            });
          }
        };

        audio.addEventListener("canplay", handleCanPlay, { once: true });

        return () => {
          audio.removeEventListener("loadeddata", handleLoadedData);
          audio.removeEventListener("canplay", handleCanPlay);
        };
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [audioUrl, getPreloadedAudio, clearPreloadedAudio]);

  useEffect(() => {
    if (!audioRef.current) return;

    const audio = audioRef.current;

    if (isPlaying) {
      if (audio.paused && audio.src) {
        audio.play().catch((error) => {
          console.error("Failed to resume:", error);
        });
      }
    } else {
      if (!audio.paused) {
        audio.pause();
      }
    }
  }, [isPlaying]);

  useEffect(() => {
    audioPlayerRef.current = { audio: audioRef };
  });

  const formatTime = (seconds: number) => {
    if (!Number.isFinite(seconds)) return "0:00";
    const mins = Math.floor(seconds / 60);
    const secs = Math.floor(seconds % 60);
    return `${mins}:${secs.toString().padStart(2, "0")}`;
  };

  const progressForBars = duration > 0 ? (previewProgress / duration) * 100 : 0;

  const waveformBars = useMemo(() => {
    if (currentTrack?.waveform) {
      try {
        const waveformData = JSON.parse(currentTrack.waveform);
        if (Array.isArray(waveformData) && waveformData.length > 0) {
          return waveformData;
        }
      } catch (error) {
        console.error("[MusicPlayer] Failed to parse waveform data:", error);
      }
    }

    return Array.from({ length: 200 }).map(() => Math.random() * 60 + 20);
  }, [currentTrack?.id, currentTrack?.waveform, currentTrack?.title]);

  const waveformViewBoxWidth = useMemo(() => {
    if (!waveformBars.length) return 0;
    const contentWidth =
      (waveformBars.length - 1) * WAVEFORM_BAR_GAP + WAVEFORM_BAR_WIDTH;
    const totalOffset = WAVEFORM_BAR_X_OFFSET * 2;
    return contentWidth + totalOffset;
  }, [waveformBars.length]);

  const waveformProgressPosition = useMemo(() => {
    if (waveformViewBoxWidth === 0) return 0;
    return (progressForBars / 100) * waveformViewBoxWidth;
  }, [progressForBars, waveformViewBoxWidth]);

  const performPreviewSeek = useCallback(
    (clientX: number) => {
      if (!waveformRef.current || !duration) return;

      const rect = waveformRef.current.getBoundingClientRect();
      const x = clientX - rect.left;
      const clickPercentage = Math.max(
        0,
        Math.min(100, (x / rect.width) * 100),
      );
      const seekTime = (clickPercentage / 100) * duration;

      pendingSeekPositionRef.current = seekTime;
    },
    [duration],
  );

  const handleWaveformMouseDown = (e: React.MouseEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(true);
    performPreviewSeek(e.clientX);
  };

  const handleWaveformTouchStart = (e: React.TouchEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(true);
    if (e.touches.length > 0) {
      performPreviewSeek(e.touches[0].clientX);
    }
  };

  const handleWaveformKeyDown = (
    event: React.KeyboardEvent<HTMLDivElement>,
  ) => {
    if (!duration) return;
    if (event.key === "ArrowLeft" || event.key === "ArrowRight") {
      event.preventDefault();
      const delta = event.key === "ArrowLeft" ? -5 : 5;
      const newTime = Math.max(0, Math.min(previewProgress + delta, duration));
      if (audioRef.current) {
        audioRef.current.currentTime = newTime;
      }
      pendingSeekPositionRef.current = null;
    }
  };

  const handleSkipSeconds = useCallback(
    (seconds: number) => {
      if (!audioRef.current) return;
      const newTime = Math.max(
        0,
        Math.min(audioRef.current.currentTime + seconds, duration),
      );
      audioRef.current.currentTime = newTime;
    },
    [duration],
  );

  const updateVolumeSeekFromThumbPosition = useCallback(() => {
    if (!volumeSliderTrackRef.current || !volumeSliderThumbRef.current) return;

    const track = volumeSliderTrackRef.current.getBoundingClientRect();
    const thumb = volumeSliderThumbRef.current.getBoundingClientRect();

    const y0 = track.top + volumeThumbHeightRest / 2;
    const y100 = track.bottom - volumeThumbHeightRest / 2;
    const trackInsideHeight = y100 - y0;
    const thumbCenterY = thumb.top + thumb.height / 2;
    const y = Math.max(y0, Math.min(y100, thumbCenterY));
    const ratio = 1 - (y - y0) / trackInsideHeight; // Inverted for volume (top = 100%)

    const volumeValue = Math.max(0, Math.min(100, ratio * 100));
    setVolumePercentage(Math.round(volumeValue));
    if (audioRef.current) {
      audioRef.current.volume = volumeValue / 100;
    }
  }, [volumeThumbHeightRest]);

  const handleVolumeTrackMouseDown = useCallback(
    (e: React.MouseEvent<HTMLDivElement>) => {
      if (!volumeSliderTrackRef.current) return;

      const track = volumeSliderTrackRef.current.getBoundingClientRect();
      const clickY = e.clientY;
      const relativeY = clickY - track.top;
      const ratio = 1 - relativeY / track.height;
      const volumeValue = Math.max(0, Math.min(100, ratio * 100));

      setVolumePercentage(Math.round(volumeValue));
      if (audioRef.current) {
        audioRef.current.volume = volumeValue / 100;
      }

      const y0 = -volumeThumbHeightRest / 3;
      const y100 =
        volumeSliderHeight - volumeThumbHeight + volumeThumbHeightRest / 3;
      const targetY = y100 - (volumeValue / 100) * (y100 - y0);
      volumeThumbY.set(targetY);

      volumePointerDown.set(1);
      setIsVolumeDragging(true);
    },
    [
      volumeThumbHeightRest,
      volumeSliderHeight,
      volumeThumbHeight,
      volumeThumbY,
      volumePointerDown,
    ],
  );

  useEffect(() => {
    if (!isVolumeDragging) {
      const y0 = -volumeThumbHeightRest / 3;
      const y100 =
        volumeSliderHeight - volumeThumbHeight + volumeThumbHeightRest / 3;
      const targetY = y100 - (volumePercentage / 100) * (y100 - y0);
      volumeThumbY.set(targetY);
    }
  }, [
    volumePercentage,
    isVolumeDragging,
    volumeSliderHeight,
    volumeThumbHeight,
    volumeThumbHeightRest,
    volumeThumbY,
  ]);

  useEffect(() => {
    function onPointerUp() {
      volumePointerDown.set(0);
      setIsVolumeDragging(false);
    }
    window.addEventListener("pointerup", onPointerUp);
    window.addEventListener("mouseup", onPointerUp);
    window.addEventListener("touchend", onPointerUp);
    return () => {
      window.removeEventListener("pointerup", onPointerUp);
      window.removeEventListener("mouseup", onPointerUp);
      window.removeEventListener("touchend", onPointerUp);
    };
  }, [volumePointerDown]);

  useEffect(() => {
    if (!isVolumeDragging || !volumeSliderTrackRef.current) return;

    document.body.style.userSelect = "none";

    const handleMouseMove = (e: MouseEvent) => {
      if (!volumeSliderTrackRef.current) return;

      const track = volumeSliderTrackRef.current.getBoundingClientRect();
      const mouseY = e.clientY;
      const relativeY = mouseY - track.top;
      const ratio = 1 - relativeY / track.height;
      const volumeValue = Math.max(0, Math.min(100, ratio * 100));

      setVolumePercentage(Math.round(volumeValue));
      if (audioRef.current) {
        audioRef.current.volume = volumeValue / 100;
      }

      const y0 = -volumeThumbHeightRest / 3;
      const y100 =
        volumeSliderHeight - volumeThumbHeight + volumeThumbHeightRest / 3;
      const targetY = y100 - (volumeValue / 100) * (y100 - y0);
      volumeThumbY.set(targetY);
    };

    window.addEventListener("mousemove", handleMouseMove);

    return () => {
      window.removeEventListener("mousemove", handleMouseMove);
      document.body.style.userSelect = "";
    };
  }, [
    isVolumeDragging,
    volumeThumbHeightRest,
    volumeSliderHeight,
    volumeThumbHeight,
    volumeThumbY,
  ]);

  useEffect(() => {
    if (!isDragging) return;

    document.body.style.userSelect = "none";

    const handleMouseMove = (e: MouseEvent) => {
      e.preventDefault();
      performPreviewSeek(e.clientX);
    };

    const handleTouchMove = (e: TouchEvent) => {
      e.preventDefault();
      if (e.touches.length > 0) {
        performPreviewSeek(e.touches[0].clientX);
      }
    };

    const handleMouseUp = (e: MouseEvent) => {
      setIsDragging(false);
      document.body.style.userSelect = "";

      performPreviewSeek(e.clientX);

      if (waveformRef.current && duration && audioRef.current) {
        const rect = waveformRef.current.getBoundingClientRect();
        const x = e.clientX - rect.left;
        const clickPercentage = Math.max(
          0,
          Math.min(100, (x / rect.width) * 100),
        );
        const seekTime = (clickPercentage / 100) * duration;
        audioRef.current.currentTime = seekTime;
        pendingSeekPositionRef.current = null;
      }
    };

    const handleTouchEnd = (e: TouchEvent) => {
      setIsDragging(false);
      document.body.style.userSelect = "";

      if (e.changedTouches.length > 0) {
        const touch = e.changedTouches[0];
        performPreviewSeek(touch.clientX);

        if (waveformRef.current && duration && audioRef.current) {
          const rect = waveformRef.current.getBoundingClientRect();
          const x = touch.clientX - rect.left;
          const clickPercentage = Math.max(
            0,
            Math.min(100, (x / rect.width) * 100),
          );
          const seekTime = (clickPercentage / 100) * duration;
          audioRef.current.currentTime = seekTime;
          pendingSeekPositionRef.current = null;
        }
      }
    };

    document.addEventListener("mousemove", handleMouseMove);
    document.addEventListener("mouseup", handleMouseUp);
    document.addEventListener("touchmove", handleTouchMove, { passive: false });
    document.addEventListener("touchend", handleTouchEnd);

    return () => {
      document.removeEventListener("mousemove", handleMouseMove);
      document.removeEventListener("mouseup", handleMouseUp);
      document.removeEventListener("touchmove", handleTouchMove);
      document.removeEventListener("touchend", handleTouchEnd);
      document.body.style.userSelect = "";
    };
  }, [isDragging, duration, performPreviewSeek]);

  const fallbackTrack =
    currentTrack ?? (queue.length > 0 ? queue[0] : undefined);
  const playerTitle = fallbackTrack?.title || "No track selected";
  const playerArtist =
    fallbackTrack && typeof fallbackTrack.artist === "string"
      ? fallbackTrack.artist.trim().length > 0
        ? fallbackTrack.artist
        : fallbackTrack.projectName || "Unknown Artist"
      : fallbackTrack?.projectName || "Unknown Artist";

  if (!currentTrack && queue.length === 0) {
    return null;
  }

  return (
    <>
      <audio
        ref={audioRef}
        // Use the native loop behaviour; custom loop attempts caused stutter
        // and play() interruption errors on some platforms.
        loop={loopMode === "track"}
        preload="auto"
        crossOrigin="anonymous"
      />

      {!hideControls && (
        <div
          className={`fixed bottom-3 sm:bottom-6 left-1/2 -translate-x-1/2 z-110 w-[calc(100%-1rem)] sm:w-[calc(100%-3rem)] max-w-[800px] transition-opacity duration-300 ${
            showPlayer ? "opacity-100" : "opacity-0"
          }`}
        >
          <div className="relative h-[50px] sm:h-[50px] border border-[#353333] rounded-t-[22px] overflow-hidden bg-neutral-900 shadow-md">
            <div className="absolute inset-0 px-3 py-1 select-none">
              <div
                ref={waveformRef}
                className="relative h-full"
                style={{ cursor: isDragging ? "grabbing" : "grab" }}
                onMouseDown={handleWaveformMouseDown}
                onTouchStart={handleWaveformTouchStart}
                role="slider"
                tabIndex={0}
                aria-label="Seek"
                aria-valuemin={0}
                aria-valuemax={Math.floor(duration)}
                aria-valuenow={Math.floor(previewProgress)}
                onKeyDown={handleWaveformKeyDown}
              >
                <svg
                  width="100%"
                  height="100%"
                  viewBox={`0 0 ${waveformViewBoxWidth} ${WAVEFORM_VIEWBOX_HEIGHT}`}
                  preserveAspectRatio="none"
                  className="text-white"
                  shapeRendering="geometricPrecision"
                >
                  {waveformBars.map((height, i) => {
                    const normalizedHeight = Math.max(
                      0,
                      Math.min(100, Number(height)),
                    );
                    const scaledHeight = Math.max(
                      12,
                      (normalizedHeight / 100) * WAVEFORM_VIEWBOX_HEIGHT,
                    );
                    const topOffset =
                      (WAVEFORM_VIEWBOX_HEIGHT - scaledHeight) / 2;
                    const barX = WAVEFORM_BAR_X_OFFSET + i * WAVEFORM_BAR_GAP;
                    const isPassed = waveformProgressPosition >= barX;
                    const delay = (i / waveformBars.length) * 600;
                    return (
                      <rect
                        key={barX}
                        x={WAVEFORM_BAR_X_OFFSET + i * WAVEFORM_BAR_GAP}
                        y={topOffset}
                        width={WAVEFORM_BAR_WIDTH}
                        height={scaledHeight}
                        rx={WAVEFORM_BAR_RADIUS}
                        fill={isPassed ? "#FFFFFF" : "#3F3F46"}
                        style={{
                          transition: `y 400ms cubic-bezier(0.4, 0, 0.2, 1) ${delay}ms, height 400ms cubic-bezier(0.4, 0, 0.2, 1) ${delay}ms`,
                          willChange: "y, height",
                        }}
                      />
                    );
                  })}
                </svg>
                <div
                  className="absolute top-0 bottom-0 rounded-full pointer-events-none -translate-x-1/2"
                  style={{
                    left: `${progressForBars}%`,
                  }}
                >
                  <div className="hidden sm:block absolute inset-0 w-1 -left-0.5 bg-amber-400/40 blur-sm" />
                  <div className="absolute inset-0 w-0.5 bg-amber-400 rounded-full" />
                </div>
              </div>
            </div>
          </div>

          <div
            className="relative h-[50px] sm:h-[55px] grid grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)] items-center gap-2 sm:gap-4 border border-[#353333] border-t-0 rounded-b-[22px] shadow-md"
            style={{
              background: "linear-gradient(0deg, #1D1D1D 0%, #282828 100%)",
            }}
          >
            <div className="flex items-center gap-2 sm:gap-3 min-w-0 z-10 ml-1.5 sm:ml-2">
              <div className="size-9 sm:size-10 bg-[#333333] border border-[rgba(53,51,51,0.2)] rounded-tl-[9px] rounded-tr-[9px] rounded-br-[9px] rounded-bl-[13px] shrink-0 overflow-hidden">
                {currentTrack && coverUrl && (
                  <img
                    src={coverUrl}
                    alt={currentTrack.title}
                    className="w-full h-full object-cover"
                    decoding="async"
                  />
                )}
                {!currentTrack && queue.length > 0 && queue[0].coverUrl && (
                  <img
                    src={queue[0].coverUrl}
                    alt={queue[0].title}
                    className="w-full h-full object-cover"
                    decoding="async"
                  />
                )}
              </div>

              <div
                className="min-w-0 w-full cursor-pointer"
                onClick={currentTrack ? handleTrackTitleClick : undefined}
              >
                <ScrollingText
                  text={playerTitle}
                  className="text-white font-medium text-sm sm:text-base leading-tight hover:opacity-80 transition-opacity"
                  gradientColor="#1D1D1D"
                />
                <ScrollingText
                  text={playerArtist}
                  className="text-[#858585] text-xs sm:text-sm leading-tight hover:opacity-80 transition-opacity"
                  gradientColor="#1D1D1D"
                />
              </div>
            </div>

            <div className="flex items-center gap-4 sm:gap-6 justify-self-center z-20">
              <div
                className="hidden sm:flex items-center relative w-10"
                onMouseEnter={() => setIsCurrentTimeHovered(true)}
                onMouseLeave={() => setIsCurrentTimeHovered(false)}
              >
                <span
                  className={`text-white text-[12px] absolute transition-all duration-200 select-none ${
                    isCurrentTimeHovered
                      ? "opacity-0 pointer-events-none"
                      : "opacity-100"
                  }`}
                  style={{
                    fontFamily: '"IBM Plex Mono", monospace',
                    fontWeight: 300,
                  }}
                >
                  {formatTime(previewProgress)}
                </span>
                <button
                  type="button"
                  onClick={(e) => {
                    handleSkipSeconds(-10);
                    blurOnClick(e);
                  }}
                  onKeyDown={preventSpacebarDefault}
                  className={`text-white hover:text-gray-300 transition-all duration-200 cursor-pointer text-[12px] ${
                    isCurrentTimeHovered
                      ? "opacity-100"
                      : "opacity-0 pointer-events-none"
                  }`}
                  style={{
                    fontFamily: '"IBM Plex Mono", monospace',
                    fontWeight: 300,
                  }}
                  aria-label="Skip backward 10 seconds"
                >
                  -10s
                </button>
              </div>

              <button
                type="button"
                className="text-white hover:text-gray-300 transition-colors cursor-pointer"
                aria-label="Previous track"
                onClick={(e) => {
                  previousTrack();
                  blurOnClick(e);
                  skipBackRef.current?.play();
                }}
                onKeyDown={preventSpacebarDefault}
              >
                <AnimatedSkipBackIcon
                  ref={skipBackRef}
                  className="size-6 sm:size-5 text-white"
                />
              </button>

              <button
                type="button"
                onClick={(e) => {
                  handlePlayPause();
                  blurOnClick(e);
                }}
                className="text-white hover:text-gray-300 transition-colors cursor-pointer"
                aria-label={isPlaying ? "Pause" : "Play"}
                onKeyDown={preventSpacebarDefault}
              >
                {isPlaying ? (
                  <PauseIcon className="size-5.5 sm:size-5 fill-current" />
                ) : (
                  <PlayIcon className="size-5.5 sm:size-5 fill-current" />
                )}
              </button>

              <button
                type="button"
                className="text-white hover:text-gray-300 transition-colors cursor-pointer"
                aria-label="Next track"
                onClick={(e) => {
                  nextTrack();
                  blurOnClick(e);
                  skipForwardRef.current?.play();
                }}
                onKeyDown={preventSpacebarDefault}
              >
                <AnimatedSkipForwardIcon
                  ref={skipForwardRef}
                  className="size-6 sm:size-5 text-white"
                />
              </button>

              <div
                className="hidden sm:flex items-center relative w-10"
                onMouseEnter={() => setIsDurationHovered(true)}
                onMouseLeave={() => setIsDurationHovered(false)}
              >
                <span
                  className={`text-white text-[12px] absolute transition-all duration-200 select-none ${
                    isDurationHovered
                      ? "opacity-0 pointer-events-none"
                      : "opacity-100"
                  }`}
                  style={{
                    fontFamily: '"IBM Plex Mono", monospace',
                    fontWeight: 300,
                  }}
                >
                  {formatTime(duration)}
                </span>
                <button
                  type="button"
                  onClick={(e) => {
                    handleSkipSeconds(10);
                    blurOnClick(e);
                  }}
                  onKeyDown={preventSpacebarDefault}
                  className={`text-white hover:text-gray-300 transition-all duration-200 cursor-pointer text-[12px] ${
                    isDurationHovered
                      ? "opacity-100"
                      : "opacity-0 pointer-events-none"
                  }`}
                  style={{
                    fontFamily: '"IBM Plex Mono", monospace',
                    fontWeight: 300,
                  }}
                  aria-label="Skip forward 10 seconds"
                >
                  +10s
                </button>
              </div>
            </div>

            <div className="flex items-center gap-5 sm:gap-6 justify-self-end z-10 pr-3 sm:pr-4">
              <button
                type="button"
                className={`transition-colors ${loopMode !== "off" ? "text-amber-400" : "text-white hover:text-gray-300"}`}
                aria-label={
                  loopMode === "off"
                    ? "Loop off"
                    : loopMode === "track"
                      ? "Loop track"
                      : "Loop project"
                }
                aria-pressed={loopMode !== "off"}
                onClick={(e) => {
                  toggleLoop();
                  blurOnClick(e);
                }}
                onKeyDown={preventSpacebarDefault}
              >
                {loopMode === "track" ? (
                  <Repeat1Icon className="size-5.5 sm:size-5" />
                ) : (
                  <RepeatIcon className="size-5.5 sm:size-5" />
                )}
              </button>

              <button
                type="button"
                className={`transition-colors ${isShuffled ? "text-amber-400" : "text-white hover:text-gray-300"}`}
                aria-label="Shuffle"
                aria-pressed={isShuffled}
                onClick={(e) => {
                  toggleShuffle();
                  blurOnClick(e);
                }}
                onKeyDown={preventSpacebarDefault}
              >
                <ShuffleIcon className="size-5.5 sm:size-5" />
              </button>

              <button
                type="button"
                className={`order-2 sm:order-none transition-colors relative ${isQueueOpen ? "text-amber-400" : "text-white hover:text-gray-300"}`}
                aria-label="Queue"
                onClick={(e) => {
                  setIsQueueOpen(!isQueueOpen);
                  blurOnClick(e);
                }}
                onKeyDown={preventSpacebarDefault}
              >
                <ListIcon className="size-5.5 sm:size-5" />
                {SHOW_QUEUE_BADGE && queue.length > 0 && (
                  <span className="absolute -top-1 -right-1 bg-amber-400 text-black text-[9px] font-bold rounded-full w-4 h-4 flex items-center justify-center">
                    {queue.length}
                  </span>
                )}
              </button>

              <div
                ref={volumeControlRef}
                className="hidden sm:flex order-1 sm:order-none relative items-center"
                onPointerEnter={() =>
                  !isMobileScreen && setIsVolumeHovered(true)
                }
                onPointerLeave={() =>
                  !isMobileScreen && setIsVolumeHovered(false)
                }
              >
                <div
                  className={`absolute -bottom-[13px] left-1/2 -translate-x-1/2 transition-opacity duration-200 ${
                    isVolumeHovered || isVolumeDragging || isVolumePopupOpen
                      ? "opacity-100"
                      : "opacity-0 pointer-events-none"
                  }`}
                >
                  <div className="bg-[#282828] border border-[#353333] rounded-[18px] px-3 py-3 shadow-lg flex flex-col items-center gap-2">
                    <Filter
                      id="volume-filter"
                      blur={volumeBlur}
                      scaleRatio={volumeScaleRatio}
                      specularOpacity={volumeSpecularOpacity}
                      specularSaturation={volumeSpecularSaturation}
                    />

                    <motion.div
                      style={{
                        position: "relative",
                        width: volumeThumbWidth,
                        height: volumeSliderHeight,
                      }}
                      onMouseDown={handleVolumeTrackMouseDown}
                    >
                      <motion.div
                        ref={volumeSliderTrackRef}
                        style={{
                          display: "inline-block",
                          width: volumeTrackWidth,
                          height: "100%",
                          left: (volumeThumbWidth - volumeTrackWidth) / 2,
                          top: 0,
                          backgroundColor: "#89898F66",
                          borderRadius: volumeTrackWidth / 2,
                          position: "absolute",
                          cursor: "pointer",
                          pointerEvents: "none",
                        }}
                      >
                        <div className="w-full h-full overflow-hidden rounded-full">
                          <motion.div
                            style={{
                              bottom: 0,
                              left: 0,
                              width: volumeTrackWidth,
                              height: `${volumePercentage}%`,
                              borderRadius: volumeTrackWidth / 2,
                              backgroundColor: "#FFBA00",
                              position: "absolute",
                            }}
                          />
                        </div>
                      </motion.div>

                      <motion.div
                        ref={volumeSliderThumbRef}
                        drag="y"
                        dragConstraints={{
                          top: -volumeThumbHeightRest / 3,
                          bottom:
                            volumeSliderHeight -
                            volumeThumbHeight +
                            volumeThumbHeightRest / 3,
                        }}
                        dragElastic={0.02}
                        onMouseDown={(e) => {
                          e.stopPropagation();
                          volumePointerDown.set(1);
                        }}
                        onMouseUp={() => {
                          volumePointerDown.set(0);
                        }}
                        onDragStart={() => {
                          volumePointerDown.set(1);
                          setIsVolumeDragging(true);
                        }}
                        onDrag={() => {
                          updateVolumeSeekFromThumbPosition();
                        }}
                        onDragEnd={() => {
                          volumePointerDown.set(0);
                          setIsVolumeDragging(false);
                        }}
                        dragMomentum={false}
                        className="absolute"
                        style={{
                          height: volumeThumbHeight,
                          width: volumeThumbWidth,
                          left: 0,
                          y: volumeThumbY,
                          borderRadius: 16,
                          backdropFilter: "url(#volume-filter)",
                          scale: volumeScaleSpring,
                          cursor: "pointer",
                          backgroundColor: volumeBackgroundColor,
                          boxShadow: "0 3px 14px rgba(0,0,0,0.1)",
                        }}
                      />
                    </motion.div>
                    <button
                      type="button"
                      onClick={(e) => {
                        if (isMobileScreen) {
                          setIsVolumePopupOpen(false);
                        } else {
                          toggleMute();
                        }
                        blurOnClick(e);
                      }}
                      onKeyDown={preventSpacebarDefault}
                      className="text-white hover:text-gray-300 transition-colors cursor-pointer"
                      aria-label={
                        isMobileScreen
                          ? "Close volume control"
                          : volumePercentage === 0
                            ? "Unmute"
                            : "Mute"
                      }
                    >
                      <VolumeIcon className="size-5.5 sm:size-5" />
                    </button>
                  </div>
                </div>

                <button
                  type="button"
                  className="text-white hover:text-gray-300 transition-colors"
                  aria-label={
                    isMobileScreen
                      ? "Volume control"
                      : volumePercentage === 0
                        ? "Unmute"
                        : "Mute"
                  }
                  onClick={(e) => {
                    if (isMobileScreen) {
                      setIsVolumePopupOpen(!isVolumePopupOpen);
                    } else {
                      toggleMute();
                    }
                    blurOnClick(e);
                  }}
                  onKeyDown={preventSpacebarDefault}
                >
                  <VolumeIcon className="size-5.5 sm:size-5" />
                </button>
              </div>
            </div>
          </div>

          <QueuePanel
            isOpen={isQueueOpen}
            onClose={() => setIsQueueOpen(false)}
          />
        </div>
      )}
    </>
  );
}
