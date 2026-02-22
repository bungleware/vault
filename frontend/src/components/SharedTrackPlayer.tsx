import React, {
  useState,
  useRef,
  useEffect,
  useMemo,
  useCallback,
} from "react";
import {
  PlayIcon,
  PauseIcon,
  SkipBackIcon,
  Volume2Icon,
  Volume1Icon,
  VolumeXIcon,
  DownloadIcon,
  MusicIcon,
  Repeat1Icon,
} from "lucide-react";
import { useMotionValue, useSpring, useTransform, motion } from "motion/react";
import { Filter } from "virtual:refractionFilter?width=20&height=32&radius=10&bezelWidth=12&glassThickness=50&refractiveIndex=1.48&bezelType=convex_squircle";

interface SharedTrackPlayerProps {
  track: any;
  project?: any;
  token?: string;
  allowDownloads?: boolean;
  allowEditing?: boolean;
  streamUrl?: string;
  downloadUrl?: string;
}

export default function SharedTrackPlayer({
  track,
  project,
  token,
  allowDownloads = false,
  allowEditing = false,
  streamUrl: customStreamUrl,
  downloadUrl: customDownloadUrl,
}: SharedTrackPlayerProps) {
  const INITIAL_VOLUME = 100;
  const VOLUME_STORAGE_KEY = "vault-volume";

  const [isPlaying, setIsPlaying] = useState(false);
  const [duration, setDuration] = useState(0);
  const [loopMode, setLoopMode] = useState<"off" | "track">("off");
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
  const [isVolumeHovered, setIsVolumeHovered] = useState(false);
  const [isVolumeDragging, setIsVolumeDragging] = useState(false);
  const [previewProgress, setPreviewProgress] = useState(0);
  const [trackTitle, setTrackTitle] = useState(track.title);
  const titleInputRef = useRef<HTMLInputElement>(null);

  const audioRef = useRef<HTMLAudioElement>(null);
  const waveformRef = useRef<HTMLDivElement>(null);
  const volumeSliderTrackRef = useRef<HTMLDivElement>(null);
  const volumeSliderThumbRef = useRef<HTMLDivElement>(null);
  const rafIdRef = useRef<number | null>(null);
  const pendingSeekPositionRef = useRef<number | null>(null);

  const WAVEFORM_BAR_WIDTH = 0.8;
  const WAVEFORM_BAR_RADIUS = 2;
  const WAVEFORM_BAR_GAP = 2;
  const WAVEFORM_BAR_X_OFFSET = 0.1;
  const WAVEFORM_VIEWBOX_HEIGHT = 120;

  const volumeThumbWidth = 20;
  const volumeThumbHeight = 32;
  const volumeSliderHeight = 128;
  const VOLUME_SCALE_REST = 0.6;
  const VOLUME_SCALE_DRAG = 1;
  const volumeThumbHeightRest = volumeThumbHeight * VOLUME_SCALE_REST;

  const volumePointerDown = useMotionValue(0);
  const volumeThumbY = useMotionValue(0);
  const volumeIsUp = useTransform(() =>
    volumePointerDown.get() > 0.5 ? 1 : 0,
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
    { damping: 80, stiffness: 2000 },
  );

  const volumeBackgroundOpacity = useSpring(
    useTransform(volumeIsUp as any, [0, 1], [1, 0.1]),
    { damping: 80, stiffness: 2000 },
  );

  const volumeBackgroundColor = useTransform(
    volumeBackgroundOpacity,
    (op) => `rgba(255, 255, 255, ${op})`,
  );

  useEffect(() => {
    const y0 = -volumeThumbHeightRest / 3;
    const y100 =
      volumeSliderHeight - volumeThumbHeight + volumeThumbHeightRest / 3;
    const targetY = y100 - (volumePercentage / 100) * (y100 - y0);
    volumeThumbY.set(targetY);
  }, []);

  const handleSaveTitle = async () => {
    if (!allowEditing || trackTitle === track.title) return;

    try {
      const response = await fetch(
        `/api/share/${token}/track/${track.public_id}/update`,
        {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ title: trackTitle }),
        },
      );

      if (!response.ok) throw new Error("Failed to update title");
    } catch (error) {
      console.error("Failed to update track title:", error);
      setTrackTitle(track.title);
    }
  };

  useEffect(() => {
    const handleRename = () => {
      if (titleInputRef.current && allowEditing) {
        titleInputRef.current.focus();
        const length = titleInputRef.current.value.length;
        titleInputRef.current.setSelectionRange(length, length);
      }
    };

    window.addEventListener("share-track-rename", handleRename);
    return () => window.removeEventListener("share-track-rename", handleRename);
  }, [allowEditing]);

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

  const streamUrl = customStreamUrl
    ? customStreamUrl
    : token
      ? `/api/share/${token}/stream`
      : "";

  const togglePlay = () => {
    if (audioRef.current) {
      if (isPlaying) {
        audioRef.current.pause();
      } else {
        audioRef.current.play();
      }
      setIsPlaying(!isPlaying);
    }
  };

  const handleLoadedMetadata = () => {
    if (audioRef.current) {
      setDuration(audioRef.current.duration);
    }
  };

  const formatTime = (seconds: number) => {
    if (!Number.isFinite(seconds)) return "0:00";
    const mins = Math.floor(seconds / 60);
    const secs = Math.floor(seconds % 60);
    return `${mins}:${secs.toString().padStart(2, "0")}`;
  };

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
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.code === "Space") {
        e.preventDefault();
        togglePlay();
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isPlaying]);

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

  useEffect(() => {
    try {
      localStorage.setItem(VOLUME_STORAGE_KEY, volumePercentage.toString());
    } catch (error) {
      console.error("Failed to save volume to localStorage:", error);
    }
  }, [volumePercentage, VOLUME_STORAGE_KEY]);

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

  const toggleLoop = useCallback(() => {
    setLoopMode((prev) => (prev === "off" ? "track" : "off"));
  }, []);

  const handleSkipBack = useCallback(() => {
    if (audioRef.current) {
      audioRef.current.currentTime = 0;
    }
  }, []);

  const handleDownload = () => {
    if (!allowDownloads) return;
    const downloadUrl =
      customDownloadUrl || (token ? `/api/share/${token}/download` : "");
    const a = document.createElement("a");
    a.href = downloadUrl;
    a.download = `${track.title}.mp3`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  };

  const waveformBars = useMemo(() => {
    if (track.waveform) {
      try {
        const data = JSON.parse(track.waveform);
        if (Array.isArray(data)) return data;
      } catch (e) {
        console.error("Failed to parse waveform", e);
      }
    }
    return Array.from({ length: 150 }).map(() => Math.random() * 60 + 20);
  }, [track.waveform]);

  const waveformViewBoxWidth = useMemo(() => {
    if (!waveformBars.length) return 0;
    const contentWidth =
      (waveformBars.length - 1) * WAVEFORM_BAR_GAP + WAVEFORM_BAR_WIDTH;
    const totalOffset = WAVEFORM_BAR_X_OFFSET * 2;
    return contentWidth + totalOffset;
  }, [waveformBars.length]);

  const progressForBars = duration > 0 ? (previewProgress / duration) * 100 : 0;
  const waveformProgressPosition =
    (progressForBars / 100) * waveformViewBoxWidth;

  const updateVolumeSeekFromThumbPosition = useCallback(() => {
    if (!volumeSliderTrackRef.current || !volumeSliderThumbRef.current) return;

    const track = volumeSliderTrackRef.current.getBoundingClientRect();
    const thumb = volumeSliderThumbRef.current.getBoundingClientRect();

    const y0 = track.top + volumeThumbHeightRest / 2;
    const y100 = track.bottom - volumeThumbHeightRest / 2;
    const trackInsideHeight = y100 - y0;
    const thumbCenterY = thumb.top + thumb.height / 2;
    const y = Math.max(y0, Math.min(y100, thumbCenterY));
    const ratio = 1 - (y - y0) / trackInsideHeight;

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
    window.addEventListener("mouseup", () => {
      volumePointerDown.set(0);
      setIsVolumeDragging(false);
    });

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

  let coverUrl =
    track.coverUrl ||
    track.cover_url ||
    project?.cover_url ||
    track.project?.cover_url ||
    null;
  if (coverUrl) {
    // Add size parameter for optimized image
    if (!coverUrl.includes("size=")) {
      coverUrl = `${coverUrl}${coverUrl.includes("?") ? "&" : "?"}size=medium`;
    }
    // Add auth token if needed
  }

  useEffect(() => {
    if ("mediaSession" in navigator) {
      navigator.mediaSession.metadata = new MediaMetadata({
        title: track.title,
        artist: track.artist?.Valid
          ? track.artist.String
          : track.artist || "Unknown Artist",
        artwork: coverUrl
          ? [{ src: coverUrl, sizes: "512x512", type: "image/png" }]
          : undefined,
      });

      navigator.mediaSession.setActionHandler("play", () => {
        if (audioRef.current) {
          audioRef.current.play();
          setIsPlaying(true);
        }
      });

      navigator.mediaSession.setActionHandler("pause", () => {
        if (audioRef.current) {
          audioRef.current.pause();
          setIsPlaying(false);
        }
      });

      navigator.mediaSession.setActionHandler("seekto", (details) => {
        if (audioRef.current && details.seekTime !== undefined) {
          audioRef.current.currentTime = details.seekTime;
          setPreviewProgress(details.seekTime);
        }
      });

      navigator.mediaSession.setActionHandler("previoustrack", () => {
        handleSkipBack();
      });

      return () => {
        navigator.mediaSession.metadata = null;
        navigator.mediaSession.setActionHandler("play", null);
        navigator.mediaSession.setActionHandler("pause", null);
        navigator.mediaSession.setActionHandler("seekto", null);
        navigator.mediaSession.setActionHandler("previoustrack", null);
      };
    }
  }, [track.title, track.artist, coverUrl, handleSkipBack]);

  return (
    <div className="w-full max-w-5xl h-auto sm:h-[200px] bg-[#121212] rounded-[32px] rounded-b-[20px] sm:rounded-b-[32px] overflow-hidden border border-[#292828] flex flex-col sm:flex-row shadow-2xl relative group">
      <audio
        ref={audioRef}
        src={streamUrl}
        loop={loopMode === "track"}
        onLoadedMetadata={handleLoadedMetadata}
        onEnded={() => setIsPlaying(false)}
      />

      <div className="w-full sm:w-[200px] aspect-square sm:aspect-auto sm:h-full relative shrink-0 bg-[#1D1D1D] border-b sm:border-b-0 sm:border-r border-[#292828] pointer-events-none select-none ">
        {coverUrl ? (
          <img
            src={coverUrl}
            alt={track.title}
            className="w-full h-full object-cover"
          />
        ) : (
          <div className="w-full h-full flex flex-col items-center justify-center bg-linear-to-br from-[#1D1D1D] to-[#151515]">
            <div className="size-24 sm:size-32 rounded-2xl bg-white/5 flex items-center justify-center">
              <span className="text-3xl sm:text-4xl">
                <MusicIcon color="white"></MusicIcon>
              </span>
            </div>
          </div>
        )}
      </div>

      <div className="flex-1 flex flex-col bg-[#121212] relative min-h-0">
        <div className="flex-1 relative bg-neutral-900 overflow-hidden min-h-[80px] sm:min-h-0">
          <div className="absolute inset-0 cursor-pointer p-4">
            <div
              ref={waveformRef}
              className="relative w-full h-full"
              onMouseDown={handleWaveformMouseDown}
              onTouchStart={handleWaveformTouchStart}
            >
              <svg
                width="100%"
                height="100%"
                viewBox={`0 0 ${waveformViewBoxWidth} ${WAVEFORM_VIEWBOX_HEIGHT}`}
                preserveAspectRatio="none"
                className="text-white h-full w-full"
                shapeRendering="geometricPrecision"
              >
                {waveformBars.map((height: number, i: number) => {
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
                      x={barX}
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
                className="absolute top-0 bottom-0 pointer-events-none"
                style={{
                  left: `${progressForBars}%`,
                  transform: "translateX(-50%)",
                }}
              >
                <div className="h-full w-0.5 bg-amber-400 shadow-[0_0_10px_rgba(251,191,36,0.5)]" />
              </div>
            </div>
          </div>
        </div>

        <div className="h-[57px] sm:h-[80px] bg-linear-to-t from-[#1D1D1D] to-[#282828] border-t border-[#353333] px-4 sm:px-8 sm:py-0 flex flex-row items-center justify-between relative z-10">
          <div className="flex flex-col min-w-0 mr-2 sm:mr-auto sm:pr-8 max-w-[25%] sm:max-w-[30%]">
            {allowEditing ? (
              <input
                ref={titleInputRef}
                type="text"
                value={trackTitle}
                onChange={(e) => setTrackTitle(e.target.value)}
                onBlur={() => {
                  handleSaveTitle();
                }}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.currentTarget.blur();
                  }
                }}
                className="text-white font-medium text-base md:text-lg leading-tight bg-transparent border-none outline-none focus:outline-none text-left w-full"
              />
            ) : (
              <h1
                className="text-white font-medium text-base md:text-lg leading-tight line-clamp-1"
                title={track.title}
              >
                {track.title}
              </h1>
            )}
            <p className="text-[#858585] text-sm md:text-base line-clamp-1">
              {track.artist?.Valid
                ? track.artist.String
                : track.artist || "Unknown Artist"}
            </p>
          </div>

          <div className="absolute left-1/2 -translate-x-1/2 flex items-center gap-3 sm:gap-4">
            <span
              className="text-xs sm:text-sm text-white"
              style={{
                fontFamily: '"IBM Plex Mono", monospace',
                fontWeight: 300,
              }}
            >
              {formatTime(previewProgress)}
            </span>

            <button
              onClick={handleSkipBack}
              onMouseDown={(e) => e.currentTarget.blur()}
              tabIndex={-1}
              className="text-white hover:text-gray-300 transition-colors outline-none focus:outline-none"
              aria-label="Restart track"
            >
              <SkipBackIcon className="size-5 fill-current" />
            </button>

            <button
              onClick={togglePlay}
              onMouseDown={(e) => e.currentTarget.blur()}
              tabIndex={-1}
              className="text-white hover:text-gray-300 transition-colors outline-none focus:outline-none"
            >
              {isPlaying ? (
                <PauseIcon className="size-5 fill-current" />
              ) : (
                <PlayIcon className="size-5 fill-current" />
              )}
            </button>

            <span
              className="text-xs sm:text-sm text-white"
              style={{
                fontFamily: '"IBM Plex Mono", monospace',
                fontWeight: 300,
              }}
            >
              {formatTime(duration)}
            </span>
          </div>

          <div className="flex items-center gap-4 sm:gap-4 ml-auto">
            {allowDownloads && (
              <button
                onClick={handleDownload}
                onMouseDown={(e) => e.currentTarget.blur()}
                tabIndex={-1}
                className="text-white hover:text-gray-300 transition-colors outline-none focus:outline-none"
              >
                <DownloadIcon className="size-5" />
              </button>
            )}

            <button
              type="button"
              onClick={toggleLoop}
              onMouseDown={(e) => e.currentTarget.blur()}
              tabIndex={-1}
              className={`transition-colors ${
                loopMode !== "off"
                  ? "text-amber-400"
                  : "text-white hover:text-gray-300"
              }`}
              aria-label="Loop track"
              aria-pressed={loopMode !== "off"}
            >
              <Repeat1Icon className="size-5" />
            </button>

            <div
              className="relative flex items-center"
              onMouseEnter={() => setIsVolumeHovered(true)}
              onMouseLeave={() => setIsVolumeHovered(false)}
            >
              <div
                className={`absolute -bottom-[53px] left-1/2 -translate-x-1/2 transition-opacity duration-200 ${
                  isVolumeHovered || isVolumeDragging
                    ? "opacity-100"
                    : "opacity-0 pointer-events-none"
                }`}
              >
                <div className="bg-[#282828] border border-[#353333] rounded-2xl px-3 py-3 shadow-lg flex flex-col items-center gap-2 mb-10">
                  <Filter
                    id="volume-filter-shared"
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
                        width: 6,
                        height: "100%",
                        left: (volumeThumbWidth - 6) / 2,
                        top: 0,
                        backgroundColor: "#89898F66",
                        borderRadius: 3,
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
                            width: 6,
                            height: `${volumePercentage}%`,
                            borderRadius: 3,
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
                        backdropFilter: "url(#volume-filter-shared)",
                        scale: volumeScaleSpring,
                        cursor: "pointer",
                        backgroundColor: volumeBackgroundColor,
                        boxShadow: "0 3px 14px rgba(0,0,0,0.1)",
                      }}
                    />
                  </motion.div>
                  <button
                    type="button"
                    onClick={toggleMute}
                    onMouseDown={(e) => e.currentTarget.blur()}
                    tabIndex={-1}
                    className="text-white hover:text-gray-300 transition-colors cursor-pointer outline-none focus:outline-none"
                    aria-label={volumePercentage === 0 ? "Unmute" : "Mute"}
                  >
                    <VolumeIcon className="size-5 text-white" />
                  </button>
                </div>
              </div>
              <button
                className="text-white hover:text-gray-300 transition-colors outline-none focus:outline-none"
                onMouseDown={(e) => e.currentTarget.blur()}
                tabIndex={-1}
              >
                <VolumeIcon className="size-5" />
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
