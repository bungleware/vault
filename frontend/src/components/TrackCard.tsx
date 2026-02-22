"use client";

import {
  Play,
  Pause,
  Users,
  MoreHorizontal,
  ListPlus,
  FolderInput,
  Download,
  LogOut,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useState, useRef, useEffect } from "react";
import { ColorExtractor } from "react-color-extractor";
import { motion, useMotionValue, useSpring, useTransform } from "motion/react";
import { Filter } from "virtual:refractionFilter?width=48&height=48&radius=16&bezelWidth=12&glassThickness=40&refractiveIndex=1.45&bezelType=convex_squircle";
import { useAudioPlayer } from "@/contexts/AudioPlayerContext";
import { Button } from "@/components/ui/button";
import { useProjectCoverImage } from "@/hooks/useProjectCoverImage";
import {
  CROSSFADE_DURATION_MS,
  BLUR_DURATION_MS,
  CROSSFADE_BLUR_PX,
  CROSSFADE_EASING,
  BLUR_EASING,
} from "@/lib/constants";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import type { Project } from "@/types/api";

export interface TrackCardData {
  public_id: string;
  title: string;
  artist?: string | null;
  projectCoverUrl?: string;
  sharedBy?: string;
  projectName?: string;
  waveform?: string | null;
  duration_seconds?: number | null;
  project_id?: number;
}

interface TrackCardProps {
  track: TrackCardData;
  onClick?: () => void;
  onShare?: () => void;
  isShared?: boolean;
  className?: string;
  isOwned?: boolean;
  canDownload?: boolean;
  onAddToQueue?: () => void;
  onMove?: () => void;
  onExport?: () => void;
  onLeave?: () => void;
  dragHandleProps?: {
    onPointerDown: (event: React.PointerEvent) => void;
    onPointerUp?: (event: React.PointerEvent) => void;
    onPointerMove?: (event: React.PointerEvent) => void;
  } & React.HTMLAttributes<HTMLDivElement>;
  isDragging?: boolean;
  dragScaleDown?: boolean;
  hoverAsFolder?: boolean;
  hoverFolderItems?: any[];
  isDropping?: boolean;
}

export function TrackCard({
  track,
  onClick,
  isShared,
  className,
  isOwned = true,
  canDownload = true,
  onAddToQueue,
  onMove,
  onExport,
  onLeave,
  dragHandleProps,
  isDragging,
  dragScaleDown,
  hoverAsFolder,
  hoverFolderItems = [],
  isDropping = false,
}: TrackCardProps) {
  const [gradientColors, setGradientColors] = useState<string[]>([
    "#8FC7FF",
    "#4CF3FF",
    "#BFF9FF",
    "#59AFFF",
  ]);
  const imgRef = useRef<HTMLImageElement>(null);
  const isDraggingRef = useRef(false);
  const [isTextCrossfading, setIsTextCrossfading] = useState(false);
  const prevHoverRef = useRef<boolean | undefined>(undefined);
  const { play, pause, isPlaying, currentTrack } = useAudioPlayer();

  const playButtonPointerDown = useMotionValue(0);
  const playButtonIsUp = useTransform(
    () => (playButtonPointerDown.get() > 0.5 ? 1 : 0) as number
  );

  const playButtonBlurBase = useMotionValue(0);
  const playButtonBlur = useSpring(playButtonBlurBase, {
    damping: 30,
    stiffness: 200,
  });
  const playButtonSpecularOpacity = useMotionValue(0.6);
  const playButtonSpecularSaturation = useMotionValue(12);
  const playButtonRefractionBase = useMotionValue(1.1);

  useEffect(() => {
    const timer = setTimeout(() => {
      playButtonBlurBase.set(3);
    }, 280);
    return () => clearTimeout(timer);
  }, [playButtonBlurBase]);

  const playButtonPressMultiplier = useTransform(
    playButtonIsUp as any,
    [0, 1],
    [0.4, 0.9]
  );

  const playButtonScaleRatio = useSpring(
    useTransform(
      [playButtonPressMultiplier, playButtonRefractionBase],
      ([m, base]) => (Number(m) || 0) * (Number(base) || 0)
    )
  );

  const playButtonScaleSpring = useSpring(
    useTransform(playButtonIsUp as any, [0, 1], [1, 0.95]),
    { damping: 80, stiffness: 2000 }
  );

  const playButtonBackgroundOpacity = useMotionValue(0.7);

  const playButtonBackgroundColor = useTransform(
    playButtonBackgroundOpacity,
    (op) => `rgba(40, 39, 39, ${op})`
  );

  const handleColorsExtracted = (colors: string[]) => {
    if (colors.length > 0) {
      const selectedColors = colors.slice(1, 5);
      setGradientColors(selectedColors);
    }
  };

  const handleError = (error: Error) => {
    console.error("[TrackCard] Failed to extract colors:", error);
  };

  const handleCardClick = (e: React.MouseEvent) => {
    if (isDraggingRef.current) {
      isDraggingRef.current = false;
      return;
    }

    const target = e.target as HTMLElement;
    if (
      target.closest("button") ||
      target.closest('[role="menuitem"]') ||
      target.closest('[role="menu"]')
    ) {
      return;
    }

    onClick?.();
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      onClick?.();
    }
  };

  useEffect(() => {
    if (isDragging) {
      isDraggingRef.current = true;
    }
  }, [isDragging]);

  useEffect(() => {
    if (prevHoverRef.current === undefined) {
      prevHoverRef.current = hoverAsFolder;
      return;
    }
    if (prevHoverRef.current !== hoverAsFolder) {
      setIsTextCrossfading(true);
      const t = setTimeout(
        () => setIsTextCrossfading(false),
        CROSSFADE_DURATION_MS
      );
      prevHoverRef.current = hoverAsFolder;
      return () => clearTimeout(t);
    }
    prevHoverRef.current = hoverAsFolder;
  }, [hoverAsFolder]);

  const handlePlayPause = () => {
    const isThisTrackPlaying =
      isPlaying && currentTrack?.id === track.public_id;

    if (isThisTrackPlaying) {
      pause();
      return;
    }

    const trackData = {
      id: track.public_id,
      title: track.title,
      artist: track.artist ?? undefined,
      projectName: track.projectName ?? "Unknown Project",
      coverUrl: track.projectCoverUrl,
      projectId: track.project_id?.toString(),
      projectCoverUrl: track.projectCoverUrl,
      waveform: track.waveform ?? undefined,
      versionId: undefined, // Shared tracks don't have version info in the grid view
      isSharedTrack: true,
    };

    play(trackData, [trackData], true, false, []);
  };

  const incomingCoverSource = (() => {
    const item = hoverFolderItems[0];
    if (!item) return null;

    const publicId =
      typeof item?.project_public_id === "string" && item.project_public_id
        ? item.project_public_id
        : typeof item?.public_id === "string" && item.public_id
          ? item.public_id
          : null;

    if (!publicId) return null;

    const coverUrl =
      typeof item?.cover_url === "string" ? item.cover_url : null;

    return { public_id: publicId, cover_url: coverUrl } satisfies Pick<
      Project,
      "public_id" | "cover_url"
    >;
  })();

  const { imageUrl: incomingCoverUrl } = useProjectCoverImage(
    incomingCoverSource ?? undefined,
    "small"
  );

  return (
    <div
      onClick={handleCardClick}
      onKeyDown={handleKeyDown}
      role="button"
      tabIndex={0}
      className={cn(
        "relative group w-full text-left focus:outline-none cursor-pointer transition-transform duration-300",
        dragScaleDown && isDragging ? "scale-[0.5]" : undefined,
        className
      )}
    >
      {/* Hidden image for color extraction */}
      {track.projectCoverUrl && (
        <div className="hidden">
          <ColorExtractor
            getColors={(colors: string[]) => handleColorsExtracted(colors)}
            onError={handleError}
          >
            <img
              ref={imgRef}
              src={track.projectCoverUrl}
              alt="cover for color extraction"
              crossOrigin="anonymous"
              loading="lazy"
              decoding="async"
            />
          </ColorExtractor>
        </div>
      )}

      {/* Disc Container */}
      <div
        className="relative aspect-square rounded-(--card-border-radius) border border-(--card-border) bg-neutral-800/40"
        style={{ touchAction: "auto" }}
        {...dragHandleProps}
      >
        {/* Original disc that transitions to top-left position */}
        <motion.div
          className={cn(
            "absolute overflow-hidden z-0",
            "transition-[top,left,right,bottom,border-radius] duration-200",
            hoverAsFolder
              ? "top-2 left-2 right-[calc(50%+2px)] bottom-[calc(50%+2px)] rounded-2xl border-(--card-border) border"
              : "inset-2 rounded-full"
          )}
          animate={{ opacity: isDragging ? 0.8 : 1 }}
          transition={{ duration: 0.3 }}
        >
          {/* Vinyl Record Disc Mask */}
          <svg
            className="absolute inset-2 w-[calc(100%-1rem)] h-[calc(100%-1rem)] z-10 pointer-events-none"
            viewBox="0 0 200 200"
            xmlns="http://www.w3.org/2000/svg"
          >
            <defs>
              <mask id={`disc-mask-${track.public_id}`}>
                {/* White circle (visible) */}
                <circle cx="100" cy="100" r="100" fill="white" />
                {/* Center hole cutout */}
                <circle cx="100" cy="100" r="20" fill="black" />
              </mask>
            </defs>

            {/* Cover art with mask applied */}
            <image
              x="0"
              y="0"
              width="200"
              height="200"
              href={track.projectCoverUrl || "/placeholder-cover.jpg"}
              preserveAspectRatio="xMidYMid slice"
              mask={`url(#disc-mask-${track.public_id})`}
              className="object-cover"
            />

            {/* Disc border */}
            <circle
              cx="100"
              cy="100"
              r="100"
              fill="none"
              stroke="var(--card-border-color, rgba(124,124,124,0.3))"
              strokeWidth="2"
            />
          </svg>

          {/* Background for non-masked area */}
          <div className="absolute inset-0 bg-gradient-to-br from-[#232323] to-[#1a1a1a] rounded-full" />

          {/* First gradient overlay layer */}
          <div
            className="absolute inset-0 rounded-full pointer-events-none z-20"
            style={{
              background: `conic-gradient(from 90deg at 50% 50%, rgba(255, 255, 255, 0.00) 157.5deg, ${gradientColors[0]} 180deg, ${gradientColors[1] || gradientColors[0]} 205.96deg, ${gradientColors[2] || gradientColors[1] || gradientColors[0]} 231.92deg, ${gradientColors[3] || gradientColors[2] || gradientColors[1] || gradientColors[0]} 273.46deg, rgba(255, 255, 255, 0.00) 327.12deg)`,
              opacity: 0.5,
              WebkitMaskImage:
                "radial-gradient(circle, transparent 0%, transparent 19%, black 20%, black 100%)",
              maskImage:
                "radial-gradient(circle, transparent 0%, transparent 19%, black 20%, black 100%)",
            }}
          />

          {/* Second gradient overlay layer (rotated 180 degrees) */}
          <div
            className="absolute inset-0 rounded-full pointer-events-none z-20"
            style={{
              background: `conic-gradient(from 90deg at 50% 50%, rgba(255, 255, 255, 0.00) 157.5deg, ${gradientColors[0]} 180deg, ${gradientColors[1] || gradientColors[0]} 205.96deg, ${gradientColors[2] || gradientColors[1] || gradientColors[0]} 231.92deg, ${gradientColors[3] || gradientColors[2] || gradientColors[1] || gradientColors[0]} 273.46deg, rgba(255, 255, 255, 0.00) 327.12deg)`,
              opacity: 0.5,
              transform: "rotate(180deg)",
              WebkitMaskImage:
                "radial-gradient(circle, transparent 0%, transparent 19%, black 20%, black 100%)",
              maskImage:
                "radial-gradient(circle, transparent 0%, transparent 19%, black 20%, black 100%)",
            }}
          />
        </motion.div>

        {/* Incoming dragged item animating into top-right position */}
        {isDropping && hoverFolderItems.length > 0 && (
          <motion.div
            className="absolute top-2 right-2 w-[calc(50%-10px)] h-[calc(50%-10px)] rounded-2xl border-(--card-border) border overflow-hidden z-20"
            initial={{ opacity: 0, scale: 0.3 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{
              type: "spring",
              stiffness: 500,
              damping: 30,
            }}
          >
            {incomingCoverUrl ? (
              <img
                src={incomingCoverUrl}
                alt="Incoming item"
                className="size-full object-cover"
                draggable={false}
                loading="lazy"
                decoding="async"
              />
            ) : (
              <div className="size-full bg-neutral-800 flex items-center justify-center text-white text-lg font-bold">
                {String(
                  hoverFolderItems[0]?.name || hoverFolderItems[0]?.title || ""
                )
                  .charAt(0)
                  .toUpperCase()}
              </div>
            )}
          </motion.div>
        )}

        {/* Glass filter for play/pause button */}
        <Filter
          id={`play-button-filter-${track.public_id}`}
          blur={playButtonBlur}
          scaleRatio={playButtonScaleRatio}
          specularOpacity={playButtonSpecularOpacity}
          specularSaturation={playButtonSpecularSaturation}
        />

        {/* Play/Pause Button */}
        <motion.button
          type="button"
          aria-label={
            isPlaying && currentTrack?.id === track.public_id ? "Pause" : "Play"
          }
          className={cn(
            "absolute -bottom-3 -right-3 z-30 shadow-md transition-opacity size-12 rounded-[16px] flex items-center justify-center",
            isDragging || hoverAsFolder
              ? "opacity-0 pointer-events-none"
              : undefined
          )}
          style={{
            backdropFilter: `url(#play-button-filter-${track.public_id})`,
            backgroundColor: playButtonBackgroundColor,
            scale: playButtonScaleSpring,
          }}
          onClick={(e) => {
            e.stopPropagation();
            handlePlayPause();
          }}
          onMouseDown={() => playButtonPointerDown.set(1)}
          onMouseUp={() => playButtonPointerDown.set(0)}
          onMouseLeave={() => playButtonPointerDown.set(0)}
        >
          {isPlaying && currentTrack?.id === track.public_id ? (
            <Pause className="size-5" fill="white" stroke="white" />
          ) : (
            <Play className="size-5" fill="white" stroke="white" />
          )}
        </motion.button>
      </div>

      {/* Track Info */}
      <motion.div
        className="mt-3 h-11"
        animate={{ opacity: isDragging ? 0.8 : 1 }}
        transition={{ duration: 0.3 }}
      >
        <div className="relative h-full">
          <div
            className={cn(
              "absolute inset-0",
              isDragging || hoverAsFolder ? "opacity-0" : "opacity-100"
            )}
            style={{
              transition: `opacity ${CROSSFADE_DURATION_MS}ms ${CROSSFADE_EASING}, filter ${BLUR_DURATION_MS}ms ${BLUR_EASING}`,
              filter: isTextCrossfading
                ? `blur(${CROSSFADE_BLUR_PX}px)`
                : undefined,
            }}
          >
            <div className="flex min-w-0 items-center gap-2">
              {/* Shared Icon */}
              {isShared && (
                <Users className="h-3 w-3 text-muted-foreground flex-shrink-0" />
              )}

              <div className="flex-1 min-w-0">
                <div className="truncate text-sm font-semibold text-foreground">
                  {track.title}
                </div>
                <div className="flex min-w-0 items-center gap-2 text-xs text-muted-foreground">
                  <span className="truncate">
                    {(typeof track.artist === "string" && track.artist.trim()
                      ? track.artist
                      : null) ||
                      (typeof track.sharedBy === "string" &&
                      track.sharedBy.trim()
                        ? track.sharedBy
                        : null) ||
                      (typeof track.projectName === "string"
                        ? track.projectName
                        : null) ||
                      "Unknown Artist"}
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* Folder preview text */}
          <div
            className={cn(
              "absolute inset-0",
              hoverAsFolder && !isDragging ? "opacity-100" : "opacity-0"
            )}
            style={{
              transition: `opacity ${CROSSFADE_DURATION_MS}ms ${CROSSFADE_EASING}, filter ${BLUR_DURATION_MS}ms ${BLUR_EASING}`,
              filter: isTextCrossfading
                ? `blur(${CROSSFADE_BLUR_PX}px)`
                : undefined,
            }}
            aria-hidden={!(hoverAsFolder && !isDragging)}
          >
            <div
              className="truncate text-sm font-semibold text-foreground"
              title="New Folder"
            >
              New Folder
            </div>
            <div className="text-xs text-muted-foreground">
              {(1 + hoverFolderItems.length).toString()} items
            </div>
          </div>

          {/* Dropdown Menu */}
          <div className="absolute bottom-0 right-0">
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button
                  variant="ghost"
                  size="icon-sm"
                  aria-label="Track options"
                  className="-mr-3 select-none p-0 h-5 rounded-md hover:bg-muted/30 transition-none"
                  onMouseDown={(e) => e.preventDefault()}
                  onClick={(e) => e.stopPropagation()}
                >
                  <MoreHorizontal />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent
                align="center"
                side="top"
                className="w-44 border-muted bg-background"
              >
                {isOwned ? (
                  <>
                    {onAddToQueue && (
                      <DropdownMenuItem onSelect={onAddToQueue}>
                        <ListPlus className="ml-1 mr-1.5 size-4.5" />
                        Add to queue
                      </DropdownMenuItem>
                    )}
                    {onMove && (
                      <DropdownMenuItem onSelect={onMove}>
                        <FolderInput className="ml-1 mr-1.5 size-4.5" />
                        Move
                      </DropdownMenuItem>
                    )}
                    {onExport && (
                      <DropdownMenuItem onSelect={onExport}>
                        <Download className="ml-1 mr-1.5 size-4.5" />
                        Export
                      </DropdownMenuItem>
                    )}
                  </>
                ) : (
                  <>
                    {onAddToQueue && (
                      <DropdownMenuItem onSelect={onAddToQueue}>
                        <ListPlus className="ml-1 mr-1.5 size-4.5" />
                        Add to queue
                      </DropdownMenuItem>
                    )}
                    {onMove && (
                      <DropdownMenuItem onSelect={onMove}>
                        <FolderInput className="ml-1 mr-1.5 size-4.5" />
                        Move
                      </DropdownMenuItem>
                    )}
                    {canDownload && onExport && (
                      <DropdownMenuItem onSelect={onExport}>
                        <Download className="ml-1 mr-1.5 size-4.5" />
                        Export
                      </DropdownMenuItem>
                    )}
                    {onLeave && (
                      <>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem
                          variant="destructive"
                          onSelect={onLeave}
                        >
                          <LogOut className="ml-1 mr-1.5 size-4.5" />
                          Leave
                        </DropdownMenuItem>
                      </>
                    )}
                  </>
                )}
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </div>
      </motion.div>
    </div>
  );
}

export default TrackCard;
