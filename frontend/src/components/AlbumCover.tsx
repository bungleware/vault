import { cn } from "@/lib/utils";
import { useEffect, useRef, useState } from "react";
import { ColorExtractor } from "react-color-extractor";

interface AlbumCoverProps {
  imageUrl?: string;
  title: string;
  className?: string;
  onUploadClick?: () => void;
  showUploadOverlay?: boolean;
  onColorsReady?: () => void;
  isPlaying?: boolean;
  playbackProgress?: number;
}

export default function AlbumCover({
  imageUrl,
  title,
  className,
  onUploadClick,
  showUploadOverlay = false,
  onColorsReady,
  isPlaying = false,
  playbackProgress = 0,
}: AlbumCoverProps) {
  const [gradientColors, setGradientColors] = useState<string[]>([
    "#8FC7FF",
    "#4CF3FF",
    "#BFF9FF",
    "#59AFFF",
  ]);
  const [discBaseColor, setDiscBaseColor] = useState<string>("white");
  const [isCoverImageLoaded, setIsCoverImageLoaded] = useState(false);
  const [isMobileScreen, setIsMobileScreen] = useState(false);
  const imgRef = useRef<HTMLImageElement>(null);
  const onColorsReadyRef = useRef(onColorsReady);

  useEffect(() => {
    onColorsReadyRef.current = onColorsReady;
  });

  useEffect(() => {
    const mediaQuery = window.matchMedia("(max-width: 640px)"); // sm breakpoint

    const handleChange = (e: MediaQueryListEvent | MediaQueryList) => {
      setIsMobileScreen(e.matches);
    };

    handleChange(mediaQuery);
    mediaQuery.addEventListener("change", handleChange);

    return () => {
      mediaQuery.removeEventListener("change", handleChange);
    };
  }, []);

  const getPixelBrightness = (data: Uint8ClampedArray, i: number): number => {
    const r = data[i];
    const g = data[i + 1];
    const b = data[i + 2];
    return 0.299 * r + 0.587 * g + 0.114 * b;
  };

  const calculateImageBrightness = (imageElement: HTMLImageElement): number => {
    try {
      const canvas = document.createElement("canvas");
      const ctx = canvas.getContext("2d", { willReadFrequently: true });
      if (!ctx) {
        console.warn("[AlbumCover] Failed to get canvas context");
        return 128;
      }

      if (!imageElement.complete || !imageElement.naturalWidth) {
        console.warn("[AlbumCover] Image not loaded yet");
        return 128;
      }

      canvas.width = imageElement.naturalWidth;
      canvas.height = imageElement.naturalHeight;

      ctx.drawImage(imageElement, 0, 0);
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const data = imageData.data;

      let totalBrightness = 0;
      const maxTrials = 100;
      const pixels = data.length / 4;
      const numTrials = Math.min(pixels, maxTrials);

      for (let t = 0; t < numTrials; t++) {
        const x = Math.random();
        const i = Math.trunc((x * data.length) / 4) * 4;
        totalBrightness += getPixelBrightness(data, i);
      }

      const avgBrightness = totalBrightness / numTrials;
      return avgBrightness;
    } catch (error) {
      console.error("[AlbumCover] Error calculating brightness:", error);
      return 128;
    }
  };

  useEffect(() => {
    setIsCoverImageLoaded(false);
    if (!imageUrl) {
      setGradientColors(["#8FC7FF", "#4CF3FF", "#BFF9FF", "#59AFFF"]);
      setDiscBaseColor("white");
      if (onColorsReadyRef.current) {
        onColorsReadyRef.current();
      }
    } else {
      setDiscBaseColor("white");
    }
  }, [imageUrl]);

  const handleColorsExtracted = (
    colors: string[],
    _imageElement?: HTMLImageElement,
  ) => {
    if (!imageUrl) {
      return;
    }

    if (colors.length > 0) {
      const selectedColors = colors.slice(1, 5);
      setGradientColors(selectedColors);
    }
  };

  const handleImageLoad = () => {
    setIsCoverImageLoaded(true);

    if (!imageUrl) {
      return;
    }

    if (imgRef.current) {
      const avgBrightness = calculateImageBrightness(imgRef.current);
      const baseColor = avgBrightness < 100 ? "black" : "white";
      setDiscBaseColor(baseColor);
    }

    if (onColorsReadyRef.current) {
      onColorsReadyRef.current();
    }
  };

  const handleError = (error: Error) => {
    console.error("[AlbumCover] Failed to extract colors:", error);
    if (onColorsReadyRef.current) {
      onColorsReadyRef.current();
    }
  };

  return (
    <div
      className={cn(
        "relative transition-transform duration-300 ease-in-out",
        className,
      )}
      style={{
        transform:
          isPlaying && !isMobileScreen ? "translateX(0)" : "translateX(2rem)",
      }}
    >
      {!isMobileScreen && (
        <svg className="absolute w-0 h-0">
          <defs>
            <filter id="cd-noise">
              <feTurbulence
                type="fractalNoise"
                baseFrequency="1"
                numOctaves="1"
                stitchTiles="stitch"
              />
              <feColorMatrix type="saturate" values="0" />
              <feComponentTransfer>
                <feFuncA type="discrete" tableValues="0 0.3" />
              </feComponentTransfer>
            </filter>
          </defs>
        </svg>
      )}

      <div
        className={cn(
          "relative z-10 aspect-square w-full rounded-2xl overflow-hidden outline outline-white/13 group bg-neutral-800",
          showUploadOverlay && onUploadClick && "cursor-pointer",
        )}
        onClick={showUploadOverlay && onUploadClick ? onUploadClick : undefined}
      >
        {imageUrl ? (
          <ColorExtractor
            getColors={(colors: string[]) => handleColorsExtracted(colors)}
            onError={handleError}
          >
            <img
              ref={imgRef}
              src={imageUrl}
              alt={title}
              className={cn(
                "w-full h-full object-cover transition-opacity duration-300 ease-out",
                isCoverImageLoaded ? "opacity-100" : "opacity-0",
              )}
              crossOrigin="anonymous"
              onLoad={handleImageLoad}
              loading="lazy"
              decoding="async"
            />
          </ColorExtractor>
        ) : (
          <div className="w-full h-full bg-neutral-800 flex items-center justify-center"></div>
        )}

        {showUploadOverlay && onUploadClick && (
          <div className="absolute inset-0 bg-black/40 opacity-0 group-hover:opacity-100 transition-opacity duration-200 flex items-end justify-center pb-6">
            <span className="text-white text-sm font-medium">
              Change cover art
            </span>
          </div>
        )}
      </div>

      {!isMobileScreen && (
        <div
          className={cn(
            "absolute top-1/2 -translate-y-1/2 w-[99%] h-[99%] z-0 transition-all duration-300 ease-in-out",
            isPlaying ? "-right-13" : "right-0",
          )}
        >
          <div className="absolute inset-0 rounded-full opacity-100" />

          <div className="relative w-full h-full rounded-full overflow-hidden border-white/50 border-2">
            <div
              className="absolute inset-0 rounded-full"
              style={{ backgroundColor: discBaseColor }}
            />
            <div className="absolute inset-0 blur-[6px]">
              <div
                className="absolute inset-0 rounded-full opacity-100"
                style={{
                  mixBlendMode: "multiply",
                  background: `conic-gradient(from 90deg at 50% 50%, rgba(255, 255, 255, 0.00) 157.5deg, ${gradientColors[0]} 180deg, ${gradientColors[1] || gradientColors[0]} 205.96deg, ${gradientColors[2] || gradientColors[1] || gradientColors[0]} 231.92deg, ${gradientColors[3] || gradientColors[2] || gradientColors[1] || gradientColors[0]} 273.46deg, rgba(255, 255, 255, 0.00) 327.12deg)`,
                  transform: `rotate(${(playbackProgress * 12) % 360}deg)`,
                }}
              />

              <div
                className="absolute inset-0 rounded-full opacity-100"
                style={{
                  mixBlendMode: "multiply",
                  background: `conic-gradient(from 90deg at 50% 50%, rgba(255, 255, 255, 0.00) 157.5deg, ${gradientColors[0]} 180deg, ${gradientColors[1] || gradientColors[0]} 205.96deg, ${gradientColors[2] || gradientColors[1] || gradientColors[0]} 231.92deg, ${gradientColors[3] || gradientColors[2] || gradientColors[1] || gradientColors[0]} 273.46deg, rgba(255, 255, 255, 0.00) 327.12deg)`,
                  transform: `rotate(${((playbackProgress * 12) % 360) + 180}deg)`,
                }}
              />
            </div>
            <div
              className="absolute inset-0 rounded-full border-8 bg-blend-color-burn opacity-10"
              style={{
                borderColor: discBaseColor === "white" ? "black" : "white",
              }}
            />
            <div
              className="absolute inset-0 rounded-full opacity-100"
              style={{
                filter: !isMobileScreen ? "url(#cd-noise)" : undefined,
                transform: `rotate(${(playbackProgress * 180) % 360}deg)`,
              }}
            />
            <div
              className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-34 h-34 z-10 flex items-center justify-center lg:border-[0.5px] rounded-full"
              style={{
                borderColor:
                  discBaseColor === "white"
                    ? "rgba(0,0,0,0.2)"
                    : "rgba(255,255,255,0.2)",
              }}
            >
              <div
                className="w-full h-full rounded-full lg:border-24 flex items-center justify-center"
                style={{ borderColor: discBaseColor }}
              >
                <div
                  className="w-22 h-22 rounded-full border-[0.5px] flex items-center justify-center"
                  style={{
                    borderColor:
                      discBaseColor === "white"
                        ? "rgba(0,0,0,0.2)"
                        : "rgba(255,255,255,0.2)",
                    backgroundColor:
                      discBaseColor === "white"
                        ? "rgba(255,255,255,0.5)"
                        : "rgba(0,0,0,0.5)",
                  }}
                >
                  <div
                    className="w-14 h-14 rounded-full border-[0.5px]"
                    style={{
                      backgroundColor: discBaseColor,
                      borderColor:
                        discBaseColor === "white"
                          ? "rgba(0,0,0,0.2)"
                          : "rgba(255,255,255,0.2)",
                    }}
                  />
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
