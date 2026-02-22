import { cn } from "@/lib/utils";
import type { CSSProperties } from "react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

type AlignOption = "left" | "center";

type CSSVars = CSSProperties & {
  "--scroll-duration"?: string;
  "--scroll-offset"?: string;
};

interface ScrollingTextProps {
  text: string;
  className?: string;
  gradientColor?: string;
  pauseOnHover?: boolean;
  align?: AlignOption;
  ariaLabel?: string;
  isActive?: boolean;
  onOverflowChange?: (isOverflowing: boolean) => void;
  gap?: number;
}

export default function ScrollingText({
  text,
  className,
  gradientColor = "#000000",
  pauseOnHover = true,
  align = "left",
  ariaLabel,
  isActive = true,

  onOverflowChange,
  gap = 16,
}: ScrollingTextProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const contentRef = useRef<HTMLSpanElement | null>(null);
  const [isOverflowing, setIsOverflowing] = useState(false);
  const [animationDuration, setAnimationDuration] = useState(10);
  const [prefersReducedMotion, setPrefersReducedMotion] = useState(false);
  const [scrollOffset, setScrollOffset] = useState(0);
  const [contentWidth, setContentWidth] = useState(0);
  const [measuredText, setMeasuredText] = useState(text);

  const updateOverflowState = useCallback(() => {
    const container = containerRef.current;
    const content = contentRef.current;
    if (!container || !content) {
      return;
    }

    const containerWidth = container.clientWidth;
    const nextContentWidth = content.scrollWidth;
    const overflows = nextContentWidth > containerWidth + 2;

    setContentWidth(nextContentWidth);
    setMeasuredText(text);

    setIsOverflowing(overflows);
    onOverflowChange?.(overflows);

    if (overflows) {
      const scrollDistance = Math.max(nextContentWidth, containerWidth);
      const calculatedDuration = Math.min(24, Math.max(6, scrollDistance / 32));
      setAnimationDuration(calculatedDuration);
      setScrollOffset(nextContentWidth + gap);
    } else {
      setScrollOffset(0);
    }
  }, [onOverflowChange, gap, text]);

  useEffect(() => {
    if (typeof window === "undefined" || !("ResizeObserver" in window)) {
      return;
    }

    const observer = new ResizeObserver(() => updateOverflowState());

    if (containerRef.current) {
      observer.observe(containerRef.current);
    }

    if (contentRef.current) {
      observer.observe(contentRef.current);
    }

    updateOverflowState();

    return () => {
      observer.disconnect();
    };
  }, [text, updateOverflowState]);

  useEffect(() => {
    if (typeof window === "undefined" || !("matchMedia" in window)) {
      return;
    }
    const mediaQuery = window.matchMedia("(prefers-reduced-motion: reduce)");
    const handleChange = (event: MediaQueryListEvent | MediaQueryList) => {
      setPrefersReducedMotion(
        "matches" in event ? event.matches : mediaQuery.matches,
      );
    };

    handleChange(mediaQuery);

    const listener = (event: MediaQueryListEvent) => handleChange(event);
    mediaQuery.addEventListener("change", listener);

    return () => {
      mediaQuery.removeEventListener("change", listener);
    };
  }, []);

  const shouldAnimate = isActive && isOverflowing && !prefersReducedMotion;

  const inlineStyles: CSSVars = shouldAnimate
    ? {
        maskImage: `linear-gradient(90deg, transparent 0%, ${gradientColor} 10%, ${gradientColor} 90%, transparent 100%)`,
        WebkitMaskImage: `linear-gradient(90deg, transparent 0%, ${gradientColor} 10%, ${gradientColor} 90%, transparent 100%)`,
        "--scroll-duration": `${animationDuration}s`,
        "--scroll-offset": `${scrollOffset || 0}px`,
      }
    : {};

  const marqueeItemStyle = useMemo(() => {
    if (!shouldAnimate || contentWidth === 0 || measuredText !== text) {
      return undefined;
    }
    return {
      width: `${contentWidth}px`,
      flex: "0 0 auto",
    } as CSSProperties;
  }, [shouldAnimate, contentWidth, measuredText, text]);

  return (
    <div
      ref={containerRef}
      className={cn(
        "relative min-w-0 max-w-full w-full overflow-hidden",
        pauseOnHover && "group/scroller",
        className,
      )}
      style={inlineStyles}
      aria-label={ariaLabel ?? text}
    >
      <div
        className={cn(
          "flex items-center whitespace-nowrap",
          shouldAnimate
            ? "justify-start"
            : align === "center"
              ? "justify-center"
              : "justify-start",
          shouldAnimate && "animate-scroll-text",
          pauseOnHover && shouldAnimate && "group-hover/scroller:paused",
        )}
        style={{ gap: shouldAnimate ? gap : undefined }}
      >
        <span
          ref={contentRef}
          className="block flex-none"
          style={marqueeItemStyle}
        >
          {text}
        </span>
        {shouldAnimate && (
          <span
            aria-hidden
            className="block flex-none"
            style={marqueeItemStyle}
          >
            {text}
          </span>
        )}
      </div>
    </div>
  );
}
