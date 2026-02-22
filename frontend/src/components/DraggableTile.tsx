import { useCallback, useEffect, useRef, useState } from "react";
import type React from "react";
import { motion, useDragControls, useMotionValue, animate } from "motion/react";
import { cn } from "@/lib/utils";

interface DraggableTileProps {
  id: string;
  layoutId?: string;
  registerRef: (id: string) => (el: HTMLDivElement | null) => void;
  isDragging: boolean;
  isBeingDropped: boolean;
  isRestoredFromFolder?: boolean;
  onDragStart: () => void;
  onDragMove: (point: { x: number; y: number }) => void;
  onDragCancel: () => void;
  onDrop: (
    shouldActuallyDrop: boolean,
    currentDragOffset?: { x: number; y: number },
  ) => boolean | Promise<boolean>;
  children: (
    dragHandleProps: {
      onPointerDown: (event: React.PointerEvent) => void;
      onPointerUp?: (event: React.PointerEvent) => void;
      onPointerMove?: (event: React.PointerEvent) => void;
    } & React.HTMLAttributes<HTMLDivElement>,
    isDragging: boolean,
  ) => React.ReactNode;
}

export default function DraggableTile({
  id,
  layoutId,
  registerRef,
  isDragging,
  isBeingDropped,
  isRestoredFromFolder = false,
  onDragStart,
  onDragMove,
  onDragCancel,
  onDrop,
  children,
}: DraggableTileProps) {
  const dragControls = useDragControls();
  const x = useMotionValue(0);
  const y = useMotionValue(0);
  const opacity = useMotionValue(isRestoredFromFolder ? 0 : 1);
  const scale = useMotionValue(isRestoredFromFolder ? 0.96 : 1);

  const [dragged, setDragged] = useState(false);
  const [isAnimatingToDrop, setIsAnimatingToDrop] = useState(false);
  const [shouldDisableDrag, setShouldDisableDrag] = useState(false);
  const [isDragReady, setIsDragReady] = useState(false);
  const animationCompleteCallbackRef = useRef<(() => void) | null>(null);
  const longPressTimerRef = useRef<NodeJS.Timeout | null>(null);
  const pendingEventRef = useRef<React.PointerEvent | null>(null);
  const initialPointerPosRef = useRef<{ x: number; y: number } | null>(null);
  const elementRef = useRef<HTMLDivElement | null>(null);
  const scrollAnimationRef = useRef<number | null>(null);
  const currentPointerYRef = useRef<number>(0);
  const hasMovedSinceDragStartRef = useRef<boolean>(false);

  useEffect(() => {
    if (!isDragging && !isAnimatingToDrop) {
      setDragged(false);
      setShouldDisableDrag(false);
      setIsDragReady(false);
      hasMovedSinceDragStartRef.current = false;
    }
  }, [isDragging, isAnimatingToDrop]);

  useEffect(() => {
    if (isBeingDropped && !isAnimatingToDrop) {
      setIsAnimatingToDrop(true);

      const fadeOut = animate(opacity, 0, { duration: 0.2 });

      fadeOut.then(() => {
        setIsAnimatingToDrop(false);

        if (animationCompleteCallbackRef.current) {
          animationCompleteCallbackRef.current();
          animationCompleteCallbackRef.current = null;
        }
      });

      return () => {
        fadeOut.stop();
      };
    }
  }, [isBeingDropped, opacity]);

  useEffect(() => {
    if (isRestoredFromFolder) {
      const scaleAnim = animate(scale, 1, {
        duration: 0.2,
        ease: [0.25, 0.46, 0.45, 0.94],
      });

      const opacityAnim = animate(opacity, 1, {
        duration: 0.3,
        ease: [0.25, 0.46, 0.45, 0.94],
      });

      return () => {
        scaleAnim.stop();
        opacityAnim.stop();
      };
    }
  }, [isRestoredFromFolder, scale, opacity]);

  useEffect(() => {
    return () => {
      if (longPressTimerRef.current) {
        clearTimeout(longPressTimerRef.current);
      }
    };
  }, []);

  useEffect(() => {
    if (!dragged) return;

    const EDGE_ZONE = 100;
    const MAX_SCROLL_SPEED = 15;

    const performScroll = () => {
      if (!hasMovedSinceDragStartRef.current) {
        scrollAnimationRef.current = requestAnimationFrame(performScroll);
        return;
      }

      const pointerY = currentPointerYRef.current;
      const viewportHeight = window.innerHeight;

      let scrollSpeed = 0;

      if (pointerY < EDGE_ZONE) {
        const distanceIntoZone = EDGE_ZONE - pointerY;
        scrollSpeed = -Math.min(
          MAX_SCROLL_SPEED,
          (distanceIntoZone / EDGE_ZONE) * MAX_SCROLL_SPEED,
        );
      } else if (pointerY > viewportHeight - EDGE_ZONE) {
        const distanceIntoZone = pointerY - (viewportHeight - EDGE_ZONE);
        scrollSpeed = Math.min(
          MAX_SCROLL_SPEED,
          (distanceIntoZone / EDGE_ZONE) * MAX_SCROLL_SPEED,
        );
      }

      if (scrollSpeed !== 0) {
        window.scrollBy(0, scrollSpeed);
      }

      scrollAnimationRef.current = requestAnimationFrame(performScroll);
    };

    scrollAnimationRef.current = requestAnimationFrame(performScroll);

    return () => {
      if (scrollAnimationRef.current) {
        cancelAnimationFrame(scrollAnimationRef.current);
        scrollAnimationRef.current = null;
      }
    };
  }, [isDragReady, dragged]);

  useEffect(() => {
    if (!isDragReady && !dragged) return;

    const handleTouchMove = (e: TouchEvent) => {
      if (e.touches.length > 0) {
        currentPointerYRef.current = e.touches[0].clientY;
        hasMovedSinceDragStartRef.current = true;
      }
      e.preventDefault();
    };

    const handlePointerMove = (e: PointerEvent) => {
      currentPointerYRef.current = e.clientY;
      hasMovedSinceDragStartRef.current = true;
    };

    document.addEventListener("touchmove", handleTouchMove, { passive: false });
    document.addEventListener("pointermove", handlePointerMove);

    return () => {
      document.removeEventListener("touchmove", handleTouchMove);
      document.removeEventListener("pointermove", handlePointerMove);
    };
  }, [isDragReady, dragged]);

  const cancelLongPress = useCallback(() => {
    if (longPressTimerRef.current) {
      clearTimeout(longPressTimerRef.current);
      longPressTimerRef.current = null;
    }
    if (scrollAnimationRef.current) {
      cancelAnimationFrame(scrollAnimationRef.current);
      scrollAnimationRef.current = null;
    }
    pendingEventRef.current = null;
    initialPointerPosRef.current = null;
    hasMovedSinceDragStartRef.current = false;
    setIsDragReady(false);
  }, []);

  const handlePointerDown = useCallback(
    (event: React.PointerEvent) => {
      x.stop();
      y.stop();
      x.set(0);
      y.set(0);

      const isTouchEvent = event.pointerType === "touch";

      if (isTouchEvent) {
        pendingEventRef.current = event;
        initialPointerPosRef.current = { x: event.clientX, y: event.clientY };
        longPressTimerRef.current = setTimeout(() => {
          if (pendingEventRef.current) {
            setIsDragReady(true);
            dragControls.start(pendingEventRef.current);
            pendingEventRef.current = null;
            initialPointerPosRef.current = null;
          }
          longPressTimerRef.current = null;
        }, 200);
      } else {
        dragControls.start(event);
      }
    },
    [dragControls, x, y],
  );

  const handlePointerUp = useCallback(() => {
    cancelLongPress();
  }, [cancelLongPress]);

  const handlePointerMove = useCallback(
    (event: React.PointerEvent) => {
      if (initialPointerPosRef.current && longPressTimerRef.current) {
        const dx = event.clientX - initialPointerPosRef.current.x;
        const dy = event.clientY - initialPointerPosRef.current.y;
        const distance = Math.sqrt(dx * dx + dy * dy);

        if (distance > 10) {
          cancelLongPress();
        }
      }
    },
    [cancelLongPress],
  );

  return (
    <motion.div
      ref={(node) => {
        registerRef(id)(node);
        elementRef.current = node;
      }}
      layoutId={isRestoredFromFolder ? undefined : layoutId}
      className={cn("relative w-40", dragged ? "z-30" : undefined)}
      style={{
        x,
        y,
        opacity,
        scale,
        touchAction: isDragReady || dragged ? "none" : "auto",
      }}
      layout={!dragged && !shouldDisableDrag}
      drag
      dragControls={dragControls}
      dragListener={false}
      dragMomentum={false}
      dragSnapToOrigin={!shouldDisableDrag}
      dragElastic={0.12}
      dragTransition={{ bounceStiffness: 1200, bounceDamping: 58 }}
      exit={
        isBeingDropped
          ? { opacity: 0, transition: { duration: 0 } }
          : { opacity: 0, scale: 0.8, transition: { duration: 0.3 } }
      }
      transition={{
        layout: { type: "spring", stiffness: 500, damping: 35 },
        default: { type: "spring", stiffness: 700, damping: 45 },
      }}
      onDragStart={() => {
        setDragged(true);
        onDragStart();
      }}
      onDrag={(_, info) => {
        onDragMove(info.point);
      }}
      onDragEnd={async () => {
        const currentOffset = { x: x.get(), y: y.get() };

        const willDrop = await onDrop(false, currentOffset);

        if (willDrop) {
          setShouldDisableDrag(true);
          x.stop();
          y.stop();

          animationCompleteCallbackRef.current = async () => {
            await onDrop(true);
          };
        } else {
          onDragCancel();
        }
      }}
    >
      {children(
        {
          onPointerDown: handlePointerDown,
          onPointerUp: handlePointerUp,
          onPointerMove: handlePointerMove,
        },
        dragged,
      )}
    </motion.div>
  );
}
