import * as React from "react";
import * as SwitchPrimitive from "@radix-ui/react-switch";
import {
  mix,
  motion,
  useMotionValue,
  useSpring,
  useTransform,
} from "motion/react";
import { Filter } from "virtual:refractionFilter?width=32&height=22&radius=11&bezelWidth=5&glassThickness=11&refractiveIndex=1.5";

import { cn } from "@/lib/utils";

function Switch({
  className,
  checked,
  onCheckedChange,
  disabled,
  ...props
}: React.ComponentProps<typeof SwitchPrimitive.Root>) {
  // CONSTANTS (layout + optics)
  const sliderHeight = 20;
  const sliderWidth = 45;
  const thumbWidth = 32;
  const thumbHeight = 22;
  const thumbRadius = thumbHeight / 2;
  const sliderRef = React.useRef<HTMLDivElement>(null);
  const filterId = React.useId();

  const THUMB_REST_SCALE = 0.75;
  const THUMB_ACTIVE_SCALE = 1.1;
  const THUMB_REST_OFFSET = ((1 - THUMB_REST_SCALE) * thumbWidth) / 2;
  const TRAVEL =
    sliderWidth - sliderHeight - (thumbWidth - thumbHeight) * THUMB_REST_SCALE;

  // MOTION SOURCES
  const internalChecked = useMotionValue(checked ? 1 : 0);
  const pointerDown = useMotionValue(0);
  const xDragRatio = useMotionValue(0);
  const active = useTransform(() => (pointerDown.get() > 0.5 ? 1 : 0));

  // Update internal state when prop changes
  React.useEffect(() => {
    internalChecked.set(checked ? 1 : 0);
  }, [checked, internalChecked]);

  // GLOBAL POINTER-UP LISTENER
  const initialPointerX = useMotionValue(0);
  const hasDragged = useMotionValue(false);
  const justDragged = React.useRef(false);

  React.useEffect(() => {
    if (disabled) return;

    const onPointerUp = () => {
      const wasDragging = hasDragged.get();
      pointerDown.set(0);
      hasDragged.set(false);

      if (wasDragging) {
        // Mark that we just completed a drag to prevent onClick from firing
        justDragged.current = true;

        // If dragged, use the final position to determine state
        // Lower threshold (0.35) makes it easier to switch
        const x = xDragRatio.get();
        const shouldBeChecked = x > 0.35;
        onCheckedChange?.(shouldBeChecked);

        // Reset the flag after a short delay
        setTimeout(() => {
          justDragged.current = false;
        }, 100);
      }
    };

    window.addEventListener("mouseup", onPointerUp);
    window.addEventListener("touchend", onPointerUp);
    return () => {
      window.removeEventListener("mouseup", onPointerUp);
      window.removeEventListener("touchend", onPointerUp);
    };
  }, [pointerDown, onCheckedChange, disabled, hasDragged, xDragRatio]);

  // SPRINGS - slower animations with more damping
  const xRatio = useSpring(
    useTransform(() => {
      const c = internalChecked.get();
      const dragRatio = xDragRatio.get();
      return pointerDown.get() > 0.5 ? dragRatio : c ? 1 : 0;
    }),
    { damping: 75, stiffness: 1200 },
  );

  const backgroundOpacity = useSpring(
    useTransform(active, (v) => 1 - 0.9 * v),
    { damping: 75, stiffness: 1800 },
  );

  const thumbScale = useSpring(
    useTransform(
      active,
      (v) => THUMB_REST_SCALE + (THUMB_ACTIVE_SCALE - THUMB_REST_SCALE) * v,
    ),
    { damping: 75, stiffness: 1800 },
  );

  const scaleRatio = useSpring(useTransform(() => 0.4 + 0.5 * active.get()));

  const considerChecked = useTransform(() => {
    const x = xDragRatio.get();
    const c = internalChecked.get();
    return pointerDown.get() ? (x > 0.35 ? 1 : 0) : c > 0.5 ? 1 : 0;
  });

  const backgroundColor = useTransform(
    // @ts-ignore - Type mismatch between useSpring/useTransform and mix function
    useSpring(considerChecked, { damping: 75, stiffness: 1200 }),
    mix("#94949F77", "#3BBF4EEE"),
  );

  const handleMove = (clientX: number) => {
    if (!sliderRef.current || disabled) return;
    const baseRatio = internalChecked.get();
    const displacementX = clientX - initialPointerX.get();

    // Mark as dragged if moved more than 2px
    if (Math.abs(displacementX) > 2) {
      hasDragged.set(true);
      justDragged.current = true;
    }

    const ratio = baseRatio + displacementX / TRAVEL;
    const overflow = ratio < 0 ? -ratio : ratio > 1 ? ratio - 1 : 0;
    const overflowSign = ratio < 0 ? -1 : 1;
    const dampedOverflow = (overflowSign * overflow) / 22;
    xDragRatio.set(Math.min(1, Math.max(0, ratio)) + dampedOverflow);
  };

  return (
    <SwitchPrimitive.Root
      data-slot="switch"
      className={cn("peer outline-none", className)}
      checked={checked}
      onCheckedChange={onCheckedChange}
      disabled={disabled}
      asChild
      {...props}
    >
      <motion.div
        ref={sliderRef}
        style={{
          display: "inline-block",
          width: sliderWidth,
          height: sliderHeight,
          backgroundColor: backgroundColor,
          borderRadius: sliderHeight / 2,
          position: "relative",
          cursor: disabled ? "not-allowed" : "pointer",
          opacity: disabled ? 0.5 : 1,
          userSelect: "none",
          WebkitUserSelect: "none",
          WebkitTouchCallout: "none",
        }}
        onClick={(e) => {
          if (disabled) return;
          // Only toggle on click if we didn't just complete a drag
          if (justDragged.current) {
            e.preventDefault();
            e.stopPropagation();
            return;
          }
          onCheckedChange?.(!checked);
        }}
        onMouseMove={(e) => {
          if (pointerDown.get() > 0.5) {
            e.stopPropagation();
            handleMove(e.clientX);
          }
        }}
        onTouchMove={(e) => {
          if (pointerDown.get() > 0.5) {
            e.stopPropagation();
            handleMove(e.touches[0].clientX);
          }
        }}
      >
        <Filter
          id={`thumb-filter-${filterId}`}
          blur={0.2}
          scaleRatio={scaleRatio}
          specularOpacity={0.15}
          specularSaturation={1.5}
        />
        <motion.div
          className="absolute"
          onTouchStart={(e) => {
            if (disabled) return;
            e.preventDefault();
            e.stopPropagation();
            pointerDown.set(1);
            initialPointerX.set(e.touches[0].clientX);
          }}
          onMouseDown={(e) => {
            if (disabled) return;
            e.preventDefault();
            e.stopPropagation();
            pointerDown.set(1);
            initialPointerX.set(e.clientX);
          }}
          style={{
            height: thumbHeight,
            width: thumbWidth,
            marginLeft:
              -THUMB_REST_OFFSET +
              (sliderHeight - thumbHeight * THUMB_REST_SCALE) / 2,
            x: useTransform(() => xRatio.get() * TRAVEL),
            y: "-50%",
            borderRadius: thumbRadius,
            top: sliderHeight / 2,
            backdropFilter: `url(#thumb-filter-${filterId})`,
            scale: thumbScale,
            backgroundColor: useTransform(
              backgroundOpacity,
              (op) => `rgba(255, 255, 255, ${op})`,
            ),
            boxShadow: useTransform(() => {
              const isPressed = pointerDown.get() > 0.5;
              return (
                "0 4px 22px rgba(0,0,0,0.1)" +
                (isPressed
                  ? ", inset 2px 7px 24px rgba(0,0,0,0.09), inset -2px -7px 24px rgba(255,255,255,0.09)"
                  : "")
              );
            }),
          }}
        />
      </motion.div>
    </SwitchPrimitive.Root>
  );
}

export { Switch };
