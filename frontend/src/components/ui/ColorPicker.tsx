"use client";

import { useEffect, useRef, useState } from "react";
import { memo } from "react";

function hslToHex(h: number, s: number, l: number) {
  l /= 100;
  s /= 100;
  const k = (n: number) => (n + h / 30) % 12;
  const a = s * Math.min(l, 1 - l);
  const f = (n: number) =>
    l - a * Math.max(-1, Math.min(Math.min(k(n) - 3, 9 - k(n)), 1));
  return (
    "#" +
    [f(0), f(8), f(4)]
      .map((x) =>
        Math.round(x * 255)
          .toString(16)
          .padStart(2, "0"),
      )
      .join("")
  );
}

function hexToHsl(hex: string): { h: number; s: number; l: number } {
  const r = parseInt(hex.slice(1, 3), 16) / 255;
  const g = parseInt(hex.slice(3, 5), 16) / 255;
  const b = parseInt(hex.slice(5, 7), 16) / 255;

  const max = Math.max(r, g, b);
  const min = Math.min(r, g, b);
  const l = (max + min) / 2;

  if (max === min) {
    return { h: 0, s: 0, l: l * 100 };
  }

  const d = max - min;
  const s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
  let h = 0;

  switch (max) {
    case r:
      h = (g - b) / d + (g < b ? 6 : 0);
      break;
    case g:
      h = (b - r) / d + 2;
      break;
    case b:
      h = (r - g) / d + 4;
      break;
  }
  h /= 6;

  return { h: h * 360, s: s * 100, l: l * 100 };
}

interface ColorPickerProps {
  size?: number;
  padding?: number;
  bulletRadius?: number;
  spreadFactor?: number;
  minSpread?: number;
  maxSpread?: number;
  minLight?: number;
  maxLight?: number;
  showColorWheel?: boolean;
  numPoints?: number;
  initialAngle?: number;
  initialRadius?: number;
  onColorChange?: (colors: string[]) => void;
}

const ColorPicker = memo(
  ({
    size = 280,
    padding = 20,
    bulletRadius = 24,
    spreadFactor = 0.4,
    minSpread = Math.PI / 1.5,
    maxSpread = Math.PI / 3,
    minLight = 15,
    maxLight = 90,
    showColorWheel = false,
    numPoints = 1,
    initialAngle,
    initialRadius,
    onColorChange,
  }: ColorPickerProps) => {
    const RADIUS = size / 2 - padding;

    const [angle, setAngle] = useState(initialAngle ?? -Math.PI / 2);
    const [radius, setRadius] = useState(initialRadius ?? RADIUS * 0.7);
    const [drag, setDrag] = useState(false);

    const ref = useRef<HTMLCanvasElement>(null);

    const hue = (angle * 180) / Math.PI;
    const light = maxLight * (radius / RADIUS);
    const color = hslToHex(hue, 100, light);

    const normalizedRadius = radius / RADIUS;
    const spread =
      (minSpread + (maxSpread - minSpread) * Math.pow(normalizedRadius, 3)) *
      spreadFactor;

    const bx1 = size / 2 + Math.cos(angle - spread) * radius;
    const by1 = size / 2 + Math.sin(angle - spread) * radius;
    const bx2 = size / 2 + Math.cos(angle + spread) * radius;
    const by2 = size / 2 + Math.sin(angle + spread) * radius;

    const angle1 = angle - spread;
    const angle2 = angle + spread;
    const hue1 = (angle1 * 180) / Math.PI;
    const hue2 = (angle2 * 180) / Math.PI;
    const light1 = maxLight * (radius / RADIUS);
    const light2 = maxLight * (radius / RADIUS);
    const color1 = hslToHex(hue1, 100, light1);
    const color2 = hslToHex(hue2, 100, light2);

    useEffect(() => {
      const ctx = ref.current!.getContext("2d")!;
      ctx.clearRect(0, 0, size, size);

      ctx.beginPath();
      ctx.arc(size / 2, size / 2, RADIUS, 0, Math.PI * 2);
      ctx.clip();

      for (let r = 0; r <= RADIUS; r++) {
        for (let a = 0; a < 360; a += 1) {
          const rad = (a * Math.PI) / 180;
          const x = size / 2 + Math.cos(rad) * r;
          const y = size / 2 + Math.sin(rad) * r;
          const lightness = minLight + (maxLight - minLight) * (r / RADIUS);
          ctx.beginPath();
          ctx.strokeStyle = hslToHex(a, 100, lightness);
          ctx.moveTo(x, y);
          ctx.lineTo(x + 1, y + 1);
          ctx.stroke();
        }
      }
    }, [size, RADIUS, minLight, maxLight]);

    const onColorChangeRef = useRef(onColorChange);
    onColorChangeRef.current = onColorChange;

    useEffect(() => {
      const colors =
        numPoints === 1
          ? [color]
          : numPoints === 2
            ? [color2, color]
            : [color2, color, color1];
      onColorChangeRef.current?.(colors);
    }, [color, color1, color2, numPoints]);

    function setFromPointer(e: React.PointerEvent) {
      const rect = ref.current!.getBoundingClientRect();
      const x = e.clientX - rect.left - size / 2;
      const y = e.clientY - rect.top - size / 2;
      let r = Math.sqrt(x * x + y * y);
      let a = Math.atan2(y, x);
      if (a < 0) a += 2 * Math.PI;
      r = Math.max(0, Math.min(RADIUS, r));
      setAngle(a);
      setRadius(r);
    }

    function onPointerDown(e: React.PointerEvent) {
      setDrag(true);
      setFromPointer(e);
      (e.target as HTMLElement).setPointerCapture(e.pointerId);
    }
    function onPointerMove(e: React.PointerEvent) {
      if (!drag) return;
      setFromPointer(e);
    }
    function onPointerUp() {
      setDrag(false);
    }

    const bx = size / 2 + Math.cos(angle) * radius;
    const by = size / 2 + Math.sin(angle) * radius;

    return (
      <div>
        <div
          style={{
            width: size,
            height: size,
          }}
          className="select-none relative"
        >
          <canvas
            ref={ref}
            width={size}
            height={size}
            className={`rounded-full ${!showColorWheel && "opacity-0"}`}
          />

          {numPoints >= 2 && (
            <div
              className="absolute rounded-full border-2 border-white/80 shadow pointer-events-none opacity-90 z-20"
              style={{
                left: bx2 - bulletRadius / 1.7,
                top: by2 - bulletRadius / 1.7,
                width: bulletRadius * 1.2,
                height: bulletRadius * 1.2,
                background: color2,
              }}
            />
          )}

          <div
            className="absolute rounded-full border-3 border-white/90 shadow cursor-grab touch-none z-30"
            style={{
              left: bx - bulletRadius * 0.7,
              top: by - bulletRadius * 0.7,
              width: bulletRadius * 1.4,
              height: bulletRadius * 1.4,
              background: color,
            }}
            onPointerDown={onPointerDown}
            onPointerMove={onPointerMove}
            onPointerUp={onPointerUp}
            onPointerLeave={onPointerUp}
          />

          {numPoints >= 3 && (
            <div
              className="absolute rounded-full border-2 border-white/80 shadow pointer-events-none opacity-90 z-20"
              style={{
                left: bx1 - bulletRadius / 1.7,
                top: by1 - bulletRadius / 1.7,
                width: bulletRadius * 1.2,
                height: bulletRadius * 1.2,
                background: color1,
              }}
            />
          )}
        </div>
      </div>
    );
  },
);

ColorPicker.displayName = "ColorPicker";

export default ColorPicker;
export { hexToHsl };
