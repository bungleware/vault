import { cn } from "@/lib/utils";

interface CDDiscBadgeProps {
  label: string;
  sublabel?: string;
  className?: string;
  editable?: boolean;
  placeholder?: string;
  onLabelChange?: (value: string) => void;
  onLabelKeyDown?: (e: React.KeyboardEvent) => void;
  colors?: string[];
  colorSpread?: number;
}

const getLuminance = (hex: string): number => {
  const rgb = parseInt(hex.slice(1), 16);
  const r = (rgb >> 16) & 0xff;
  const g = (rgb >> 8) & 0xff;
  const b = (rgb >> 0) & 0xff;

  const [rs, gs, bs] = [r, g, b].map((c) => {
    c = c / 255;
    return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
  });

  return 0.2126 * rs + 0.7152 * gs + 0.0722 * bs;
};

const getAverageLuminance = (colors: string[]): number => {
  const luminances = colors.map(getLuminance);
  return luminances.reduce((a, b) => a + b, 0) / luminances.length;
};

export default function CDDiscBadge({
  label,
  sublabel,
  className,
  editable = false,
  placeholder,
  onLabelChange,
  onLabelKeyDown,
  colors,
  colorSpread = 50,
}: CDDiscBadgeProps) {
  const defaultColors = ["#8FC7FF", "#4CF3FF", "#BFF9FF"];
  const discColors = colors && colors.length > 0 ? colors : defaultColors;

  const avgLuminance = getAverageLuminance(discColors);
  const bgLightness = Math.round(85 + avgLuminance * 15);
  const backgroundColor = `hsl(0, 0%, ${bgLightness}%)`;

  const createConicGradient = (colors: string[], spread: number) => {
    const baseSpread = 10 + (spread / 100) * 50;

    const start = 157.5;
    const colorStart = 180;

    if (colors.length === 1) {
      return `conic-gradient(from 90deg at 50% 50%,
        rgba(255, 255, 255, 0.00) ${start}deg,
        ${colors[0]} ${colorStart}deg,
        ${colors[0]}DD ${colorStart + baseSpread * 0.5}deg,
        ${colors[0]}AA ${colorStart + baseSpread}deg,
        ${colors[0]} ${colorStart + baseSpread * 1.8}deg,
        rgba(255, 255, 255, 0.00) ${start + 170}deg)`;
    } else if (colors.length === 2) {
      return `conic-gradient(from 90deg at 50% 50%,
        rgba(255, 255, 255, 0.00) ${start}deg,
        ${colors[0]} ${colorStart}deg,
        ${colors[1]} ${colorStart + baseSpread}deg,
        ${colors[0]}DD ${colorStart + baseSpread * 1.5}deg,
        ${colors[1]}DD ${colorStart + baseSpread * 2.2}deg,
        rgba(255, 255, 255, 0.00) ${start + 170}deg)`;
    } else {
      return `conic-gradient(from 90deg at 50% 50%,
        rgba(255, 255, 255, 0.00) ${start}deg,
        ${colors[0]} ${colorStart}deg,
        ${colors[1]} ${colorStart + baseSpread * 0.6}deg,
        ${colors[2]} ${colorStart + baseSpread * 1.2}deg,
        ${colors[0]}DD ${colorStart + baseSpread * 2}deg,
        rgba(255, 255, 255, 0.00) ${start + 170}deg)`;
    }
  };

  const conicGradient = createConicGradient(discColors, colorSpread);
  return (
    <div className={cn("relative flex items-center justify-center", className)}>
      <svg className="absolute w-0 h-0">
        <defs>
          <filter id="cd-noise-badge">
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

      <div className="relative bg-linear-to-b from-[#262626] to-[#201f1f] border border-[#353333] rounded-[64px] w-[305px] h-[375px] flex flex-col items-center justify-center">
        <div className="absolute top-0 left-0 pl-8 pt-8 text-white text-[15px] font-light text-center">
          {"{v}"}
        </div>

        <div className="relative w-64 h-64  -translate-y-8">
          <div
            className="absolute inset-0 rounded-full border-2 border-[#c6c6c6]"
            style={{ backgroundColor }}
          />

          <div className="absolute inset-1.5 rounded-full overflow-hidden">
            <div
              className="absolute inset-0 rounded-full"
              style={{ backgroundColor }}
            />
            <div className="absolute inset-0 blur-[2px]">
              <div
                key="cd-spin-layer-1"
                className="absolute inset-0 rounded-full opacity-100 animate-spin"
                style={{
                  animationDuration: "30s",
                  mixBlendMode: "multiply",
                  background: conicGradient,
                  willChange: "transform",
                  transformStyle: "preserve-3d",
                }}
              />

              <div
                key="cd-spin-layer-2"
                className="absolute inset-0 rounded-full opacity-100 rotate-180 animate-spin"
                style={{
                  animationDuration: "30s",
                  mixBlendMode: "multiply",
                  background: conicGradient,
                  willChange: "transform",
                  transformStyle: "preserve-3d",
                }}
              />
            </div>
            <div className="absolute inset-0 rounded-full border-black border-4 bg-blend-color-burn opacity-7" />
            <div
              key="cd-spin-noise"
              className="absolute inset-0 rounded-full opacity-100 animate-spin"
              style={{
                animationDuration: "2s",
                filter: "url(#cd-noise-badge)",
                willChange: "transform",
                transformStyle: "preserve-3d",
              }}
            />

            <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-20 h-20 z-10 flex items-center justify-center border-black/20 border-[0.5px] rounded-full">
              <div className="w-full h-full rounded-full border-18 border-white flex items-center justify-center">
                <div className="w-12 h-11 rounded-full border-black/20 border-[0.5px] flex items-center justify-center bg-white/50">
                  <div className="w-7.5 h-7.5 rounded-full bg-white border-black/20 border-[0.5px]" />
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="absolute bottom-5 left-1/2 -translate-x-1/2 flex flex-col items-center gap-0">
          <div className="flex items-center gap-2">
            {editable ? (
              <input
                type="text"
                value={label}
                placeholder={placeholder}
                onChange={(e) => onLabelChange?.(e.target.value)}
                onKeyDown={onLabelKeyDown}
                className="text-white text-lg font-medium bg-transparent border-none outline-none text-center cursor-text px-2 min-w-[100px] placeholder:text-[#848484]"
                style={{ caretColor: "white" }}
                autoFocus
              />
            ) : (
              <p className="text-white text-lg font-medium">{label}</p>
            )}
          </div>
          {sublabel && (
            <p className="text-white text-[11px] font-extralight font-['IBM_Plex_Mono']">
              {sublabel}
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
