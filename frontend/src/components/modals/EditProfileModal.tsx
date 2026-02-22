import { useState, useEffect, useCallback, useMemo } from "react";
import { createPortal } from "react-dom";
import { AnimatePresence, motion } from "motion/react";
import { X } from "lucide-react";
import { Button } from "@/components/ui/button";
import ColorPicker, { hexToHsl } from "@/components/ui/ColorPicker";
import DotPattern from "@/components/ui/DotPattern";
import CDDiscBadge from "@/components/CDDiscBadge";
import { cn } from "@/lib/utils";
import { updatePreferences } from "@/api/preferences";

interface EditProfileModalProps {
  isOpen: boolean;
  onClose: () => void;
  currentUsername: string;
  userCreatedAt?: string;
  currentDiscColors?: string[];
  currentColorSpread?: number;
  currentGradientSpread?: number;
  currentColorShiftRotation?: number;
  onSave: (username: string) => Promise<void>;
}

function calculateInitialAngleAndRadius(
  color: string,
  maxLight: number = 90,
  RADIUS: number = 120,
): { angle: number; radius: number } {
  const hsl = hexToHsl(color);
  const angle = (hsl.h * Math.PI) / 180;
  const radius = (hsl.l / maxLight) * RADIUS;
  return { angle, radius };
}

function applyColorShift(colors: string[], shiftAmount: number): string[] {
  if (colors.length === 0 || shiftAmount === 0) return colors;
  const normalizedShift =
    ((shiftAmount % colors.length) + colors.length) % colors.length;
  return [
    ...colors.slice(-normalizedShift),
    ...colors.slice(0, -normalizedShift),
  ];
}

export default function EditProfileModal({
  isOpen,
  onClose,
  currentUsername,
  userCreatedAt,
  currentDiscColors,
  currentColorSpread,
  currentGradientSpread,
  currentColorShiftRotation,
  onSave,
}: EditProfileModalProps) {
  const defaultColors = ["#8FC7FF", "#4CF3FF", "#BFF9FF"];
  const PICKER_SIZE = 280;
  const PICKER_PADDING = 20;
  const PICKER_RADIUS = PICKER_SIZE / 2 - PICKER_PADDING;
  const MAX_LIGHT = 90;

  const [username, setUsername] = useState(currentUsername);
  const [discColors, setDiscColors] = useState<string[]>(defaultColors);
  const [colorShift, setColorShift] = useState(0);
  const [numPoints, setNumPoints] = useState(3);
  const [colorSpread, setColorSpread] = useState(50);
  const [gradientSpread, setGradientSpread] = useState(40);
  const [isSaving, setIsSaving] = useState(false);

  const initialAngleAndRadius = useMemo(() => {
    if (!currentDiscColors || currentDiscColors.length === 0) {
      return undefined;
    }
    const shift = currentColorShiftRotation ?? 0;
    const unshiftAmount =
      currentDiscColors.length - (shift % currentDiscColors.length);
    const unshiftedColors = applyColorShift(currentDiscColors, unshiftAmount);
    const mainColor = unshiftedColors[Math.floor(unshiftedColors.length / 2)];
    return calculateInitialAngleAndRadius(mainColor, MAX_LIGHT, PICKER_RADIUS);
  }, [currentDiscColors, currentColorShiftRotation, MAX_LIGHT, PICKER_RADIUS]);

  useEffect(() => {
    setUsername(currentUsername);
    if (currentDiscColors && currentDiscColors.length > 0) {
      setDiscColors(currentDiscColors);
      setNumPoints(Math.min(currentDiscColors.length, 3));
    } else {
      setDiscColors(defaultColors);
      setNumPoints(3);
    }
    setColorSpread(currentColorSpread ?? 50);
    setGradientSpread(currentGradientSpread ?? 40);
    setColorShift(currentColorShiftRotation ?? 0);
  }, [
    currentUsername,
    currentDiscColors,
    currentColorSpread,
    currentGradientSpread,
    currentColorShiftRotation,
    isOpen,
  ]);

  const handleCancel = useCallback(() => {
    setUsername(currentUsername);
    onClose();
  }, [currentUsername, onClose]);

  const handleColorChange = useCallback(
    (colors: string[]) => {
      setDiscColors(applyColorShift(colors, colorShift));
    },
    [colorShift],
  );

  const handleShiftColors = useCallback(() => {
    setColorShift((prev) => (prev + 1) % Math.max(numPoints, 1));
    setDiscColors((prev) => {
      const active = prev.slice(0, numPoints);
      if (active.length <= 1) return prev;
      return [...active.slice(-1), ...active.slice(0, -1)];
    });
  }, [numPoints]);

  const handleSave = useCallback(async () => {
    const colorsToSave = discColors.slice(0, numPoints);
    const colorsChanged =
      JSON.stringify(colorsToSave) !==
      JSON.stringify(currentDiscColors || defaultColors);
    const colorSpreadChanged = colorSpread !== (currentColorSpread ?? 50);
    const gradientSpreadChanged =
      gradientSpread !== (currentGradientSpread ?? 40);
    const usernameChanged = username !== currentUsername;

    if (
      !usernameChanged &&
      !colorsChanged &&
      !colorSpreadChanged &&
      !gradientSpreadChanged
    ) {
      onClose();
      return;
    }

    setIsSaving(true);
    try {
      if (
        colorsChanged ||
        colorSpreadChanged ||
        gradientSpreadChanged ||
        colorShift !== (currentColorShiftRotation ?? 0)
      ) {
        await updatePreferences({
          disc_colors: colorsToSave,
          color_spread: colorSpread,
          gradient_spread: gradientSpread,
          color_shift_rotation: colorShift,
        });
      }

      if (usernameChanged) {
        await onSave(username.trim() || "User");
      } else if (colorsChanged || colorSpreadChanged || gradientSpreadChanged) {
        await onSave(currentUsername);
      }

      onClose();
    } catch (error) {
      console.error("Failed to save profile:", error);
    } finally {
      setIsSaving(false);
    }
  }, [
    discColors,
    numPoints,
    currentDiscColors,
    defaultColors,
    colorSpread,
    currentColorSpread,
    gradientSpread,
    currentGradientSpread,
    username,
    currentUsername,
    onClose,
    onSave,
  ]);

  useEffect(() => {
    if (!isOpen) return;

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        handleCancel();
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isOpen, handleCancel]);

  return createPortal(
    <>
      <AnimatePresence>
        {isOpen && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.15, ease: [0.4, 0, 0.2, 1] }}
            className="fixed inset-0 z-1000 bg-black/80"
            onClick={handleCancel}
          />
        )}
      </AnimatePresence>

      <AnimatePresence>
        {isOpen && (
          <div className="fixed inset-0 z-1000 flex items-center justify-center p-0 md:p-4 pointer-events-none">
            <div className="flex flex-col md:flex-row items-center md:items-start gap-0 md:gap-8 pointer-events-auto max-h-full md:max-h-none overflow-y-auto md:overflow-visible">
              <motion.div
                layoutId="profile-disc-badge"
                className="hidden md:flex flex-col items-center"
                initial={false}
                transition={{ type: "spring", stiffness: 300, damping: 30 }}
              >
                <CDDiscBadge
                  label={username}
                  placeholder="User"
                  sublabel={
                    userCreatedAt
                      ? `Created ${new Date(userCreatedAt).toLocaleDateString(
                          "en-US",
                          {
                            year: "numeric",
                            month: "short",
                            day: "numeric",
                          },
                        )}`
                      : "Vault Instance"
                  }
                  colors={discColors.slice(0, numPoints)}
                  colorSpread={colorSpread}
                  editable
                  onLabelChange={setUsername}
                  onLabelKeyDown={(e) => {
                    if (e.key === "Enter") {
                      handleSave();
                    }
                  }}
                />
              </motion.div>

              <motion.div
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: 20 }}
                transition={{
                  type: "spring",
                  stiffness: 400,
                  damping: 35,
                  mass: 0.8,
                }}
                className="relative z-10 w-full max-w-full md:max-w-[500px] min-h-[100dvh] md:min-h-0 border-0 md:border border-[#292828] rounded-none md:rounded-[34px] shadow-2xl overflow-hidden"
                style={{
                  background: "linear-gradient(0deg, #151515 0%, #1D1D1D 100%)",
                }}
                onClick={(e) => e.stopPropagation()}
              >
                <div className="p-6">
                  <div className="flex items-center justify-between mb-6">
                    <h2 className="text-2xl font-medium text-white">
                      Edit Profile
                    </h2>
                    <button
                      onClick={handleCancel}
                      className="text-[#848484] hover:text-white transition-colors"
                    >
                      <X className="size-5" />
                    </button>
                  </div>

                  <div className="space-y-6">
                    <div className="md:hidden">
                      <label className="text-[#848484] text-sm mb-2 block">
                        Username
                      </label>
                      <input
                        type="text"
                        value={username}
                        placeholder="User"
                        onChange={(e) => setUsername(e.target.value)}
                        onKeyDown={(e) => {
                          if (e.key === "Enter") handleSave();
                        }}
                        className="w-full bg-[#191919] border border-[#353333] rounded-[12px] px-4 py-3 text-white text-base outline-none focus:border-[#555] transition-colors placeholder:text-[#484848]"
                        style={{ caretColor: "white" }}
                      />
                    </div>

                    <div>
                      <label className="text-[#848484] text-sm mb-2 block">
                        Disc Colors
                      </label>
                      <div className="bg-[#191919] border border-[#353333] rounded-[12px] p-6 relative">
                        <DotPattern
                          width={10}
                          height={10}
                          className={cn(
                            "mask-[radial-gradient(200px_circle_at_50%_140px,white,transparent)] z-0",
                          )}
                        />
                        <div className="flex flex-col items-center gap-4 relative z-10">
                          <ColorPicker
                            size={280}
                            padding={20}
                            bulletRadius={24}
                            spreadFactor={gradientSpread / 100}
                            numPoints={numPoints}
                            showColorWheel={false}
                            initialAngle={initialAngleAndRadius?.angle}
                            initialRadius={initialAngleAndRadius?.radius}
                            onColorChange={handleColorChange}
                          />

                          <div className="flex gap-2 items-center">
                            <button
                              onClick={() =>
                                setNumPoints(Math.max(1, numPoints - 1))
                              }
                              disabled={numPoints <= 1}
                              className="text-[#848484] disabled:text-[#484848] size-7 rounded text-2xl hover:bg-[#252525] disabled:hover:bg-transparent transition-all cursor-pointer disabled:cursor-not-allowed flex items-center justify-center"
                            >
                              -
                            </button>
                            <span className="text-[#848484] text-sm w-16 text-center">
                              {numPoints} {numPoints === 1 ? "color" : "colors"}
                            </span>
                            <button
                              onClick={() =>
                                setNumPoints(Math.min(3, numPoints + 1))
                              }
                              disabled={numPoints >= 3}
                              className="text-[#848484] disabled:text-[#484848] size-7 rounded text-2xl hover:bg-[#252525] disabled:hover:bg-transparent transition-all cursor-pointer disabled:cursor-not-allowed flex items-center justify-center"
                            >
                              +
                            </button>
                            <div className="w-px h-5 bg-[#353333] mx-1"></div>
                            <button
                              onClick={handleShiftColors}
                              disabled={numPoints <= 1}
                              title="Rotate color order"
                              className="text-[#848484] disabled:text-[#484848] px-3 py-1 rounded flex gap-1 items-center hover:bg-[#252525] disabled:hover:bg-transparent transition-all cursor-pointer disabled:cursor-not-allowed"
                            >
                              {Array.from({ length: numPoints }).map((_, i) => (
                                <div
                                  key={i}
                                  className={`w-2 h-2 rounded-full transition-colors ${
                                    i === colorShift % numPoints
                                      ? "bg-white"
                                      : "bg-[#484848]"
                                  }`}
                                />
                              ))}
                            </button>
                          </div>

                          <div className="w-full flex flex-col gap-2">
                            <div className="flex items-center justify-between">
                              <span className="text-[#848484] text-xs">
                                Gradient Spread
                              </span>
                              <span className="text-[#848484] text-xs">
                                {gradientSpread}%
                              </span>
                            </div>
                            <input
                              type="range"
                              min="0"
                              max="200"
                              value={gradientSpread}
                              onChange={(e) =>
                                setGradientSpread(Number(e.target.value))
                              }
                              className="w-full h-1 bg-[#2a2a2a] rounded-lg appearance-none cursor-pointer [&::-webkit-slider-thumb]:appearance-none [&::-webkit-slider-thumb]:w-3 [&::-webkit-slider-thumb]:h-3 [&::-webkit-slider-thumb]:rounded-full [&::-webkit-slider-thumb]:bg-white [&::-moz-range-thumb]:w-3 [&::-moz-range-thumb]:h-3 [&::-moz-range-thumb]:rounded-full [&::-moz-range-thumb]:bg-white [&::-moz-range-thumb]:border-0"
                            />
                            <div className="flex items-center justify-between text-[10px] text-[#5a5a5a]">
                              <span>Narrow</span>
                              <span>Wide</span>
                            </div>
                          </div>

                          <div className="w-full flex flex-col gap-2">
                            <div className="flex items-center justify-between">
                              <span className="text-[#848484] text-xs">
                                Color Spread
                              </span>
                              <span className="text-[#848484] text-xs">
                                {colorSpread}%
                              </span>
                            </div>
                            <input
                              type="range"
                              min="0"
                              max="100"
                              value={colorSpread}
                              onChange={(e) =>
                                setColorSpread(Number(e.target.value))
                              }
                              className="w-full h-1 bg-[#2a2a2a] rounded-lg appearance-none cursor-pointer [&::-webkit-slider-thumb]:appearance-none [&::-webkit-slider-thumb]:w-3 [&::-webkit-slider-thumb]:h-3 [&::-webkit-slider-thumb]:rounded-full [&::-webkit-slider-thumb]:bg-white [&::-moz-range-thumb]:w-3 [&::-moz-range-thumb]:h-3 [&::-moz-range-thumb]:rounded-full [&::-moz-range-thumb]:bg-white [&::-moz-range-thumb]:border-0"
                            />
                            <div className="flex items-center justify-between text-[10px] text-[#5a5a5a]">
                              <span>Tight</span>
                              <span>Wide</span>
                            </div>
                          </div>

                          <div
                            className="w-full h-12 rounded"
                            style={{
                              background:
                                numPoints === 1
                                  ? discColors[0]
                                  : numPoints === 2
                                    ? `linear-gradient(90deg, ${discColors[0]} 0%, ${discColors[1]} 100%)`
                                    : `linear-gradient(90deg, ${discColors[0]} 0%, ${discColors[1]} 50%, ${discColors[2]} 100%)`,
                            }}
                          />
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-4 pt-2">
                      <Button
                        onClick={handleCancel}
                        className="flex-1 bg-[#1e1e1e] border border-[#2e2e2e] hover:bg-[#252525] active:bg-[#2a2a2a] text-white rounded-xl h-[41px]"
                        disabled={isSaving}
                      >
                        <span className="text-sm font-semibold">Cancel</span>
                      </Button>
                      <Button
                        onClick={handleSave}
                        variant={"hot"}
                        className="flex-1 bg-[#e0e0e0] hover:bg-[#d5d5d5] active:bg-[#cacaca] text-black rounded-xl h-[41px]"
                        disabled={isSaving || !username.trim()}
                      >
                        <span className="text-sm font-semibold">Save</span>
                      </Button>
                    </div>
                  </div>
                </div>
              </motion.div>
            </div>
          </div>
        )}
      </AnimatePresence>
    </>,
    document.body,
  );
}
