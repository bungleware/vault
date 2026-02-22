import { Minus, Plus } from "lucide-react";
import { useState, useEffect, useRef } from "react";
import { cn } from "@/lib/utils";

interface BPMSelectorProps {
  value?: number;
  onChange: (bpm: number) => void;
  onClose: () => void;
}

export default function BPMSelector({
  value,
  onChange,
  onClose,
}: BPMSelectorProps) {
  const [bpm, setBpm] = useState<string>(value?.toString() || "120");
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    setBpm(value?.toString() || "120");
  }, [value]);

  useEffect(() => {
    if (inputRef.current) {
      inputRef.current.focus();
      inputRef.current.select();
    }
  }, []);

  const handleIncrement = () => {
    const currentBpm = parseInt(bpm) || 120;
    const newBpm = Math.min(currentBpm + 1, 999);
    setBpm(newBpm.toString());
    onChange(newBpm);
  };

  const handleDecrement = () => {
    const currentBpm = parseInt(bpm) || 120;
    const newBpm = Math.max(currentBpm - 1, 1);
    setBpm(newBpm.toString());
    onChange(newBpm);
  };

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value;
    setBpm(value);

    const numValue = parseInt(value);
    if (!isNaN(numValue) && numValue > 0 && numValue <= 999) {
      onChange(numValue);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Escape") {
      onClose();
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      handleIncrement();
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      handleDecrement();
    }
  };

  return (
    <div className="flex flex-col gap-3">
      <div className="inline-grid grid-cols-[auto_auto_auto] gap-0.5">
        <button
          type="button"
          onClick={handleDecrement}
          aria-label="Decrease BPM by one"
          className={cn(
            "flex h-8 w-8 items-center justify-center rounded-sm",
            "border border-white/10 bg-transparent p-2",
            "hover:bg-white/5 transition-colors duration-300",
          )}
        >
          <Minus className="size-3.5 text-white/60" />
        </button>

        <div className="relative h-8 w-28 overflow-hidden rounded-sm bg-[#2b2a2a]">
          <input
            ref={inputRef}
            type="number"
            inputMode="numeric"
            min="1"
            max="999"
            placeholder="120"
            value={bpm}
            onChange={handleInputChange}
            onKeyDown={handleKeyDown}
            className={cn(
              "h-full w-full appearance-none border-0 bg-transparent",
              "text-center text-white outline-none",
              "placeholder:text-white/40",
              "selection:bg-[#6a6a6a] selection:text-white",
              "[&::-webkit-outer-spin-button]:appearance-none",
              "[&::-webkit-inner-spin-button]:appearance-none",
            )}
            style={{
              fontFamily: '"IBM Plex Mono", monospace',
              MozAppearance: "textfield",
            }}
          />
        </div>

        <button
          type="button"
          onClick={handleIncrement}
          aria-label="Increase BPM by one"
          className={cn(
            "flex h-8 w-8 items-center justify-center rounded-sm",
            "border border-white/10 bg-transparent p-2",
            "hover:bg-white/5 transition-colors duration-300",
          )}
        >
          <Plus className="size-3.5 text-white/60" />
        </button>
      </div>
    </div>
  );
}
