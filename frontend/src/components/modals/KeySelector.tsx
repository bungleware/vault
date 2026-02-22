import { useState, useRef, useEffect } from "react";
import { cn } from "@/lib/utils";
import * as Tone from "tone";

interface KeySelectorProps {
  value?: string;
  onChange: (key: string) => void;
}

type Note =
  | "C"
  | "C#"
  | "Db"
  | "D"
  | "D#"
  | "Eb"
  | "E"
  | "F"
  | "F#"
  | "Gb"
  | "G"
  | "G#"
  | "Ab"
  | "A"
  | "A#"
  | "Bb"
  | "B";
type Mode = "major" | "minor";

const NOTES: Note[] = [
  "C",
  "C#",
  "Db",
  "D",
  "D#",
  "Eb",
  "E",
  "F",
  "F#",
  "Gb",
  "G",
  "G#",
  "Ab",
  "A",
  "A#",
  "Bb",
  "B",
];

const WHITE_KEYS: Note[] = ["C", "D", "E", "F", "G", "A", "B"];

const BLACK_KEY_GROUPS: { sharp: Note; flat: Note; position: number }[] = [
  { sharp: "C#", flat: "Db", position: 10.5 },
  { sharp: "D#", flat: "Eb", position: 24.5 },
  { sharp: "F#", flat: "Gb", position: 52.5 },
  { sharp: "G#", flat: "Ab", position: 66.5 },
  { sharp: "A#", flat: "Bb", position: 80.5 },
];

const parseKey = (keyString?: string): { note: Note; mode: Mode } | null => {
  if (!keyString) return null;

  const parts = keyString.trim().split(" ");
  if (parts.length !== 2) return null;

  const note = parts[0] as Note;
  const mode = parts[1].toLowerCase() as Mode;

  if (!NOTES.includes(note) || !["major", "minor"].includes(mode)) {
    return null;
  }

  return { note, mode };
};

const formatKey = (note: Note, mode: Mode): string => {
  return `${note} ${mode}`;
};

const getNoteConfig = (
  note: Note,
): { soundFile: string; semitoneOffset: number } => {
  const noteConfigs: Record<
    Note,
    { soundFile: string; semitoneOffset: number }
  > = {
    C: { soundFile: "/piano/piano-c3.mp3", semitoneOffset: -1 },
    "C#": { soundFile: "/piano/piano-c3.mp3", semitoneOffset: 0 },
    Db: { soundFile: "/piano/piano-c3.mp3", semitoneOffset: 0 },
    D: { soundFile: "/piano/piano-c3.mp3", semitoneOffset: 1 },
    "D#": { soundFile: "/piano/piano-c3.mp3", semitoneOffset: 2 },
    Eb: { soundFile: "/piano/piano-c3.mp3", semitoneOffset: 2 },
    E: { soundFile: "/piano/piano-e3.mp3", semitoneOffset: -1 },
    F: { soundFile: "/piano/piano-e3.mp3", semitoneOffset: 0 },
    "F#": { soundFile: "/piano/piano-e3.mp3", semitoneOffset: 1 },
    Gb: { soundFile: "/piano/piano-e3.mp3", semitoneOffset: 1 },
    G: { soundFile: "/piano/piano-e3.mp3", semitoneOffset: 2 },
    "G#": { soundFile: "/piano/piano-e3.mp3", semitoneOffset: 3 },
    Ab: { soundFile: "/piano/piano-e3.mp3", semitoneOffset: 3 },
    A: { soundFile: "/piano/piano-a3.mp3", semitoneOffset: 0 },
    "A#": { soundFile: "/piano/piano-a3.mp3", semitoneOffset: 1 },
    Bb: { soundFile: "/piano/piano-a3.mp3", semitoneOffset: 1 },
    B: { soundFile: "/piano/piano-a3.mp3", semitoneOffset: 2 },
  };
  return noteConfigs[note];
};

export default function KeySelector({ value, onChange }: KeySelectorProps) {
  const playersRef = useRef<Map<string, Tone.Player>>(new Map());
  const currentPlayerRef = useRef<Tone.Player | null>(null);

  const parsed = parseKey(value);
  const [selectedNote, setSelectedNote] = useState<Note | null>(
    parsed?.note || null,
  );
  const [selectedMode, setSelectedMode] = useState<Mode>(
    parsed?.mode || "major",
  );

  useEffect(() => {
    const soundFiles = [
      "/piano/piano-c3.mp3",
      "/piano/piano-e3.mp3",
      "/piano/piano-a3.mp3",
    ];

    soundFiles.forEach((file) => {
      if (!playersRef.current.has(file)) {
        const player = new Tone.Player(file).toDestination();
        player.volume.value = 0;
        player.fadeIn = 0.01;
        player.fadeOut = 0.05;
        playersRef.current.set(file, player);
      }
    });

    return () => {
      playersRef.current.forEach((player) => player.dispose());
      playersRef.current.clear();
    };
  }, []);

  const playNoteSound = async (note: Note) => {
    if (Tone.context.state !== "running") {
      await Tone.start();
    }

    if (currentPlayerRef.current) {
      currentPlayerRef.current.stop();
    }

    const { soundFile, semitoneOffset } = getNoteConfig(note);
    const player = playersRef.current.get(soundFile);

    if (player && player.loaded) {
      player.playbackRate = Math.pow(2, semitoneOffset / 12);
      player.start();
      currentPlayerRef.current = player;
    }
  };

  const playChord = async () => {
    if (!selectedNote) return;

    if (Tone.context.state !== "running") {
      await Tone.start();
    }

    if (currentPlayerRef.current) {
      currentPlayerRef.current.stop();
    }

    const { soundFile, semitoneOffset } = getNoteConfig(selectedNote);

    const thirdInterval = selectedMode === "major" ? 4 : 3;
    const fifthInterval = 7;

    const rootPlayer = new Tone.Player(soundFile).toDestination();
    const thirdPlayer = new Tone.Player(soundFile).toDestination();
    const fifthPlayer = new Tone.Player(soundFile).toDestination();

    [rootPlayer, thirdPlayer, fifthPlayer].forEach((p) => {
      p.volume.value = -3;
      p.fadeIn = 0.01;
      p.fadeOut = 0.05;
    });

    await Promise.all([Tone.loaded()]);

    rootPlayer.playbackRate = Math.pow(2, semitoneOffset / 12);
    thirdPlayer.playbackRate = Math.pow(
      2,
      (semitoneOffset + thirdInterval) / 12,
    );
    fifthPlayer.playbackRate = Math.pow(
      2,
      (semitoneOffset + fifthInterval) / 12,
    );

    const now = Tone.now();
    rootPlayer.start(now);
    thirdPlayer.start(now);
    fifthPlayer.start(now);

    setTimeout(() => {
      rootPlayer.dispose();
      thirdPlayer.dispose();
      fifthPlayer.dispose();
    }, 5000);
  };

  const playArpeggio = async () => {
    if (!selectedNote) return;

    if (Tone.context.state !== "running") {
      await Tone.start();
    }

    if (currentPlayerRef.current) {
      currentPlayerRef.current.stop();
    }

    const { soundFile, semitoneOffset } = getNoteConfig(selectedNote);

    const thirdInterval = selectedMode === "major" ? 4 : 3;
    const fifthInterval = 7;

    const rootPlayer = new Tone.Player(soundFile).toDestination();
    const thirdPlayer = new Tone.Player(soundFile).toDestination();
    const fifthPlayer = new Tone.Player(soundFile).toDestination();

    [rootPlayer, thirdPlayer, fifthPlayer].forEach((p) => {
      p.volume.value = 0;
      p.fadeIn = 0.01;
      p.fadeOut = 0.05;
    });

    await Promise.all([Tone.loaded()]);

    rootPlayer.playbackRate = Math.pow(2, semitoneOffset / 12);
    thirdPlayer.playbackRate = Math.pow(
      2,
      (semitoneOffset + thirdInterval) / 12,
    );
    fifthPlayer.playbackRate = Math.pow(
      2,
      (semitoneOffset + fifthInterval) / 12,
    );

    const now = Tone.now();
    const noteDelay = 0.15;
    rootPlayer.start(now);
    thirdPlayer.start(now + noteDelay);
    fifthPlayer.start(now + noteDelay * 2);

    setTimeout(() => {
      rootPlayer.dispose();
      thirdPlayer.dispose();
      fifthPlayer.dispose();
    }, 5000);
  };

  const handleNoteSelect = (note: Note) => {
    setSelectedNote(note);
    onChange(formatKey(note, selectedMode));
    playNoteSound(note);
  };

  const handleModeToggle = (mode: Mode) => {
    setSelectedMode(mode);
    if (selectedNote) {
      onChange(formatKey(selectedNote, mode));
    }
  };

  return (
    <div className="flex flex-col gap-4">
      <div className="flex gap-2">
        <button
          onClick={() => handleModeToggle("major")}
          className={cn(
            "flex-1 px-4 py-2 rounded-lg text-sm font-medium transition-all",
            selectedMode === "major"
              ? "bg-white text-black"
              : "bg-white/10 text-white/60 hover:bg-white/15",
          )}
        >
          Major
        </button>
        <button
          onClick={() => handleModeToggle("minor")}
          className={cn(
            "flex-1 px-4 py-2 rounded-lg text-sm font-medium transition-all",
            selectedMode === "minor"
              ? "bg-white text-black"
              : "bg-white/10 text-white/60 hover:bg-white/15",
          )}
        >
          Minor
        </button>
      </div>

      <div className="flex gap-2">
        <button
          onClick={playChord}
          className="flex-1 px-4 py-2 rounded-lg text-sm font-medium transition-all bg-white/10 text-white hover:bg-white/15"
        >
          Play Chord
        </button>
        <button
          onClick={playArpeggio}
          className="flex-1 px-4 py-2 rounded-lg text-sm font-medium transition-all bg-white/10 text-white hover:bg-white/15"
        >
          Play Arpeggio
        </button>
      </div>

      <div className="relative h-32 bg-[#0a0a0a] rounded-lg p-2 overflow-hidden">
        <div className="flex h-full gap-0.5">
          {WHITE_KEYS.map((note) => {
            const isSelected = selectedNote === note;
            return (
              <button
                key={note}
                onClick={() => handleNoteSelect(note)}
                className={cn(
                  "flex-1 rounded-md transition-all",
                  "text-xs font-medium flex items-end justify-center pb-2",
                  isSelected
                    ? "bg-blue-500 text-white shadow-lg shadow-blue-500/50"
                    : "bg-white/90 text-black/60 hover:bg-white",
                  "border border-white/10",
                )}
              >
                {note}
              </button>
            );
          })}

          {BLACK_KEY_GROUPS.map(({ sharp, flat, position }) => {
            const sharpSelected = selectedNote === sharp;
            const flatSelected = selectedNote === flat;

            return (
              <div
                key={`${sharp}-${flat}`}
                className="absolute h-16 w-8 z-10 flex flex-col"
                style={{
                  left: `${position}%`,
                }}
              >
                <button
                  onClick={() => handleNoteSelect(sharp)}
                  className={cn(
                    "flex-1 rounded-t-xs transition-all border-b border-white/10",
                    "text-[9px] font-medium flex items-center justify-center",
                    sharpSelected
                      ? "bg-blue-500 text-white shadow-lg shadow-blue-500/50 z-20"
                      : "bg-linear-to-b from-[#2a2a2a] to-[#252525] text-white/40 hover:from-[#3a3a3a] hover:to-[#2e2e2e]",
                    "border-l border-r border-t border-white/5",
                  )}
                >
                  {sharp}
                </button>

                <button
                  onClick={() => handleNoteSelect(flat)}
                  className={cn(
                    "flex-1 rounded-b-md transition-all",
                    "text-[9px] font-medium flex items-center justify-center",
                    flatSelected
                      ? "bg-blue-500 text-white shadow-lg shadow-blue-500/50 z-20"
                      : "bg-linear-to-b from-[#252525] to-[#1a1a1a] text-white/40 hover:from-[#2e2e2e] hover:to-[#2a2a2a]",
                    "border-l border-r border-b border-white/5",
                  )}
                >
                  {flat}
                </button>
              </div>
            );
          })}
        </div>
      </div>

      <div className="text-center text-sm text-white/60 font-mono min-h-5">
        {selectedNote ? formatKey(selectedNote, selectedMode) : ""}
      </div>
    </div>
  );
}
