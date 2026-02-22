import { useState, useEffect, useRef, useCallback } from "react";
import { motion } from "motion/react";
import { X } from "lucide-react";
import type { Track, Project, Note } from "@/types/api";
import {
  useTrackNotes,
  useProjectNotes,
  useUpsertTrackNote,
  useUpsertProjectNote,
} from "@/hooks/useNotes";
import { useAuth } from "@/contexts/AuthContext";
import { toast } from "@/routes/__root";
import { Button } from "@/components/ui/button";

interface TrackNotesPanelProps {
  mode: "track";
  selectedTrack: Track | null;
  project?: never;
  onClose: () => void;
}

interface ProjectNotesPanelProps {
  mode: "project";
  project: Project | null;
  selectedTrack?: never;
  onClose: () => void;
}

type NotesPanelProps = TrackNotesPanelProps | ProjectNotesPanelProps;

function NoteItem({ note }: { note: Note }) {
  return (
    <div className="bg-linear-to-b from-[#232323] to-[#201f1f] border border-[#353333] rounded-2xl overflow-hidden">
      <div className="flex items-center gap-2.5 px-4 py-3 border-b border-white/5">
        <div className="size-6 rounded-full bg-white/10 flex items-center justify-center text-xs font-semibold text-white/70 shrink-0">
          {note.author_name[0]?.toUpperCase()}
        </div>
        <span className="text-sm text-white/60">@{note.author_name}</span>
      </div>
      <div className="px-4 py-4">
        <p
          className="text-white/90 text-sm whitespace-pre-wrap leading-relaxed"
          style={{ fontFamily: '"IBM Plex Mono", monospace' }}
        >
          {note.content || (
            <span className="text-white/30 italic">No notes yet...</span>
          )}
        </p>
      </div>
    </div>
  );
}

function EditableNote({
  initialContent,
  authorName,
  onSave,
  entityId,
}: {
  initialContent: string;
  authorName: string;
  onSave: (content: string) => void;
  entityId: string;
}) {
  const [content, setContent] = useState(initialContent);
  const saveTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const lastEntityIdRef = useRef<string>(entityId);
  const hasUserEditedRef = useRef<boolean>(false);
  const lastSavedContentRef = useRef<string>(initialContent);
  const isInitialMountRef = useRef<boolean>(true);
  const lastInitialContentRef = useRef<string>(initialContent);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    const el = textareaRef.current;
    if (!el) return;
    el.style.height = "auto";
    el.style.height = `${el.scrollHeight}px`;
  }, [content]);

  useEffect(() => {
    if (lastEntityIdRef.current !== entityId) {
      lastEntityIdRef.current = entityId;
      hasUserEditedRef.current = false;
      lastSavedContentRef.current = initialContent;
      lastInitialContentRef.current = initialContent;
      isInitialMountRef.current = true;
      setContent(initialContent);
    }
  }, [entityId, initialContent]);

  useEffect(() => {
    if (lastEntityIdRef.current === entityId) {
      if (isInitialMountRef.current) {
        if (initialContent && initialContent !== content) {
          setContent(initialContent);
          lastSavedContentRef.current = initialContent;
          lastInitialContentRef.current = initialContent;
          isInitialMountRef.current = false;
          return;
        } else if (initialContent === content) {
          isInitialMountRef.current = false;
          lastInitialContentRef.current = initialContent;
          return;
        }
        lastInitialContentRef.current = initialContent;
        return;
      }

      if (!hasUserEditedRef.current && initialContent !== content) {
        if (initialContent !== lastInitialContentRef.current) {
          setContent(initialContent);
          lastSavedContentRef.current = initialContent;
          lastInitialContentRef.current = initialContent;
        }
      } else if (initialContent === content && hasUserEditedRef.current) {
        hasUserEditedRef.current = false;
        lastSavedContentRef.current = initialContent;
        lastInitialContentRef.current = initialContent;
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialContent, entityId]);

  const onSaveRef = useRef(onSave);
  useEffect(() => {
    onSaveRef.current = onSave;
  }, [onSave]);

  useEffect(() => {
    if (content === initialContent) {
      return;
    }

    if (saveTimeoutRef.current) {
      clearTimeout(saveTimeoutRef.current);
    }

    saveTimeoutRef.current = setTimeout(() => {
      onSaveRef.current(content);
      lastSavedContentRef.current = content;
    }, 1000);

    return () => {
      if (saveTimeoutRef.current) {
        clearTimeout(saveTimeoutRef.current);
      }
      if (content !== initialContent) {
        onSaveRef.current(content);
      }
    };
  }, [content, initialContent]);

  return (
    <div className="bg-linear-to-b from-[#232323] to-[#201f1f] border border-[#353333] rounded-2xl overflow-hidden">
      <div className="flex items-center justify-between gap-2.5 px-4 py-3 border-b border-white/5">
        <div className="flex items-center gap-2.5">
          <div className="size-6 rounded-full bg-white/10 flex items-center justify-center text-xs font-semibold text-white/70 shrink-0">
            {authorName[0]?.toUpperCase()}
          </div>
          <span className="text-sm text-white/60">@{authorName}</span>
        </div>
        <span className="text-xs text-white/25 select-none">Your note</span>
      </div>
      <div className="px-4 py-4">
        <textarea
          ref={textareaRef}
          value={content}
          onChange={(e) => {
            hasUserEditedRef.current = true;
            setContent(e.target.value);
          }}
          placeholder="Write your note..."
          className="w-full bg-transparent border-none resize-none text-white/90 placeholder:text-white/25 focus:outline-none focus:ring-0 text-sm leading-relaxed min-h-30 max-h-80 overflow-y-auto"
          style={{ fontFamily: '"IBM Plex Mono", monospace' }}
        />
      </div>
    </div>
  );
}

export default function NotesPanel(props: NotesPanelProps) {
  const { mode, onClose } = props;
  const selectedTrack = mode === "track" ? props.selectedTrack : null;
  const project = mode === "project" ? props.project : null;

  const { user } = useAuth();
  const upsertTrackNote = useUpsertTrackNote();
  const upsertProjectNote = useUpsertProjectNote();

  const currentId =
    mode === "track" ? selectedTrack?.public_id : project?.public_id;
  const currentTitle = mode === "track" ? selectedTrack?.title : project?.name;

  const { data: trackNotes = [], isLoading: trackNotesLoading } = useTrackNotes(
    mode === "track" ? currentId : null,
  );
  const { data: projectNotes = [], isLoading: projectNotesLoading } =
    useProjectNotes(mode === "project" ? currentId : null);

  const notes = mode === "track" ? trackNotes : projectNotes;
  const isLoading = mode === "track" ? trackNotesLoading : projectNotesLoading;

  const myNote = notes.find((n) => n.is_owner);
  const otherNotes = notes.filter((n) => !n.is_owner);

  const saveNote = useCallback(
    async (content: string) => {
      if (!currentId || !user?.username) return;

      try {
        if (mode === "track") {
          await upsertTrackNote.mutateAsync({
            trackId: currentId,
            content,
            authorName: user.username,
          });
        } else {
          await upsertProjectNote.mutateAsync({
            projectId: currentId,
            content,
            authorName: user.username,
          });
        }
      } catch (error) {
        console.error("Failed to save note:", error);
        toast.error("Failed to save note");
      }
    },
    [currentId, user?.username, mode, upsertTrackNote, upsertProjectNote],
  );

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        onClose();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [onClose]);

  if (!currentId) {
    return (
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="flex flex-col h-full items-center justify-center text-muted-foreground"
      >
        <p className="text-sm">
          {mode === "track"
            ? "Select a track to view notes"
            : "No project selected"}
        </p>
      </motion.div>
    );
  }

  return (
    <motion.div
      initial={{ opacity: 0, x: 20 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 20 }}
      transition={{ type: "spring", stiffness: 300, damping: 30 }}
      className="flex flex-col h-full"
    >
      <div className="flex items-center justify-between mb-6">
        <div className="min-w-0 flex-1">
          <h2
            className="text-xl font-light text-white"
            style={{ fontFamily: '"IBM Plex Mono", monospace' }}
          >
            Notes
          </h2>
          <p className="text-lg text-muted-foreground mt-0.5 truncate">
            {currentTitle}
          </p>
        </div>
        <Button size="icon-lg" onClick={onClose} className="shrink-0">
          <X className="size-5" />
        </Button>
      </div>

      <div className="flex-1 overflow-y-auto space-y-6">
        {!isLoading && user?.username && currentId && (
          <EditableNote
            key={currentId}
            initialContent={myNote?.content ?? ""}
            authorName={user.username}
            onSave={saveNote}
            entityId={currentId}
          />
        )}

        {!isLoading &&
          otherNotes.map((note) => <NoteItem key={note.id} note={note} />)}

        {!isLoading && notes.length === 0 && !user && (
          <div className="text-[#848484] text-base text-center py-4">
            No notes yet
          </div>
        )}
      </div>
    </motion.div>
  );
}
