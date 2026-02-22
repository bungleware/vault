import { createFileRoute, useNavigate } from "@tanstack/react-router";
import DraggableProjectGrid from "@/components/DraggableProjectGrid";
import { useFolderContents, useCreateFolder } from "@/hooks/useFolders";
import { useCreateProject } from "@/hooks/useProjects";
import MorphingAddButton from "@/components/MorphingAddButton";
import { toast } from "@/routes/__root";
import LinkNotAvailable from "@/components/LinkNotAvailable";
import { useEffect, useRef, useMemo } from "react";
import { useAudioPlayer } from "@/contexts/AudioPlayerContext";

export const Route = createFileRoute("/_main/folder/$folderId/")({
  component: FolderPage,
});

function FolderPage() {
  const { folderId } = Route.useParams();
  const folderIdNum = parseInt(folderId, 10);
  const { data: contents, isLoading, error } = useFolderContents(folderIdNum);
  const { currentTrack, queue } = useAudioPlayer();
  const createProject = useCreateProject();
  const createFolder = useCreateFolder();
  const navigate = useNavigate();
  const contentRef = useRef<HTMLDivElement>(null);
  const lastFolderIdRef = useRef<string | null>(null);
  const pendingShowTimerRef = useRef<NodeJS.Timeout | null>(null);

  const projects = useMemo(() => {
    const allProjects = contents?.projects || [];
    return allProjects.map((p: any) => ({
      ...p,
      isShared: !!p.shared_by_username,
      sharedByUsername: p.shared_by_username,
    }));
  }, [contents?.projects]);

  const folders = useMemo(() => {
    return contents?.folders || [];
  }, [contents?.folders]);

  const sharedTracks = useMemo(() => {
    return contents?.shared_tracks || [];
  }, [contents?.shared_tracks]);

  useEffect(() => {
    const currentFolderId = folderId;

    if (lastFolderIdRef.current !== currentFolderId && contentRef.current) {
      if (pendingShowTimerRef.current) {
        clearTimeout(pendingShowTimerRef.current);
        pendingShowTimerRef.current = null;
      }

      contentRef.current.classList.remove("folder-content-visible");
      contentRef.current.classList.add("folder-content-hidden");

      void contentRef.current.offsetWidth;

      lastFolderIdRef.current = currentFolderId;
    }
  }, [folderId]);

  useEffect(() => {
    if (
      contentRef.current &&
      contents &&
      !isLoading &&
      lastFolderIdRef.current === folderId
    ) {
      if (pendingShowTimerRef.current) {
        clearTimeout(pendingShowTimerRef.current);
      }

      pendingShowTimerRef.current = setTimeout(() => {
        if (contentRef.current && lastFolderIdRef.current === folderId) {
          contentRef.current.classList.remove("folder-content-hidden");
          contentRef.current.classList.add("folder-content-visible");
          pendingShowTimerRef.current = null;
        }
      }, 50);

      return () => {
        if (pendingShowTimerRef.current) {
          clearTimeout(pendingShowTimerRef.current);
          pendingShowTimerRef.current = null;
        }
      };
    }
  }, [folderId, contents, isLoading]);

  const handleCreateProject = async () => {
    try {
      const newProject = await createProject.mutateAsync({
        name: "New Project",
        description: "Click to edit description",
        folder_id: folderIdNum,
      });

      navigate({
        to: "/project/$projectId",
        params: { projectId: String(newProject.public_id) },
      });
    } catch (error) {
      toast.error("Failed to create project");
      console.error("Error creating project:", error);
    }
  };

  const handleCreateFolder = async () => {
    try {
      await createFolder.mutateAsync({
        name: "New Folder",
        parent_id: folderIdNum,
      });
    } catch (error) {
      toast.error("Failed to create folder");
      console.error("Error creating folder:", error);
    }
  };

  if (!isLoading && error) {
    return <LinkNotAvailable />;
  }

  return (
    <div className="min-h-screen bg-background">
      <style>{`
        .folder-content-hidden {
          opacity: 0;
        }
        .folder-content-visible {
          opacity: 1;
          transition: opacity 300ms ease-in-out;
        }
      `}</style>
      <div className="mx-auto max-w-4xl px-6 md:pt-35 pt-30 pb-12">
        <div ref={contentRef} className="folder-content-hidden">
          <DraggableProjectGrid
            key={folderId}
            initialProjects={projects}
            initialFolders={folders}
            initialSharedTracks={sharedTracks}
            currentFolderId={folderIdNum}
          />
        </div>

        {/* Top gradient overlay */}
        <div
          className="fixed top-0 left-0 right-0 h-[130px] z-10 pointer-events-none"
          style={{
            background:
              "linear-gradient(to bottom, #181818 5%, rgba(24, 24, 24, 0.95) 20%, rgba(24, 24, 24, 0.85) 30%, rgba(24, 24, 24, 0.7) 45%, rgba(24, 24, 24, 0.5) 60%, rgba(24, 24, 24, 0.3) 75%, rgba(24, 24, 24, 0.1) 90%, transparent 100%)",
          }}
        />

        {/* Bottom gradient overlay */}
        <div
          className="fixed bottom-0 left-0 right-0 h-[200px] z-100 pointer-events-none"
          style={{
            background:
              "linear-gradient(to top, #181818 4%, rgba(24, 24, 24, 0.95) 20%, rgba(24, 24, 24, 0.85) 30%, rgba(24, 24, 24, 0.7) 45%, rgba(24, 24, 24, 0.5) 60%, rgba(24, 24, 24, 0.3) 76%, rgba(24, 24, 24, 0.1) 89%, transparent 100%)",
          }}
        />

        {/* Floating Add Button */}
        <MorphingAddButton
          onAddProject={handleCreateProject}
          onAddFolder={handleCreateFolder}
          isCreatingProject={createProject.isPending}
          isCreatingFolder={createFolder.isPending}
          className={`transition-all duration-100 ${
            contents && !isLoading ? "opacity-100" : "opacity-0"
          }`}
          bottomOffset={
            currentTrack || queue.length > 0
              ? "bottom-[130px] sm:bottom-[145px]"
              : "bottom-8"
          }
        />
      </div>
    </div>
  );
}
