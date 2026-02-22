import { createFileRoute, useNavigate } from "@tanstack/react-router";
import DraggableProjectGrid from "@/components/DraggableProjectGrid";
// import { LinearBlur } from "progressive-blur";
import { useProjects, useCreateProject } from "@/hooks/useProjects";
import { useFolders, useCreateFolder } from "@/hooks/useFolders";
import MorphingAddButton from "@/components/MorphingAddButton";
import { toast } from "@/routes/__root";
import { useState, useEffect, useMemo } from "react";
import { useAudioPlayer } from "@/contexts/AudioPlayerContext";
import { useQuery } from "@tanstack/react-query";
import * as sharingApi from "@/api/sharing";

export const Route = createFileRoute("/_main/")({
  component: App,
});

function App() {
  const {
    data: projects,
    isLoading: projectsLoading,
    error: projectsError,
  } = useProjects("root");
  const {
    data: folders,
    isLoading: foldersLoading,
    error: foldersError,
  } = useFolders();

  const { data: sharedTracksData, isLoading: sharedTracksLoading } = useQuery({
    queryKey: ["shared-tracks"],
    queryFn: sharingApi.listTracksSharedWithMe,
    staleTime: 5 * 60 * 1000,
  });

  const sharedTracks = useMemo(() => {
    return sharedTracksData || [];
  }, [sharedTracksData]);

  const isLoading = projectsLoading || foldersLoading || sharedTracksLoading;
  const error = projectsError || foldersError;
  const createProject = useCreateProject();
  const createFolder = useCreateFolder();
  const navigate = useNavigate();
  const { currentTrack, queue } = useAudioPlayer();
  const [showContent, setShowContent] = useState(false);

  const allProjects = useMemo(() => {
    const allProjects = projects || [];
    return allProjects.map((p: any) => ({
      ...p,
      isShared: !!p.shared_by_username,
      sharedByUsername: p.shared_by_username,
    }));
  }, [projects]);

  const memoizedFolders = useMemo(() => {
    return folders || [];
  }, [folders]);

  useEffect(() => {
    if (allProjects && folders && sharedTracks && !isLoading) {
      if (!showContent) {
        const timer = setTimeout(() => {
          setShowContent(true);
        }, 50);
        return () => clearTimeout(timer);
      }
    }
  }, [allProjects, folders, sharedTracks, isLoading]); // eslint-disable-line react-hooks/exhaustive-deps

  const handleCreateProject = async () => {
    try {
      const newProject = await createProject.mutateAsync({
        name: "New Project",
        description: "Click to edit description",
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
        parent_id: null,
      });
    } catch (error) {
      toast.error("Failed to create folder");
      console.error("Error creating folder:", error);
    }
  };

  if (!isLoading && error) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background">
        <div className="text-center">
          <p className="text-red-400">Error loading projects</p>
          <p className="text-gray-400 text-sm mt-2">{error.message}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background">
      <div className="mx-auto max-w-4xl px-6 md:pt-35 pt-30 pb-12">
        <div
          className={`transition-opacity duration-300 ${
            showContent ? "opacity-100" : "opacity-0"
          }`}
        >
          <DraggableProjectGrid
            initialProjects={allProjects}
            initialFolders={memoizedFolders}
            initialSharedTracks={sharedTracks}
          />
        </div>

        <div
          className="fixed top-0 left-0 right-0 h-[130px] z-10 pointer-events-none"
          style={{
            background:
              "linear-gradient(to bottom, #181818 5%, rgba(24, 24, 24, 0.95) 20%, rgba(24, 24, 24, 0.85) 30%, rgba(24, 24, 24, 0.7) 45%, rgba(24, 24, 24, 0.5) 60%, rgba(24, 24, 24, 0.3) 75%, rgba(24, 24, 24, 0.1) 90%, transparent 100%)",
          }}
        />

        <div
          className="fixed bottom-0 left-0 right-0 h-[200px] z-100 pointer-events-none"
          style={{
            background:
              "linear-gradient(to top, #181818 4%, rgba(24, 24, 24, 0.95) 20%, rgba(24, 24, 24, 0.85) 30%, rgba(24, 24, 24, 0.7) 45%, rgba(24, 24, 24, 0.5) 60%, rgba(24, 24, 24, 0.3) 76%, rgba(24, 24, 24, 0.1) 89%, transparent 100%)",
          }}
        />

        <MorphingAddButton
          onAddProject={handleCreateProject}
          onAddFolder={handleCreateFolder}
          isCreatingProject={createProject.isPending}
          isCreatingFolder={createFolder.isPending}
          className={`transition-all duration-100 ${
            showContent ? "opacity-100" : "opacity-0"
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
