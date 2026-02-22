import { useMemo } from "react";
import { Button } from "@/components/ui/button";
import { useProjects } from "@/hooks/useProjects";
import type { Project } from "@/types/api";
import { useProjectCoverImage } from "@/hooks/useProjectCoverImage";
import BaseModal from "./BaseModal";

function ProjectCover({ project }: { project: Project }) {
  const { imageUrl } = useProjectCoverImage(project, "small");

  if (imageUrl) {
    return (
      <img
        src={imageUrl}
        alt={`${project.name} cover`}
        className="size-full object-cover"
        draggable={false}
      />
    );
  }

  return (
    <div className="size-full bg-neutral-800 flex items-center justify-center text-white text-xs font-bold border border-white/10 rounded-md">
      {String(project.name).charAt(0).toUpperCase()}
    </div>
  );
}

interface MoveTrackModalProps {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: (projectId: number) => void;
  trackName: string;
  currentProjectId: number;
  isMoving?: boolean;
}

export default function MoveTrackModal({
  isOpen,
  onClose,
  onConfirm,
  trackName,
  currentProjectId,
  isMoving = false,
}: MoveTrackModalProps) {
  const { data: allProjects, isLoading: isLoadingProjects } = useProjects();

  const projects = useMemo(() => {
    if (!allProjects) return [];
    return allProjects.filter((p) => p.id !== currentProjectId);
  }, [allProjects, currentProjectId]);

  const handleProjectClick = (projectId: number) => {
    if (!isMoving) {
      onConfirm(projectId);
    }
  };

  return (
    <BaseModal
      isOpen={isOpen}
      onClose={onClose}
      disableClose={isMoving}
      dataAttributes={{
        "data-modal-backdrop": "true",
        "data-modal-container": "true",
        "data-modal-content": "true",
      }}
    >
      <div className="p-6 md:p-8 space-y-6">
        <div className="text-center space-y-3 p-3">
          <h2 className="text-2xl font-semibold text-white">Move Track</h2>
          <p className="text-sm text-muted-foreground">
            Click a project to move{" "}
            <span className="text-white font-medium">
              &ldquo;{trackName}&rdquo;
            </span>{" "}
            to.
          </p>
        </div>

        <div className="space-y-2">
          <div className="max-h-[300px] overflow-y-auto rounded-2xl border border-white/10">
            {isLoadingProjects ? (
              <div className="text-center py-8 text-muted-foreground">
                Loading projects...
              </div>
            ) : (
              <>
                {projects.length === 0 ? (
                  <div className="text-center py-8 text-muted-foreground">
                    No other projects available
                  </div>
                ) : (
                  projects.map((project) => (
                    <button
                      key={project.id}
                      onClick={() => handleProjectClick(project.id)}
                      disabled={isMoving}
                      className={`w-full px-4 py-3 text-left transition-all border-b border-white/5 last:border-b-0 flex items-center gap-3 ${
                        isMoving
                          ? "opacity-50 cursor-not-allowed"
                          : "bg-white/5 hover:bg-white/10"
                      }`}
                    >
                      <div className="size-8 rounded-md overflow-hidden shrink-0">
                        <ProjectCover project={project} />
                      </div>
                      <span className="text-base font-medium text-white">
                        {project.name}
                      </span>
                    </button>
                  ))
                )}
              </>
            )}
          </div>
        </div>

        <div className="pt-2">
          <Button onClick={onClose} disabled={isMoving} className="w-full">
            Cancel
          </Button>
        </div>
      </div>
    </BaseModal>
  );
}
