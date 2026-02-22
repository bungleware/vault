import { Outlet, createFileRoute, useNavigate } from "@tanstack/react-router";
import {
	ChevronLeftIcon,
	MoreHorizontal,
	FileText,
	Pencil,
	FolderInput,
	Download,
	ListPlus,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useTrack } from "@/hooks/useTracks";
import { useProjects } from "@/hooks/useProjects";
import { useQuery } from "@tanstack/react-query";
import * as sharingApi from "@/api/sharing";
import { useMemo } from "react";

export const Route = createFileRoute("/shared-track/$trackId")({
  component: SharedTrackLayout,
});

function SharedTrackLayout() {
  const navigate = useNavigate();
  const { trackId } = Route.useParams();
  const { data: track } = useTrack(trackId);

  const { data: ownedProjects = [] } = useProjects();

  const { data: sharedProjects = [] } = useQuery({
    queryKey: ["shared-projects"],
    queryFn: sharingApi.listProjectsSharedWithMe,
    staleTime: 5 * 60 * 1000,
  });

  const project = useMemo(() => {
    if (!track?.project_id) return undefined;
    const allProjects = [...ownedProjects, ...sharedProjects];
    return allProjects.find((p) => p.id === track.project_id);
  }, [track?.project_id, ownedProjects, sharedProjects]);

  const handleRename = () => {
    window.dispatchEvent(new Event("track-rename"));
  };

  const handleMove = () => {
    window.dispatchEvent(new Event("track-move"));
  };

  const handleExport = () => {
    window.dispatchEvent(new Event("track-export"));
  };

  const handleAddToQueue = () => {
    window.dispatchEvent(new Event("track-add-to-queue"));
  };

  const canEdit = (track as any)?.can_edit ?? false;

  const canDownload =
    project?.allow_downloads ?? (track as any)?.can_download ?? false;

	return (
		<>
			<div className="min-h-screen bg-background">
				<header className="fixed top-0 left-0 right-0 z-50 flex items-center justify-between bg-linear-to-b from-background from-30% to-transparent text-white md:p-10 p-6">
          <Button
            variant="default"
            size="icon-lg"
            onClick={() => navigate({ to: "/" })}
          >
            <ChevronLeftIcon className="size-4.5" />
					</Button>
					<div className="flex items-center gap-2.5">
						<DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="default" size="icon-lg">
                  <MoreHorizontal strokeWidth={3} className="size-4.5" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent
                align="end"
                sideOffset={8}
                className="w-44 border-muted bg-background"
              >
                {canEdit && (
                  <DropdownMenuItem onSelect={handleRename}>
                    <Pencil className="ml-1 mr-1.5 size-4.5" />
                    Rename
                  </DropdownMenuItem>
                )}
                <DropdownMenuItem onSelect={handleMove}>
                  <FolderInput className="ml-1 mr-1.5 size-4.5" />
                  Move
                </DropdownMenuItem>
                <DropdownMenuItem
                  onSelect={() =>
                    window.dispatchEvent(new Event("open-track-notes"))
                  }
                >
                  <FileText className="ml-1 mr-1.5 size-4.5" />
                  Notes
                </DropdownMenuItem>
                {canDownload && (
                  <DropdownMenuItem onSelect={handleExport}>
                    <Download className="ml-1 mr-1.5 size-4.5" />
                    Export
                  </DropdownMenuItem>
                )}
                <DropdownMenuItem onSelect={handleAddToQueue}>
                  <ListPlus className="ml-1 mr-1.5 size-4.5" />
                  Add to queue
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </header>
        <Outlet />
      </div>

    </>
  );
}
