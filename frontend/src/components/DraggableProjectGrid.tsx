import { useCallback, useState, useEffect, useRef } from "react";
import type React from "react";

import { useNavigate } from "@tanstack/react-router";
import { useQueryClient } from "@tanstack/react-query";

import ProjectCard from "@/components/ProjectCard";
import FolderCard from "./FolderCard";
import DraggableTile from "./DraggableTile";
import TrackCard from "@/components/TrackCard";
import MoveProjectModal from "@/components/modals/MoveProjectModal";
import LeaveProjectModal from "@/components/modals/LeaveProjectModal";
import LeaveTrackModal from "@/components/modals/LeaveTrackModal";
import type {
  Project,
  Folder,
  FolderContents,
  SharedTrackResponse,
} from "@/types/api";
import { cn } from "@/lib/utils";
import type {
  GridItem,
  GridProjectItem,
  GridFolderItem,
  GridTrackItem,
} from "./grid/types";
import { folderToGridItem, trackToGridItem } from "./grid/types";
import { useDragAndDrop } from "./grid/useDragAndDrop";
import { LayoutGroup, AnimatePresence } from "motion/react";
import {
  useMoveProject,
  useMoveProjectsToFolder,
  projectKeys,
} from "@/hooks/useProjects";
import {
  useCreateFolder,
  useEmptyFolder,
  useUpdateFolder,
  folderKeys,
} from "@/hooks/useFolders";
import * as foldersApi from "@/api/folders";
import * as organizationApi from "@/api/organization";
import * as sharingApi from "@/api/sharing";
import { useAudioPlayer } from "@/contexts/AudioPlayerContext";
import { downloadTrack, getTrack } from "@/api/tracks";
import { getCSRFToken } from "@/api/client";
import { toast } from "@/routes/__root";

interface DraggableProjectGridProps {
  initialProjects: Project[];
  initialFolders?: Folder[];
  initialSharedTracks?: SharedTrackResponse[];
  currentFolderId?: number;
  className?: string;
}

export default function DraggableProjectGrid({
  initialProjects,
  initialFolders = [],
  initialSharedTracks = [],
  currentFolderId,
  className,
}: DraggableProjectGridProps) {
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const moveProject = useMoveProject();
  const moveProjectsToFolder = useMoveProjectsToFolder();
  const createFolder = useCreateFolder();
  const emptyFolder = useEmptyFolder();

  const isDropInProgressRef = useRef(false);
  const lastKnownDataRef = useRef<{
    projectIds: Set<string>;
    folderIds: Set<number>;
  } | null>(null);

  const [items, setItems] = useState<GridItem[]>(() => {
    const folderItems: GridFolderItem[] = initialFolders.map((f) =>
      folderToGridItem(f, []),
    );
    const projectItems: GridProjectItem[] = initialProjects.map((p) => ({
      id: String(p.id),
      type: "project",
      project: p,
      isShared: (p as any).isShared,
      sharedByUsername: (p as any).sharedByUsername,
    }));
    const trackItems = initialSharedTracks
      .filter((t) => {
        if (currentFolderId === undefined) {
          return !t.folder_id;
        }
        return t.folder_id === currentFolderId;
      })
      .map((t) => trackToGridItem(t));

    if (
      initialFolders.length > 0 ||
      initialProjects.length > 0 ||
      initialSharedTracks.length > 0
    ) {
      lastKnownDataRef.current = {
        projectIds: new Set(initialProjects.map((p) => String(p.id))),
        folderIds: new Set(initialFolders.map((f) => f.id)),
      };
    }

    return [...folderItems, ...projectItems, ...trackItems];
  });

  const [restoredProjectIds, setRestoredProjectIds] = useState<Set<string>>(
    new Set(),
  );
  const [emptiedFolderIds, setEmptiedFolderIds] = useState<Set<string>>(
    new Set(),
  );
  const [newFolderIds, setNewFolderIds] = useState<Set<string>>(new Set());
  const [newProjectIds, setNewProjectIds] = useState<Set<string>>(new Set());

  const [isMoveModalOpen, setIsMoveModalOpen] = useState(false);
  const [selectedTrackForMove, setSelectedTrackForMove] =
    useState<SharedTrackResponse | null>(null);
  const [isMovingTrack, setIsMovingTrack] = useState(false);
  const [currentTrackFolderId, setCurrentTrackFolderId] = useState<
    number | null
  >(null);

  const [showLeaveModal, setShowLeaveModal] = useState(false);
  const [projectToLeave, setProjectToLeave] = useState<{
    name: string;
    publicId: string;
  } | null>(null);
  const [isLeaving, setIsLeaving] = useState(false);

  const [showLeaveTrackModal, setShowLeaveTrackModal] = useState(false);
  const [trackToLeave, setTrackToLeave] = useState<SharedTrackResponse | null>(
    null,
  );
  const [isLeavingTrack, setIsLeavingTrack] = useState(false);

  const { addToQueue } = useAudioPlayer();

  const optimisticProjectIdsRef = useRef<Set<string>>(new Set());
  const optimisticFolderIdsRef = useRef<Set<number>>(new Set());
  const syncDebounceRef = useRef<NodeJS.Timeout | null>(null);

  useEffect(() => {
    if (isDropInProgressRef.current) {
      return;
    }

    if (syncDebounceRef.current) {
      clearTimeout(syncDebounceRef.current);
    }

    syncDebounceRef.current = setTimeout(() => {
      const projectMap = new Map(initialProjects.map((p) => [String(p.id), p]));
      const folderMap = new Map(initialFolders.map((f) => [f.id, f]));
      const relevantTracks = initialSharedTracks.filter((t) => {
        if (currentFolderId === undefined) {
          return !t.folder_id;
        }
        return t.folder_id === currentFolderId;
      });
      const trackMap = new Map(relevantTracks.map((t) => [t.public_id, t]));
      const currentProjectIds = new Set(
        initialProjects.map((p) => String(p.id)),
      );
      const currentFolderIds = new Set(initialFolders.map((f) => f.id));
      const currentTrackIds = new Set(relevantTracks.map((t) => t.public_id));

      setItems((prevItems) => {
        const isInitialLoad = lastKnownDataRef.current === null;

        if (isInitialLoad) {
          const hasExistingItems = prevItems.length > 0;

          if (!hasExistingItems) {
            const folderItems: GridFolderItem[] = initialFolders.map((f) =>
              folderToGridItem(f, []),
            );
            const projectItems: GridProjectItem[] = initialProjects.map(
              (p) => ({
                id: String(p.id),
                type: "project",
                project: p,
                isShared: (p as any).isShared,
                sharedByUsername: (p as any).sharedByUsername,
              }),
            );
            const trackItems = initialSharedTracks
              .filter((t) => {
                if (currentFolderId === undefined) {
                  return !t.folder_id;
                }
                return t.folder_id === currentFolderId;
              })
              .map((t) => trackToGridItem(t));
            lastKnownDataRef.current = {
              projectIds: currentProjectIds,
              folderIds: currentFolderIds,
            };
            return [...folderItems, ...projectItems, ...trackItems];
          }

          const prevProjectIds = new Set<string>();
          const prevFolderIds = new Set<number>();
          const prevTrackIds = new Set<string>();
          prevItems.forEach((item) => {
            if (item.type === "project") {
              prevProjectIds.add(item.id);
            } else if (item.type === "track") {
              prevTrackIds.add(item.track.public_id);
            } else if (item.folderId) {
              prevFolderIds.add(item.folderId);
            }
          });

          const idsMatch =
            prevProjectIds.size === currentProjectIds.size &&
            prevFolderIds.size === currentFolderIds.size &&
            prevTrackIds.size === currentTrackIds.size &&
            [...prevProjectIds].every((id) => currentProjectIds.has(id)) &&
            [...prevFolderIds].every((id) => currentFolderIds.has(id)) &&
            [...prevTrackIds].every((id) => currentTrackIds.has(id));

          if (idsMatch) {
            const folderItems: GridFolderItem[] = initialFolders.map((f) =>
              folderToGridItem(f, []),
            );
            const projectItems: GridProjectItem[] = initialProjects.map(
              (p) => ({
                id: String(p.id),
                type: "project",
                project: p,
                isShared: (p as any).isShared,
                sharedByUsername: (p as any).sharedByUsername,
              }),
            );
            const trackItems = initialSharedTracks
              .filter((t) => {
                if (currentFolderId === undefined) {
                  return !t.folder_id;
                }
                return t.folder_id === currentFolderId;
              })
              .map((t) => trackToGridItem(t));
            lastKnownDataRef.current = {
              projectIds: currentProjectIds,
              folderIds: currentFolderIds,
            };
            return [...folderItems, ...projectItems, ...trackItems];
          }
        }

        lastKnownDataRef.current = {
          projectIds: currentProjectIds,
          folderIds: currentFolderIds,
        };

        const existingBackendFolderIds = new Set<number>();
        prevItems.forEach((item) => {
          if (item.type === "folder" && item.folderId) {
            existingBackendFolderIds.add(item.folderId);
          }
        });

        const updatedItems = prevItems
          .map((item) => {
            if (item.type === "project") {
              const updatedProject = projectMap.get(item.id);
              if (!updatedProject) {
                if (optimisticProjectIdsRef.current.has(item.id)) {
                  return item;
                }
                return null;
              }
              if (optimisticProjectIdsRef.current.has(item.id)) {
                optimisticProjectIdsRef.current.delete(item.id);
              }
              return { ...item, project: updatedProject };
            } else if (item.type === "track") {
              const updatedTrack = trackMap.get(item.track.public_id);
              if (!updatedTrack) {
                return null;
              }
              return { ...item, track: updatedTrack };
            } else {
              if (item.folderId) {
                const updatedFolder = folderMap.get(item.folderId);
                if (!updatedFolder) {
                  if (optimisticFolderIdsRef.current.has(item.folderId)) {
                    return item;
                  }
                  return null;
                }
                if (optimisticFolderIdsRef.current.has(item.folderId)) {
                  optimisticFolderIdsRef.current.delete(item.folderId);
                }
                return { ...item, name: updatedFolder.name };
              }
              const updatedFolderItems = item.items
                .map((project) => {
                  const updatedProject = projectMap.get(String(project.id));
                  return updatedProject || null;
                })
                .filter((p): p is Project => p !== null);

              if (updatedFolderItems.length === 0) {
                return null;
              }

              return { ...item, items: updatedFolderItems };
            }
          })
          .filter((item): item is GridItem => item !== null);

        const newFolders = initialFolders
          .filter((f) => !existingBackendFolderIds.has(f.id))
          .map((f) => folderToGridItem(f, []));

        if (newFolders.length > 0) {
          setNewFolderIds((prev) => {
            const next = new Set(prev);
            newFolders.forEach((folder) => next.add(folder.id));
            return next;
          });

          setTimeout(() => {
            setNewFolderIds((prev) => {
              const next = new Set(prev);
              newFolders.forEach((folder) => next.delete(folder.id));
              return next;
            });
          }, 500);
        }

        const existingProjectIds = new Set<string>();
        updatedItems.forEach((item) => {
          if (item.type === "project") {
            existingProjectIds.add(item.id);
          } else if (item.type === "folder") {
            item.items.forEach((p) => existingProjectIds.add(String(p.id)));
          }
        });

        const newProjects = initialProjects
          .filter((p) => !existingProjectIds.has(String(p.id)))
          .map(
            (p): GridProjectItem => ({
              id: String(p.id),
              type: "project",
              project: p,
              isShared: (p as any).isShared,
              sharedByUsername: (p as any).sharedByUsername,
            }),
          );

        if (newProjects.length > 0) {
          setNewProjectIds((prev) => {
            const next = new Set(prev);
            newProjects.forEach((project) => next.add(project.id));
            return next;
          });

          setTimeout(() => {
            setNewProjectIds((prev) => {
              const next = new Set(prev);
              newProjects.forEach((project) => next.delete(project.id));
              return next;
            });
          }, 500);
        }

        const existingTrackIds = new Set<string>();
        updatedItems.forEach((item) => {
          if (item.type === "track") {
            existingTrackIds.add(item.track.public_id);
          }
        });

        const newTracks = initialSharedTracks
          .filter((t) => {
            if (!existingTrackIds.has(t.public_id)) {
              if (currentFolderId === undefined) {
                return !t.folder_id;
              }
              return t.folder_id === currentFolderId;
            }
            return false;
          })
          .map((t) => trackToGridItem(t));

        const updatedFolders = updatedItems.filter(
          (item) => item.type === "folder",
        );
        const updatedNonFolders = updatedItems.filter(
          (item) => item.type !== "folder",
        );

        return [
          ...updatedFolders,
          ...newFolders,
          ...updatedNonFolders,
          ...newProjects,
          ...newTracks,
        ];
      });
    }, 50);

    return () => {
      if (syncDebounceRef.current) {
        clearTimeout(syncDebounceRef.current);
      }
    };
  }, [initialProjects, initialFolders, initialSharedTracks]);

  const updateFolder = useUpdateFolder();

  const handleCreateFolder = useCallback(
    async (
      name: string,
      projectIds: string[],
      folderIds?: number[],
    ): Promise<number | undefined> => {
      isDropInProgressRef.current = true;

      try {
        const folder = await createFolder.mutateAsync({
          name,
          parent_id: currentFolderId ?? null,
        });

        const ownedProjectItems: Array<{
          publicId: string;
          id: number;
          order: number;
        }> = [];
        const sharedProjectItems: Array<{
          id: number;
          publicId: string;
          order: number;
        }> = [];

        projectIds.forEach((publicId, index) => {
          const item = items.find(
            (it) => it.type === "project" && it.project.public_id === publicId,
          );
          if (item && item.type === "project") {
            if (item.isShared) {
              sharedProjectItems.push({
                id: item.project.id,
                publicId: item.project.public_id,
                order: index,
              });
            } else {
              ownedProjectItems.push({
                publicId: item.project.public_id,
                id: item.project.id,
                order: index,
              });
            }
          }
        });

        if (ownedProjectItems.length > 0) {
          await moveProjectsToFolder.mutateAsync({
            projects: ownedProjectItems.map((p) => ({
              project_id: p.publicId,
              custom_order: p.order,
            })),
            folderId: folder.id,
          });
        }

        if (sharedProjectItems.length > 0) {
          await Promise.all(
            sharedProjectItems.map((project) =>
              organizationApi.organizeSharedProject(project.id, {
                folder_id: folder.id,
                custom_order: project.order,
              }),
            ),
          );
        }

        if (folderIds && folderIds.length > 0) {
          await Promise.all(
            folderIds.map((folderId) =>
              updateFolder.mutateAsync({
                id: folderId,
                data: { parent_id: folder.id },
              }),
            ),
          );
        }

        setTimeout(() => {
          isDropInProgressRef.current = false;
        }, 500);

        return folder.id;
      } catch (error) {
        console.error("Failed to create folder:", error);
        isDropInProgressRef.current = false;
        return undefined;
      }
    },
    [createFolder, moveProjectsToFolder, updateFolder, currentFolderId, items],
  );

  const handleMoveFolderToFolder = useCallback(
    async (folderId: number, targetFolderId: number | null): Promise<void> => {
      isDropInProgressRef.current = true;

      try {
        const movedFolder = await queryClient.fetchQuery({
          queryKey: folderKeys.detail(folderId),
          queryFn: () => foldersApi.getFolder(folderId),
        });
        const oldParentId = movedFolder.parent_id;

        await updateFolder.mutateAsync({
          id: folderId,
          data: { parent_id: targetFolderId },
        });

        if (targetFolderId) {
          await queryClient.refetchQueries({
            queryKey: folderKeys.contents(targetFolderId),
          });
        }

        if (oldParentId) {
          queryClient.invalidateQueries({
            queryKey: folderKeys.contents(oldParentId),
          });
        } else {
          queryClient.invalidateQueries({
            queryKey: folderKeys.lists(),
          });
        }

        setTimeout(() => {
          isDropInProgressRef.current = false;
        }, 500);
      } catch (error) {
        isDropInProgressRef.current = false;
        throw error;
      }
    },
    [updateFolder, queryClient],
  );

  const handleMoveProjectToFolder = useCallback(
    async (
      projectId: string,
      folderId: number,
      customOrder?: number,
    ): Promise<void> => {
      isDropInProgressRef.current = true;

      try {
        if (customOrder !== undefined) {
          await moveProjectsToFolder.mutateAsync({
            projects: [{ project_id: projectId, custom_order: customOrder }],
            folderId,
          });
        } else {
          await moveProject.mutateAsync({ id: projectId, folderId });
        }

        await queryClient.refetchQueries({
          queryKey: projectKeys.list(folderId),
        });

        setTimeout(() => {
          isDropInProgressRef.current = false;
        }, 500);
      } catch (error) {
        isDropInProgressRef.current = false;
        throw error;
      }
    },
    [moveProject, moveProjectsToFolder, queryClient],
  );

  const handleOrganizeSharedProject = useCallback(
    async (
      projectId: number,
      folderId: number | null,
      customOrder?: number,
    ): Promise<void> => {
      isDropInProgressRef.current = true;

      try {
        await organizationApi.organizeSharedProject(projectId, {
          folder_id: folderId,
          custom_order: customOrder,
        });

        if (folderId) {
          await queryClient.refetchQueries({
            queryKey: projectKeys.list(folderId),
          });
          await queryClient.refetchQueries({
            queryKey: folderKeys.contents(folderId),
          });
        }
        queryClient.invalidateQueries({ queryKey: ["shared-projects"] });

        setTimeout(() => {
          isDropInProgressRef.current = false;
        }, 500);
      } catch (error) {
        console.error("Failed to organize shared project:", error);
        isDropInProgressRef.current = false;
        throw error;
      }
    },
    [queryClient],
  );

  const handleOrganizeSharedTrack = useCallback(
    async (
      trackId: number,
      folderId: number | null,
      customOrder?: number,
    ): Promise<void> => {
      isDropInProgressRef.current = true;

      try {
        await organizationApi.organizeSharedTrack(trackId, {
          folder_id: folderId,
          custom_order: customOrder,
        });

        if (folderId) {
          await queryClient.refetchQueries({
            queryKey: folderKeys.contents(folderId),
          });
        }
        queryClient.invalidateQueries({ queryKey: ["shared-tracks"] });

        setTimeout(() => {
          isDropInProgressRef.current = false;
        }, 500);
      } catch (error) {
        console.error("Failed to organize shared track:", error);
        isDropInProgressRef.current = false;
        throw error;
      }
    },
    [queryClient],
  );

  const handleLeaveSharedProject = useCallback((project: Project) => {
    if (!project.public_id) return;
    setProjectToLeave({
      name: String(project.name),
      publicId: project.public_id,
    });
    setShowLeaveModal(true);
  }, []);

  const handleLeaveConfirm = useCallback(async () => {
    if (!projectToLeave || isLeaving) return;

    setIsLeaving(true);
    try {
      await sharingApi.leaveSharedProject(projectToLeave.publicId);
      queryClient.invalidateQueries({ queryKey: ["shared-projects"] });
      queryClient.invalidateQueries({ queryKey: ["projects"] });
      setShowLeaveModal(false);
      setProjectToLeave(null);
      setItems((prev) =>
        prev.filter(
          (i) =>
            i.type !== "project" ||
            (i as GridProjectItem).project.public_id !==
              projectToLeave.publicId,
        ),
      );
      toast.success("Left project");
    } catch (error) {
      toast.error("Failed to leave project");
      console.error("Failed to leave project:", error);
    } finally {
      setIsLeaving(false);
    }
  }, [projectToLeave, isLeaving, queryClient]);

  const {
    draggingId,
    hoverTargetId,
    stableHoverTargetId,
    droppingIntoId,
    registerRef,
    handleDragStart,
    handleDragMove,
    handleDragCancel,
    handleDrop,
  } = useDragAndDrop(items, setItems, {
    onCreateFolder: handleCreateFolder,
    onMoveProjectToFolder: handleMoveProjectToFolder,
    onMoveFolderToFolder: handleMoveFolderToFolder,
    onOrganizeSharedProject: handleOrganizeSharedProject,
    onOrganizeSharedTrack: handleOrganizeSharedTrack,
  });

  const handleTrackAddToQueue = useCallback(
    async (track: SharedTrackResponse) => {
      try {
        let coverUrl = track.cover_url;
        if (coverUrl) {
          // Add size parameter for optimized image
          if (!coverUrl.includes("size=")) {
            coverUrl = `${coverUrl}${coverUrl.includes("?") ? "&" : "?"}size=small`;
          }
        }

        addToQueue({
          id: track.public_id,
          title: String(track.title),
          artist: track.artist || undefined,
          projectName: track.project_name || "Unknown Project",
          coverUrl: coverUrl,
          projectId: track.project_public_id ?? undefined,
          projectCoverUrl: coverUrl ?? undefined,
          waveform: track.waveform,
          versionId: undefined, // SharedTrackResponse doesn't have active_version_id
        });

        const { toast } = await import("@/routes/__root");
        toast.success(`Added "${track.title}" to queue`);
      } catch (error) {
        const { toast } = await import("@/routes/__root");
        toast.error("Failed to add track to queue");
        console.error("Failed to add track to queue:", error);
      }
    },
    [addToQueue],
  );

  const handleTrackMove = useCallback((track: SharedTrackResponse) => {
    setSelectedTrackForMove(track);
    setCurrentTrackFolderId(track.folder_id ?? null);
    setIsMoveModalOpen(true);
  }, []);

  const handleTrackExport = useCallback(async (track: SharedTrackResponse) => {
    if (!track.can_download) {
      const { toast } = await import("@/routes/__root");
      toast.error("Downloads are not allowed for this track");
      return;
    }

    try {
      const fullTrack = await getTrack(track.public_id);
      if (!fullTrack.active_version_id) {
        const { toast } = await import("@/routes/__root");
        toast.error("Track has no version to export");
        return;
      }
      await downloadTrack(track.public_id, fullTrack.active_version_id);
    } catch (error) {
      const { toast } = await import("@/routes/__root");
      toast.error("Failed to download track");
      console.error("Failed to download track:", error);
    }
  }, []);

  const handleTrackLeaveClick = useCallback((track: SharedTrackResponse) => {
    setTrackToLeave(track);
    setShowLeaveTrackModal(true);
  }, []);

  const handleTrackLeaveConfirm = useCallback(async () => {
    if (!trackToLeave?.id || isLeavingTrack) return;

    setIsLeavingTrack(true);
    try {
      const response = await fetch(
        `/api/shared-tracks/${trackToLeave.id}/leave`,
        {
          method: "DELETE",
          headers: {
            ...(getCSRFToken()
              ? { "X-CSRF-Token": getCSRFToken() as string }
              : {}),
          },
          credentials: "include",
        },
      );

      if (!response.ok) {
        throw new Error("Failed to leave shared track");
      }

      queryClient.invalidateQueries({ queryKey: ["shared-tracks"] });
      queryClient.invalidateQueries({ queryKey: ["shared-projects"] });
      setShowLeaveTrackModal(false);
      setTrackToLeave(null);
      setItems((prev) =>
        prev.filter(
          (i) =>
            i.type !== "track" ||
            (i as GridTrackItem).track.public_id !== trackToLeave.public_id,
        ),
      );
      toast.success("Left shared track");
    } catch (error) {
      toast.error("Failed to leave track");
      console.error("Failed to leave track:", error);
    } finally {
      setIsLeavingTrack(false);
    }
  }, [trackToLeave, isLeavingTrack, queryClient]);

  const handleConfirmMoveTrack = useCallback(
    async (folderId: number | null) => {
      if (isMovingTrack || !selectedTrackForMove) return;
      setIsMovingTrack(true);
      try {
        await organizationApi.organizeSharedTrack(selectedTrackForMove.id, {
          folder_id: folderId,
        });
        setIsMoveModalOpen(false);
        setSelectedTrackForMove(null);
        queryClient.invalidateQueries({ queryKey: ["shared-tracks"] });
        if (folderId) {
          const { folderKeys } = await import("@/hooks/useFolders");
          queryClient.invalidateQueries({
            queryKey: folderKeys.contents(folderId),
          });
        }
        queryClient.invalidateQueries({ queryKey: ["folders"] });
        const { toast } = await import("@/routes/__root");
        toast.success("Track moved successfully");
      } catch (error) {
        const { toast } = await import("@/routes/__root");
        toast.error("Failed to move track");
        console.error("Failed to move track:", error);
      } finally {
        setIsMovingTrack(false);
      }
    },
    [isMovingTrack, selectedTrackForMove, queryClient],
  );

  const handleEmptyFolder = useCallback(
    async (folderId: string) => {
      const folder = items.find(
        (it) => it.id === folderId && it.type === "folder",
      );
      if (!folder || folder.type !== "folder" || !folder.folderId) return;

      let itemsToRestore: GridItem[] = [];

      try {
        isDropInProgressRef.current = true;
        setEmptiedFolderIds((prev) => new Set(prev).add(folderId));

        itemsToRestore = folder.items.map((project) => ({
          id: String(project.id),
          type: "project",
          project,
          isShared:
            !!(project as any).isShared ||
            !!(project as any).shared_by_username,
          sharedByUsername:
            (project as any).sharedByUsername ||
            (project as any).shared_by_username,
        }));

        if (folder.folderId) {
          const cachedData = queryClient.getQueryData<FolderContents>(
            folderKeys.contents(folder.folderId),
          );
          if (cachedData) {
            const cachedProjects: GridProjectItem[] = cachedData.projects.map(
              (project) => ({
                id: String(project.id),
                type: "project",
                project,
                isShared:
                  !!(project as any).isShared ||
                  !!(project as any).shared_by_username,
                sharedByUsername:
                  (project as any).sharedByUsername ||
                  (project as any).shared_by_username,
              }),
            );
            const cachedFolders: GridFolderItem[] = cachedData.folders.map(
              (f) => folderToGridItem(f, []),
            );
            const cachedTracks: GridTrackItem[] = (
              cachedData.shared_tracks || []
            ).map((track) => trackToGridItem(track));
            itemsToRestore = [
              ...cachedFolders,
              ...cachedProjects,
              ...cachedTracks,
            ];
          }
        }

        itemsToRestore.forEach((item) => {
          if (item.type === "project") {
            optimisticProjectIdsRef.current.add(item.id);
          } else if (item.type === "folder" && item.folderId) {
            optimisticFolderIdsRef.current.add(item.folderId);
          } else if (item.type === "track") {
            optimisticProjectIdsRef.current.add(item.id);
          }
        });

        setItems((prev) => {
          const next = prev.filter((it) => it.id !== folderId);
          return [...next, ...itemsToRestore];
        });

        const restoredIds = new Set(itemsToRestore.map((item) => item.id));
        setRestoredProjectIds(restoredIds);

        await emptyFolder.mutateAsync(folder.folderId);

        const tracksToOrganize = itemsToRestore.filter(
          (item): item is GridTrackItem => item.type === "track",
        );
        if (tracksToOrganize.length > 0) {
          await Promise.all(
            tracksToOrganize.map((trackItem) =>
              organizationApi.organizeSharedTrack(trackItem.track.id, {
                folder_id: currentFolderId ?? null,
              }),
            ),
          );
        }

        setTimeout(() => {
          isDropInProgressRef.current = false;
        }, 500);

        setTimeout(() => {
          setRestoredProjectIds(new Set());
          setEmptiedFolderIds((prev) => {
            const next = new Set(prev);
            next.delete(folderId);
            return next;
          });
        }, 500);
      } catch (error) {
        console.error("Failed to empty folder:", error);

        isDropInProgressRef.current = false;

        itemsToRestore.forEach((item) => {
          if (item.type === "project") {
            optimisticProjectIdsRef.current.delete(item.id);
          } else if (item.type === "folder" && item.folderId) {
            optimisticFolderIdsRef.current.delete(item.folderId);
          } else if (item.type === "track") {
            optimisticProjectIdsRef.current.delete(item.id);
          }
        });

        setEmptiedFolderIds((prev) => {
          const next = new Set(prev);
          next.delete(folderId);
          return next;
        });
      }
    },
    [items, emptyFolder, queryClient, currentFolderId],
  );

  return (
    <LayoutGroup>
      <div className="relative">
        <div
          className={cn(
            "flex flex-wrap justify-center gap-6 gap-y-3 sm:gap-14 sm:gap-y-14 pb-40",
            className,
          )}
        >
          <AnimatePresence mode="popLayout">
            {items.map((item) => {
              const isDragging = draggingId === item.id;
              const scaleDown =
                draggingId === item.id &&
                hoverTargetId !== null &&
                hoverTargetId !== item.id;
              const sourceItem = draggingId
                ? items.find((it) => it.id === draggingId)
                : undefined;
              const sourceProject =
                sourceItem && sourceItem.type === "project"
                  ? sourceItem.project
                  : undefined;

              if (item.type === "folder") {
                const isEmptied = emptiedFolderIds.has(item.id);
                const isNewFolder = newFolderIds.has(item.id);
                const isDraggingFolder = isDragging;
                const isBeingDroppedInto =
                  draggingId === item.id && droppingIntoId !== null;

                return (
                  <DraggableTile
                    key={isEmptied ? `emptied-${item.id}` : item.id}
                    id={item.id}
                    layoutId={isEmptied ? undefined : item.id}
                    registerRef={registerRef}
                    isDragging={isDraggingFolder}
                    isBeingDropped={isBeingDroppedInto}
                    isRestoredFromFolder={isNewFolder}
                    onDragStart={() => handleDragStart(item.id)}
                    onDragMove={(p) => handleDragMove(item.id, p)}
                    onDragCancel={handleDragCancel}
                    onDrop={handleDrop}
                  >
                    {(dragHandleProps) => {
                      const handlePointerDown = (e: React.PointerEvent) => {
                        const target = e.target as HTMLElement;

                        if (
                          target.closest(
                            '[data-slot="dropdown-menu-trigger"]',
                          ) ||
                          target.closest(
                            '[data-slot="dropdown-menu-content"]',
                          ) ||
                          target.closest('[data-slot="dropdown-menu-item"]')
                        ) {
                          return;
                        }

                        const folderCard = target.closest(
                          '[data-dropdown-open="true"]',
                        );
                        if (folderCard) {
                          return;
                        }

                        if (
                          target.closest('[data-modal-backdrop="true"]') ||
                          target.closest('[data-modal-container="true"]') ||
                          target.closest('[data-modal-content="true"]')
                        ) {
                          return;
                        }

                        if (
                          document.querySelector('[data-modal-open="true"]')
                        ) {
                          return;
                        }

                        dragHandleProps.onPointerDown?.(e);
                      };

                      return (
                        <div
                          className="flex items-center justify-center w-40"
                          style={
                            isEmptied
                              ? { opacity: 0, pointerEvents: "none" }
                              : undefined
                          }
                          onPointerDown={handlePointerDown}
                          onPointerUp={dragHandleProps.onPointerUp}
                          onPointerMove={dragHandleProps.onPointerMove}
                        >
                          <FolderCard
                            folder={{
                              id: item.id,
                              name: item.name,
                              items: item.items,
                              folderId: item.folderId,
                            }}
                            className="w-40"
                            hoverActive={
                              hoverTargetId === item.id &&
                              draggingId !== item.id
                            }
                            hoverIncomingItems={
                              stableHoverTargetId === item.id && sourceProject
                                ? [sourceProject]
                                : []
                            }
                            isDropping={droppingIntoId === item.id}
                            dragScaleDown={scaleDown}
                            isDragging={isDraggingFolder}
                            onEmptyFolder={handleEmptyFolder}
                          />
                        </div>
                      );
                    }}
                  </DraggableTile>
                );
              }

              if (item.type === "track") {
                let coverUrl = item.track.cover_url;
                if (coverUrl) {
                  // Add size parameter for optimized image
                  if (!coverUrl.includes("size=")) {
                    coverUrl = `${coverUrl}${coverUrl.includes("?") ? "&" : "?"}size=small`;
                  }
                }

                const isBeingDroppedInto =
                  draggingId === item.id && droppingIntoId !== null;
                const isRestoredTrack = restoredProjectIds.has(item.id);
                const isNewTrack = newProjectIds.has(item.id);

                return (
                  <DraggableTile
                    key={item.id}
                    id={item.id}
                    layoutId={item.id}
                    registerRef={registerRef}
                    isDragging={isDragging}
                    isBeingDropped={isBeingDroppedInto}
                    isRestoredFromFolder={isRestoredTrack || isNewTrack}
                    onDragStart={() => handleDragStart(item.id)}
                    onDragMove={(p) => handleDragMove(item.id, p)}
                    onDragCancel={handleDragCancel}
                    onDrop={handleDrop}
                  >
                    {(dragHandleProps, dragged) => (
                      <div className="flex items-center justify-center w-40">
                        <TrackCard
                          className="w-40"
                          track={{
                            ...item.track,
                            projectCoverUrl: coverUrl || undefined,
                            projectName: item.track.project_name,
                            sharedBy: item.track.shared_by_username,
                          }}
                          isShared={true}
                          isOwned={false}
                          canDownload={item.track.can_download}
                          onClick={() => {
                            navigate({
                              to: "/shared-track/$trackId",
                              params: { trackId: item.track.public_id },
                            });
                          }}
                          onAddToQueue={() => handleTrackAddToQueue(item.track)}
                          onMove={() => handleTrackMove(item.track)}
                          onExport={() => handleTrackExport(item.track)}
                          onLeave={() => handleTrackLeaveClick(item.track)}
                          dragHandleProps={dragHandleProps}
                          isDragging={dragged}
                          dragScaleDown={scaleDown}
                          hoverAsFolder={
                            hoverTargetId === item.id && draggingId !== item.id
                          }
                          hoverFolderItems={
                            stableHoverTargetId === item.id && sourceProject
                              ? [sourceProject]
                              : []
                          }
                          isDropping={droppingIntoId === item.id}
                        />
                      </div>
                    )}
                  </DraggableTile>
                );
              }

              const isBeingDroppedInto =
                draggingId === item.id && droppingIntoId !== null;
              const isRestoredProject = restoredProjectIds.has(item.id);
              const isNewProject = newProjectIds.has(item.id);

              return (
                <DraggableTile
                  key={item.id}
                  id={item.id}
                  layoutId={item.id}
                  registerRef={registerRef}
                  isDragging={isDragging}
                  isBeingDropped={isBeingDroppedInto}
                  isRestoredFromFolder={isRestoredProject || isNewProject}
                  onDragStart={() => handleDragStart(item.id)}
                  onDragMove={(p) => handleDragMove(item.id, p)}
                  onDragCancel={handleDragCancel}
                  onDrop={handleDrop}
                >
                  {(dragHandleProps, dragged) => (
                    <div className="flex items-center justify-center w-40">
                      <ProjectCard
                        project={item.project}
                        className="w-40"
                        dragHandleProps={dragHandleProps}
                        isDragging={dragged}
                        dragScaleDown={scaleDown}
                        hoverAsFolder={
                          hoverTargetId === item.id && draggingId !== item.id
                        }
                        hoverFolderItems={
                          stableHoverTargetId === item.id && sourceProject
                            ? [sourceProject]
                            : []
                        }
                        isDropping={droppingIntoId === item.id}
                        isBeingDropped={
                          draggingId === item.id && droppingIntoId !== null
                        }
                        isOwned={!item.isShared}
                        isShared={item.isShared}
                        sharedByUsername={item.sharedByUsername}
                        onLeaveClick={
                          item.isShared
                            ? () => handleLeaveSharedProject(item.project)
                            : undefined
                        }
                      />
                    </div>
                  )}
                </DraggableTile>
              );
            })}
          </AnimatePresence>
        </div>
      </div>

      {/* Leave Track Modal */}
      {trackToLeave && (
        <LeaveTrackModal
          isOpen={showLeaveTrackModal}
          onClose={() => {
            setShowLeaveTrackModal(false);
            setTrackToLeave(null);
          }}
          onConfirm={handleTrackLeaveConfirm}
          trackName={String(trackToLeave.title)}
          isLeaving={isLeavingTrack}
        />
      )}

      {/* Leave Project Modal */}
      {projectToLeave && (
        <LeaveProjectModal
          isOpen={showLeaveModal}
          onClose={() => {
            setShowLeaveModal(false);
            setProjectToLeave(null);
          }}
          onConfirm={handleLeaveConfirm}
          projectName={projectToLeave.name}
          isLeaving={isLeaving}
        />
      )}

      {/* Move Track Modal */}
      {selectedTrackForMove && (
        <MoveProjectModal
          isOpen={isMoveModalOpen}
          onClose={() => {
            if (!isMovingTrack) {
              setIsMoveModalOpen(false);
              setSelectedTrackForMove(null);
            }
          }}
          onConfirm={handleConfirmMoveTrack}
          projectName={selectedTrackForMove.title}
          currentFolderId={currentTrackFolderId}
          isMoving={isMovingTrack}
        />
      )}
    </LayoutGroup>
  );
}
