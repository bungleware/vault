import { useCallback, useRef, useState } from "react";
import type { GridItem } from "./types";
import { dedupeProjects } from "./types";
import { CROSSFADE_DURATION_MS } from "@/lib/constants";
import { getCachedCoverUrl } from "@/hooks/useProjectCoverImage";

interface DragDropCallbacks {
  onCreateFolder?: (name: string, projectIds: string[], folderIds?: number[]) => Promise<number | undefined>;
  onMoveProjectToFolder?: (projectId: string, folderId: number) => Promise<void>;
  onMoveFolderToFolder?: (folderId: number, targetFolderId: number | null) => Promise<void>;
  onOrganizeSharedProject?: (projectId: number, folderId: number | null, customOrder?: number) => Promise<void>;
  onOrganizeSharedTrack?: (trackId: number, folderId: number | null, customOrder?: number) => Promise<void>;
}

export function useDragAndDrop(
  items: GridItem[],
  setItems: React.Dispatch<React.SetStateAction<GridItem[]>>,
  callbacks?: DragDropCallbacks
) {
  const [draggingId, setDraggingId] = useState<string | null>(null);
  const [hoverTargetId, setHoverTargetId] = useState<string | null>(null);
  const [stableHoverTargetId, setStableHoverTargetId] = useState<string | null>(null);
  const [droppingIntoId, setDroppingIntoId] = useState<string | null>(null);

  const itemRefs = useRef<Map<string, HTMLDivElement>>(new Map());
  const hoverTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const rectsRef = useRef<Map<string, DOMRect>>(new Map());

  const registerRef = useCallback(
    (id: string) => (el: HTMLDivElement | null) => {
      if (!el) {
        itemRefs.current.delete(id);
      } else {
        itemRefs.current.set(id, el);
      }
    },
    []
  );

  const measureRects = useCallback(() => {
    const rects = new Map<string, DOMRect>();
    itemRefs.current.forEach((el, id) => {
      rects.set(id, el.getBoundingClientRect());
    });
    return rects;
  }, []);

  const findHoverTarget = useCallback(
    (point: { x: number; y: number }, excludeId: string | null) => {
      const rects = rectsRef.current;
      let found: string | null = null;
      rects.forEach((rect, id) => {
        if (excludeId && id === excludeId) return;
        if (
          point.x >= rect.left &&
          point.x <= rect.right &&
          point.y >= rect.top &&
          point.y <= rect.bottom
        ) {
          found = id;
        }
      });
      return found;
    },
    []
  );

  const handleDragStart = useCallback(
    (id: string) => {
      rectsRef.current = measureRects();
      setDraggingId(id);
      setHoverTargetId(null);
    },
    [measureRects]
  );

  const handleDragMove = useCallback(
    (id: string, _point: { x: number; y: number }) => {
      rectsRef.current = measureRects();
      const draggedRect = rectsRef.current.get(id);
      if (!draggedRect) {
        setHoverTargetId(null);
        return;
      }

      const cardCenter = {
        x: draggedRect.left + draggedRect.width / 2,
        y: draggedRect.top + draggedRect.height / 2,
      };

      const target = findHoverTarget(cardCenter, draggingId);
      setHoverTargetId(target);

      if (hoverTimeoutRef.current) {
        clearTimeout(hoverTimeoutRef.current);
        hoverTimeoutRef.current = null;
      }

      if (target) {
        setStableHoverTargetId(target);
      } else {
        hoverTimeoutRef.current = setTimeout(() => {
          setStableHoverTargetId(null);
          hoverTimeoutRef.current = null;
        }, CROSSFADE_DURATION_MS);
      }
    },
    [draggingId, findHoverTarget, measureRects]
  );

  const handleDragCancel = useCallback(() => {
    setDraggingId(null);
    setHoverTargetId(null);
    if (hoverTimeoutRef.current) {
      clearTimeout(hoverTimeoutRef.current);
      hoverTimeoutRef.current = null;
    }
    setTimeout(() => {
      setStableHoverTargetId(null);
    }, CROSSFADE_DURATION_MS);
  }, []);

  const handleDrop = useCallback(
    async (
      shouldActuallyDrop: boolean,
      _currentDragOffset?: { x: number; y: number }
    ): Promise<boolean> => {
      if (!draggingId) return false;
      const sourceIndex = items.findIndex((it) => it.id === draggingId);
      const source = items[sourceIndex];
      const targetId = hoverTargetId;

      if (!targetId || targetId === draggingId) {
        setDraggingId(null);
        setHoverTargetId(null);
        return false;
      }

      const targetIndex = items.findIndex((it) => it.id === targetId);
      const target = items[targetIndex];

      if (source && source.type === "project") {
        if (target.type === "project" || target.type === "folder" || target.type === "track") {
          if (!shouldActuallyDrop) {
            setDroppingIntoId(targetId);
            return true;
          }

          if (target.type === "project") {
            const projectIds = [target.project.public_id, source.project.public_id];
            const projectItems = [target.project, source.project];

            if (callbacks?.onCreateFolder) {
              try {
                const cachedUrl = getCachedCoverUrl(target.project);
                if (cachedUrl) {
                  await new Promise<void>((resolve) => {
                    const img = new Image();
                    img.onload = () => resolve();
                    img.onerror = () => resolve();
                    img.src = cachedUrl;
                    if (img.complete) {
                      resolve();
                    }
                  });
                }

                const folderId = await callbacks.onCreateFolder("New Folder", projectIds);

                if (folderId) {
                  const newFolder: GridItem = {
                    id: target.id,
                    type: "folder",
                    name: "New Folder",
                    folderId: folderId,
                    items: projectItems,
                  };

                  setItems((prev) => {
                    const next = [...prev];
                    next.splice(targetIndex, 1, newFolder);
                    const removeIndex = next.findIndex((it) => it.id === source.id);
                    if (removeIndex !== -1) next.splice(removeIndex, 1);
                    return next;
                  });
                }
              } catch (error) {
                console.error("Failed to create folder:", error);
              }
            } else {
              const projectItems = [target.project, source.project];
              const newFolder: GridItem = {
                id: target.id,
                type: "folder",
                name: "New Folder",
                items: projectItems,
              };

              setItems((prev) => {
                const next = [...prev];
                next.splice(targetIndex, 1, newFolder);
                const removeIndex = next.findIndex((it) => it.id === source.id);
                if (removeIndex !== -1) next.splice(removeIndex, 1);
                return next;
              });
            }
          } else if (target.type === "folder") {
            if (target.folderId) {
              try {
                if (source.isShared && callbacks?.onOrganizeSharedProject) {
                  await callbacks.onOrganizeSharedProject(
                    source.project.id,
                    target.folderId
                  );
                } else if (callbacks?.onMoveProjectToFolder) {
                  await callbacks.onMoveProjectToFolder(
                    source.project.public_id,
                    target.folderId
                  );
                }
              } catch (error) {
                console.error("Failed to move project to folder:", error);
              }
            }

            setItems((prev) => {
              const next = prev.map((it) => {
                if (it.id === target.id && it.type === "folder") {
                  return {
                    ...it,
                    items: dedupeProjects([...it.items, source.project]),
                  };
                }
                return it;
              });
              const removeIndex = next.findIndex((it) => it.id === source.id);
              if (removeIndex !== -1) next.splice(removeIndex, 1);
              return next;
            });
          } else if (target.type === "track") {
            if (callbacks?.onCreateFolder && callbacks?.onOrganizeSharedTrack && callbacks?.onMoveProjectToFolder) {
              try {
                const folderId = await callbacks.onCreateFolder("New Folder", []);

                if (folderId) {
                  await callbacks.onOrganizeSharedTrack(target.track.id, folderId, 0);
                  
                  if (source.isShared && callbacks.onOrganizeSharedProject) {
                    await callbacks.onOrganizeSharedProject(source.project.id, folderId, 1);
                  } else {
                    await callbacks.onMoveProjectToFolder(source.project.public_id, folderId);
                  }

                  const newFolder: GridItem = {
                    id: target.id,
                    type: "folder",
                    name: "New Folder",
                    folderId: folderId,
                    items: [source.project],
                  };

                  setItems((prev) => {
                    const next = [...prev];
                    next.splice(targetIndex, 1, newFolder);
                    const removeIndex = next.findIndex((it) => it.id === source.id);
                    if (removeIndex !== -1) next.splice(removeIndex, 1);
                    return next;
                  });
                }
              } catch (error) {
                console.error("Failed to create folder with track and project:", error);
              }
            }
          }

          setDroppingIntoId(null);
          setDraggingId(null);
          setHoverTargetId(null);
          return true;
        }
      }

      if (source && source.type === "folder") {
        if (target.type === "project" || target.type === "folder") {
          if (!shouldActuallyDrop) {
            setDroppingIntoId(targetId);
            return true;
          }

          if (target.type === "project") {
            if (callbacks?.onCreateFolder && source.folderId) {
              try {
                const cachedUrl = getCachedCoverUrl(target.project);
                if (cachedUrl) {
                  await new Promise<void>((resolve) => {
                    const img = new Image();
                    img.onload = () => resolve();
                    img.onerror = () => resolve();
                    img.src = cachedUrl;
                    if (img.complete) {
                      resolve();
                    }
                  });
                }

                const folderId = await callbacks.onCreateFolder(
                  "New Folder",
                  [target.project.public_id],
                  [source.folderId]
                );

                if (folderId) {
                  const newFolder: GridItem = {
                    id: target.id,
                    type: "folder",
                    name: "New Folder",
                    folderId: folderId,
                    items: [target.project],
                  };

                  setItems((prev) => {
                    const next = [...prev];
                    next.splice(targetIndex, 1, newFolder);
                    const removeIndex = next.findIndex((it) => it.id === source.id);
                    if (removeIndex !== -1) next.splice(removeIndex, 1);
                    return next;
                  });
                }
              } catch (error) {
                console.error("Failed to create folder:", error);
              }
            }
          } else if (target.type === "folder") {
            if (callbacks?.onMoveFolderToFolder && source.folderId && target.folderId) {
              try {
                await callbacks.onMoveFolderToFolder(source.folderId, target.folderId);
                
                setItems((prev) => {
                  const next = prev.filter((it) => it.id !== source.id);
                  return next;
                });
              } catch (error) {
                console.error("Failed to move folder to folder:", error);
              }
            }
          }

          setDroppingIntoId(null);
          setDraggingId(null);
          setHoverTargetId(null);
          return true;
        }
      }

      if (source && source.type === "track") {
        if (target.type === "project" || target.type === "folder" || target.type === "track") {
          if (!shouldActuallyDrop) {
            setDroppingIntoId(targetId);
            return true;
          }

          if (target.type === "folder") {
            if (target.folderId && callbacks?.onOrganizeSharedTrack) {
              try {
                await callbacks.onOrganizeSharedTrack(
                  source.track.id,
                  target.folderId
                );
              } catch (error) {
                console.error("Failed to organize track into folder:", error);
              }
            }

            setItems((prev) => {
              const next = prev.filter((it) => it.id !== source.id);
              return next;
            });
          } else if (target.type === "project") {
            if (callbacks?.onCreateFolder && callbacks?.onOrganizeSharedTrack) {
              try {
                const cachedUrl = getCachedCoverUrl(target.project);
                if (cachedUrl) {
                  await new Promise<void>((resolve) => {
                    const img = new Image();
                    img.onload = () => resolve();
                    img.onerror = () => resolve();
                    img.src = cachedUrl;
                    if (img.complete) {
                      resolve();
                    }
                  });
                }

                const folderId = await callbacks.onCreateFolder("New Folder", [target.project.public_id]);

                if (folderId) {
                  await callbacks.onOrganizeSharedTrack(source.track.id, folderId, 1);

                  const newFolder: GridItem = {
                    id: target.id,
                    type: "folder",
                    name: "New Folder",
                    folderId: folderId,
                    items: [target.project],
                  };

                  setItems((prev) => {
                    const next = [...prev];
                    next.splice(targetIndex, 1, newFolder);
                    const removeIndex = next.findIndex((it) => it.id === source.id);
                    if (removeIndex !== -1) next.splice(removeIndex, 1);
                    return next;
                  });
                }
              } catch (error) {
                console.error("Failed to create folder with track and project:", error);
              }
            }
          } else if (target.type === "track") {
            if (callbacks?.onCreateFolder && callbacks?.onOrganizeSharedTrack) {
              try {
                const folderId = await callbacks.onCreateFolder("New Folder", []);

                if (folderId) {
                  await callbacks.onOrganizeSharedTrack(target.track.id, folderId, 0);
                  await callbacks.onOrganizeSharedTrack(source.track.id, folderId, 1);

                  const newFolder: GridItem = {
                    id: target.id,
                    type: "folder",
                    name: "New Folder",
                    folderId: folderId,
                    items: [],
                  };

                  setItems((prev) => {
                    const next = [...prev];
                    next.splice(targetIndex, 1, newFolder);
                    const removeIndex = next.findIndex((it) => it.id === source.id);
                    if (removeIndex !== -1) next.splice(removeIndex, 1);
                    return next;
                  });
                }
              } catch (error) {
                console.error("Failed to create folder with two tracks:", error);
              }
            }
          }

          setDroppingIntoId(null);
          setDraggingId(null);
          setHoverTargetId(null);
          return true;
        }
      }

      setDraggingId(null);
      setHoverTargetId(null);
      return false;
    },
    [draggingId, hoverTargetId, items, setItems, callbacks]
  );

  return {
    draggingId,
    hoverTargetId,
    stableHoverTargetId,
    droppingIntoId,
    registerRef,
    handleDragStart,
    handleDragMove,
    handleDragCancel,
    handleDrop,
  };
}
