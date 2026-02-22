import type { Project, Folder, SharedTrackResponse } from "@/types/api";

export type GridProjectItem = {
  id: string;
  type: "project";
  project: Project;
  isShared?: boolean;
  sharedByUsername?: string;
  customOrder?: number;
};

export type GridFolderItem = {
  id: string;
  type: "folder";
  name: string;
  items: Project[];
  folderId?: number;
};

export type GridTrackItem = {
  id: string;
  type: "track";
  track: SharedTrackResponse;
  isShared?: boolean;
  sharedByUsername?: string;
  customOrder?: number;
  folderId?: number | null;
};

export type GridItem = GridProjectItem | GridFolderItem | GridTrackItem;

export function folderToGridItem(folder: Folder, items: Project[] = []): GridFolderItem {
  return {
    id: `folder-${folder.id}`,
    type: "folder",
    name: folder.name,
    items,
    folderId: folder.id,
  };
}

export function trackToGridItem(track: SharedTrackResponse): GridTrackItem {
  return {
    id: `track-${track.public_id}`,
    type: "track",
    track,
    folderId: track.folder_id,
  };
}

export function dedupeProjects(projects: Project[]): Project[] {
  const seen = new Set<number>();
  const result: Project[] = [];
  for (const p of projects) {
    if (seen.has(p.id)) continue;
    seen.add(p.id);
    result.push(p);
  }
  return result;
}
