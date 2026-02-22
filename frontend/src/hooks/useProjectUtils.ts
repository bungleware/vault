import type { Track } from "@/types/api";

export function formatDate(dateString: string | undefined | null) {
  if (!dateString) return "Unknown";

  const date = new Date(dateString);

  if (Number.isNaN(date.getTime())) return "Unknown";

  const currentYear = new Date().getFullYear();
  const dateYear = date.getFullYear();

  const monthShort = date.toLocaleDateString("en-US", { month: "short" });
  const day = date.getDate();

  if (dateYear === currentYear) {
    return `${monthShort} ${day}`;
  } else {
    return `${monthShort} ${day}, ${dateYear}`;
  }
}

export interface PlayerTrack {
  id: string;
  title: string;
  artist?: string | null;
  projectName?: string;
  coverUrl?: string | null;
  projectId?: string;
  projectCoverUrl?: string;
  waveform?: string | null;
  versionId?: number | null;
}

export function mapTrackToPlayerTrack(
  track: Track,
  project: { name: string; public_id: string; cover_url?: string | null },
  projectCoverImage: string | null,
): PlayerTrack {
  return {
    id: track.public_id,
    title: String(track.title),
    artist: track.artist,
    projectName: String(project.name),
    coverUrl: projectCoverImage,
    projectId: project.public_id,
    projectCoverUrl: project.cover_url ?? undefined,
    waveform: track.waveform,
    versionId: track.active_version_id,
  };
}

export function mapTracksToPlayerTracks(
  tracks: Track[],
  project: { name: string; public_id: string; cover_url?: string | null },
  projectCoverImage: string | null,
): PlayerTrack[] {
  return tracks.map((t) => mapTrackToPlayerTrack(t, project, projectCoverImage));
}
