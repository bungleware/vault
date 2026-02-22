import TrackDetailsModal from "@/components/modals/TrackDetailsModal";
import TrackVersionsModal from "@/components/modals/TrackVersionsModal";
import CoverArtOptionsModal from "@/components/modals/CoverArtOptionsModal";
import BaseModal from "@/components/modals/BaseModal";
import NotesPanel from "@/components/NotesPanel";
import GlobalSearchModal from "@/components/GlobalSearchModal";
import type { Track, Project, VisibilityStatus } from "@/types/api";

interface TrackDetailsData {
  title: string;
  duration?: string;
  key?: string | null;
  bpm?: number | null;
  fileName?: string;
  active_version_id?: number | null;
  waveform?: string | null;
  visibility_status?: VisibilityStatus;
}

interface ProjectModalsProps {
  // Track details modal
  selectedTrack: Track | null;
  trackDetailsData: TrackDetailsData | null;
  isModalOpen: boolean;
  onCloseModal: () => void;
  project: Project;
  projectCoverImage: string | null;
  isProjectOwned: boolean;
  canEditTrack: (track: Track | null) => boolean;
  isInSharedProject: boolean;
  projectAllowsDownloads: boolean;
  onTrackUpdate: () => void;
  onOpenNotes: (track: Track) => void;

  // Versions modal
  versionUploadTrack: Track | null;
  isVersionsModalOpen: boolean;
  onCloseVersionsModal: () => void;
  onBackFromVersions: () => void;

  // Cover art modal
  isCoverModalOpen: boolean;
  onCloseCoverModal: () => void;
  onLibraryClick: () => void;
  onExportCover: () => void;
  hasExistingCover: boolean;
  canEditCover: boolean;
  canDownloadCover: boolean;

  // Notes modal (mobile)
  isSmallScreen: boolean;
  isNotesOpen: boolean;
  onCloseNotes: () => void;
  notesTrack: Track | null;

  // Global search
  isGlobalSearchOpen: boolean;
  onCloseGlobalSearch: () => void;
}

export function ProjectModals({
  selectedTrack,
  trackDetailsData,
  isModalOpen,
  onCloseModal,
  project,
  projectCoverImage,
  isProjectOwned,
  canEditTrack,
  isInSharedProject,
  projectAllowsDownloads,
  onTrackUpdate,
  onOpenNotes,
  versionUploadTrack,
  isVersionsModalOpen,
  onCloseVersionsModal,
  onBackFromVersions,
  isCoverModalOpen,
  onCloseCoverModal,
  onLibraryClick,
  onExportCover,
  hasExistingCover,
  canEditCover,
  canDownloadCover,
  isSmallScreen,
  isNotesOpen,
  onCloseNotes,
  notesTrack,
  isGlobalSearchOpen,
  onCloseGlobalSearch,
}: ProjectModalsProps) {
  return (
    <>
      {selectedTrack && trackDetailsData && (
        <TrackDetailsModal
          isOpen={isModalOpen}
          onClose={onCloseModal}
          trackId={selectedTrack.public_id}
          track={trackDetailsData}
          onUpdate={onTrackUpdate}
          projectName={project.name}
          artist={selectedTrack.artist}
          coverUrl={projectCoverImage}
          projectId={project.public_id}
          projectCoverUrl={project.cover_url ?? undefined}
          isProjectOwned={isProjectOwned}
          canEdit={canEditTrack(selectedTrack)}
          isInSharedProject={isInSharedProject}
          projectAllowsDownloads={projectAllowsDownloads}
          onOpenNotes={() => onOpenNotes(selectedTrack)}
        />
      )}

      {versionUploadTrack && (
        <TrackVersionsModal
          isOpen={isVersionsModalOpen}
          onClose={onCloseVersionsModal}
          onBack={onBackFromVersions}
          trackId={versionUploadTrack.public_id}
          track={{
            title: String(versionUploadTrack.title),
            key: versionUploadTrack.key,
            bpm: versionUploadTrack.bpm,
            active_version_id: versionUploadTrack.active_version_id,
          }}
          onUpdate={onTrackUpdate}
          showBackdrop={true}
        />
      )}

      <CoverArtOptionsModal
        isOpen={isCoverModalOpen}
        onClose={onCloseCoverModal}
        onLibraryClick={onLibraryClick}
        onExportClick={onExportCover}
        hasExistingCover={hasExistingCover}
        canEdit={canEditCover}
        canDownload={canDownloadCover}
      />

      {isSmallScreen && (
        <BaseModal isOpen={isNotesOpen} onClose={onCloseNotes} maxWidth="lg">
          <div className="p-6 min-h-[300px]">
            {notesTrack ? (
              <NotesPanel
                mode="track"
                selectedTrack={notesTrack}
                onClose={onCloseNotes}
              />
            ) : (
              <NotesPanel
                mode="project"
                project={project}
                onClose={onCloseNotes}
              />
            )}
          </div>
        </BaseModal>
      )}

      <GlobalSearchModal
        isOpen={isGlobalSearchOpen}
        onClose={onCloseGlobalSearch}
      />
    </>
  );
}
