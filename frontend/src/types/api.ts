export type Quality = "source" | "lossless" | "lossy";

export type TranscodingStatus = 'pending' | 'processing' | 'completed' | 'failed'

export type VisibilityStatus = 'private' | 'invite_only' | 'public'

export interface User {
  id: number
  username: string
  email: string
  is_admin: boolean
  is_owner: boolean
  created_at: string 
  updated_at: string
}

export interface UserPreferences {
  user_id: number
  default_quality: Quality
  disc_colors?: string[]
  color_spread?: number
  gradient_spread?: number
  color_shift_rotation?: number
  created_at: string
  updated_at: string
}

export interface Project {
  id: number
  user_id: number
  public_id: string
  name: string
  description?: string | null
  quality_override?: Quality | null
  author_override?: string | null
  notes?: string | null
  notes_author_name?: string | null
  notes_updated_at?: string | null
  cover_url?: string | null
  folder_id?: number | null
  custom_order?: number
  visibility_status: VisibilityStatus
  allow_editing: boolean
  allow_downloads: boolean
  owner_username: string
  is_shared: boolean
  shared_by_username?: string | null
  created_at: string
  updated_at: string
}

export interface Folder {
  id: number
  name: string
  parent_id?: number | null
  folder_order: number
  created_at: string
  updated_at: string
}

export interface FolderContents {
  folder: Folder
  folders: Folder[]
  projects: Project[]
  shared_tracks: SharedTrackResponse[]
}

export interface Track {
  id: number
  user_id: number
  project_id: number
  public_id: string
  title: string
  artist?: string | null
  album?: string | null
  key?: string | null
  bpm?: number | null
  notes?: string | null
  notes_author_name?: string | null
  notes_updated_at?: string | null
  active_version_id?: number | null
  active_version_duration_seconds?: number | null
  track_order: number
  created_at: string
  updated_at: string
  waveform?: string | null
  lossy_transcoding_status?: TranscodingStatus | null
  visibility_status?: VisibilityStatus
}

export interface TrackWithShareInfo extends Track {
  folder_id?: number | null
  can_edit?: boolean
  can_download?: boolean
  project_name?: string
  project_public_id?: string
  project_cover_url?: string | null
}

export interface TrackVersion {
  id: number
  track_id: number
  version_name: string
  notes?: string | null
  duration_seconds?: number | null
  version_order: number
  created_at: string
  updated_at: string
}

export interface VersionWithMetadata extends TrackVersion {
  source_file_size?: number | null
  source_format?: string | null
  source_bitrate?: number | null
  source_original_filename?: string | null
  lossy_transcoding_status?: TranscodingStatus | null
  waveform?: string | null
}

export interface RegisterRequest {
  username: string
  email: string
  password: string
  instance_name?: string
  setup_token?: string
}

export interface LoginRequest {
  username: string
  password: string
}

export interface UpdatePreferencesRequest {
  default_quality?: Quality
  disc_colors?: string[]
  color_spread?: number
  gradient_spread?: number
  color_shift_rotation?: number
}

export interface UpdateInstanceNameRequest {
  name: string
}

export interface CreateProjectRequest {
  name: string
  description?: string
  quality_override?: Quality
  author_override?: string
  folder_id?: number
}

export interface UpdateProjectRequest {
  name?: string
  description?: string
  quality_override?: Quality
  author_override?: string
  notes?: string
  notes_author_name?: string
}

export interface MoveProjectRequest {
  folder_id: number | null
}

export interface CreateFolderRequest {
  name: string
  parent_id?: number | null
}

export interface UpdateFolderRequest {
  name?: string
  parent_id?: number | null
}

export interface CreateTrackRequest {
  project_id: number
  title: string
  artist?: string
  album?: string
}

export interface UpdateTrackRequest {
  title?: string
  artist?: string
  album?: string
  project_id?: number
  key?: string
  bpm?: number
  notes?: string
  notes_author_name?: string
}

export interface UpdateVersionRequest {
  version_name?: string
  notes?: string
}

export interface AuthResponse {
	user: User
}

export interface Note {
  id: number
  user_id: number
  content: string
  author_name: string
  created_at: string
  updated_at: string
  is_owner: boolean
}

export interface UpsertNoteRequest {
  content: string
  author_name: string
}

export interface StorageStats {
  total_size_bytes: number
  source_size_bytes: number
  lossless_size_bytes: number
  lossy_size_bytes: number
  file_count: number
  project_count: number
  track_count: number
}

export interface InstanceInfo {
  version: string
  commit_sha?: string
  name: string
  created_at?: string
  storage_quota_bytes?: number | null
  storage_used_bytes?: number
}

export interface InstanceVersion {
  version: string
  commit_sha?: string
}

export type ShareType = 'track' | 'project'

export interface SharePermissions {
  allow_editing: boolean
  allow_downloads: boolean
  password?: string
}

export interface ShareToken {
  id: number
  token: string
  user_id: number
  track_id?: number
  track_public_id?: string
  project_id?: number
  project_public_id?: string
  version_id?: number | null
  expires_at?: string | null
  max_access_count?: number | null
  current_access_count: number
  allow_editing: boolean
  allow_downloads: boolean
  visibility_type: 'invite_only' | 'public'
  has_password: boolean
  created_at: string
  updated_at: string
  share_url: string
}

export interface CreateShareTokenRequest {
  track_id?: number
  project_id?: number
  version_id?: number
  expires_at?: string
  max_access_count?: number
  allow_editing?: boolean
  allow_downloads?: boolean
  password?: string
  visibility_type?: 'invite_only' | 'public'
}

export interface UpdateVisibilityRequest {
  visibility_status: VisibilityStatus
  allow_editing: boolean
  allow_downloads: boolean
  password?: string
}

export interface AcceptShareRequest {
  password?: string
  user_instance_url?: string
}

export interface ShareAccess {
  id: number
  share_type: ShareType
  share_token_id: number
  user_id: number
  user_instance_url?: string | null
  federation_token_id?: number | null
  accepted_at: string
  last_accessed_at?: string | null
  access_count: number
  can_edit: boolean
  can_download: boolean
}

export interface ValidateShareResponse {
  valid: boolean
  password_required?: boolean
  error?: string
  track?: Track
  project?: Project
  project_id?: number
  version?: TrackVersion
  allow_editing?: boolean
  allow_downloads?: boolean
}

export interface SharedTrackResponse {
  id: number
  public_id: string
  title: string
  artist?: string | null
  cover_url?: string | null
  project_name: string
  project_id?: number
  project_public_id?: string
  waveform?: string | null
  duration_seconds?: number | null
  shared_by_username: string
  can_download: boolean
  folder_id?: number | null
  custom_order?: number
}

export interface SharedProjectOrganization {
  id: number
  user_id: number
  project_id: number
  folder_id?: number | null
  custom_order: number
  created_at: string
  updated_at: string
}

export interface SharedTrackOrganization {
  id: number
  user_id: number
  track_id: number
  folder_id?: number | null
  custom_order: number
  created_at: string
  updated_at: string
}

export interface OrganizeItemRequest {
  folder_id?: number | null
  custom_order?: number
}

export interface BulkOrganizeItem {
  type: 'project' | 'track'
  id: number
  is_shared: boolean
  folder_id?: number | null
  custom_order: number
}

export interface BulkOrganizeRequest {
  items: BulkOrganizeItem[]
}

