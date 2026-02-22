import { put, post } from './client'
import type {
  OrganizeItemRequest,
  BulkOrganizeRequest,
  SharedProjectOrganization,
  SharedTrackOrganization,
} from '../types/api'


export async function organizeSharedProject(
  projectId: number,
  data: OrganizeItemRequest
): Promise<SharedProjectOrganization> {
  return put<SharedProjectOrganization>(`/api/shared-projects/${projectId}/organize`, data)
}

export async function organizeSharedTrack(
  trackId: number,
  data: OrganizeItemRequest
): Promise<SharedTrackOrganization> {
  return put<SharedTrackOrganization>(`/api/shared-tracks/${trackId}/organize`, data)
}

export async function bulkOrganize(data: BulkOrganizeRequest): Promise<void> {
  return post<void>('/api/organize/bulk', data)
}
