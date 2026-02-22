import { get, post, put, del, getCSRFToken } from './client'
import { getProjectCoverUrl } from './media'
import type { Project, CreateProjectRequest, UpdateProjectRequest, MoveProjectRequest } from '../types/api'
import { env } from '../env'

const API_BASE_URL = env.VITE_API_URL || ''

export async function getProjects(folderId?: number | 'root'): Promise<Project[]> {
  const params = folderId !== undefined ? `?folder_id=${folderId}` : ''
  return get<Project[]>(`/api/projects${params}`)
}

export async function getProject(id: string): Promise<Project> {
  return get<Project>(`/api/projects/${id}`)
}

export async function createProject(data: CreateProjectRequest): Promise<Project> {
  return post<Project>('/api/projects', data)
}

export async function updateProject(
  id: string,
  data: UpdateProjectRequest
): Promise<Project> {
  return put<Project>(`/api/projects/${id}`, data)
}

export async function updateProjectNotes(id: string, notes: string, authorName?: string): Promise<Project> {
  return updateProject(id, { notes, notes_author_name: authorName })
}

export async function deleteProject(id: string): Promise<void> {
  return del<void>(`/api/projects/${id}`)
}

export async function moveProject(id: string, data: MoveProjectRequest): Promise<Project> {
  return put<Project>(`/api/projects/${id}/folder`, data)
}

export interface ProjectWithOrder {
  project_id: string
  custom_order: number
}

export async function moveProjectsToFolder(
  params: {
    projectIds?: string[]
    projects?: ProjectWithOrder[]
    folderId: number
  }
): Promise<Project[]> {
  return post<Project[]>('/api/projects/move-to-folder', {
    project_ids: params.projectIds,
    projects: params.projects,
    folder_id: params.folderId,
  })
}

export async function uploadProjectCover(id: string, file: File): Promise<Project> {
	const formData = new FormData()
	formData.append('cover', file)
	const response = await fetch(`${API_BASE_URL}/api/projects/${id}/cover`, {
		method: 'PUT',
		credentials: 'include',
		headers: getCSRFToken() ? { 'X-CSRF-Token': getCSRFToken() as string } : {},
		body: formData,
	})

  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: 'Failed to upload cover' }))
    throw new Error(error.error || 'Failed to upload cover')
  }

  return response.json()
}

export async function deleteProjectCover(id: string): Promise<Project> {
	const response = await fetch(`${API_BASE_URL}/api/projects/${id}/cover`, {
		method: 'DELETE',
		credentials: 'include',
		headers: getCSRFToken() ? { 'X-CSRF-Token': getCSRFToken() as string } : {},
	})

  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: 'Failed to delete cover' }))
    throw new Error(error.error || 'Failed to delete cover')
  }

  return response.json()
}

export type CoverSize = 'small' | 'medium' | 'large' | 'source'

export async function fetchProjectCover(
  id: string,
  coverUrl?: string | null,
  size?: CoverSize
): Promise<Blob> {
	if (coverUrl?.startsWith('/api/share/')) {
		let url = `${API_BASE_URL}${coverUrl}`
		if (size) {
			const separator = url.includes('?') ? '&' : '?'
			url = `${url}${separator}size=${size}`
		}
		const response = await fetch(url)
		if (!response.ok) {
			throw new Error('Failed to load cover art')
		}
		return response.blob()
	}

	const signed = await getProjectCoverUrl(id, { size })
	const response = await fetch(`${API_BASE_URL}${signed.url}`)

	if (!response.ok) {
		throw new Error('Failed to load cover art')
	}

  return response.blob()
}

export async function duplicateProject(id: string): Promise<Project> {
  return post<Project>(`/api/projects/${id}/duplicate`)
}

export async function exportProject(id: string): Promise<Blob> {
	const response = await fetch(`${API_BASE_URL}/api/projects/${id}/export`, {
		credentials: 'include',
	})

  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: 'Failed to export project' }))
    throw new Error(error.error || 'Failed to export project')
  }

  return response.blob()
}
