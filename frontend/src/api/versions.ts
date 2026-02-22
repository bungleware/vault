import { get, put, del, getCSRFToken } from './client'
import type { VersionWithMetadata, UpdateVersionRequest } from '../types/api'
import { env } from '../env'

const API_BASE_URL = env.VITE_API_URL || ''


export async function getVersions(trackId: string): Promise<VersionWithMetadata[]> {
  return get<VersionWithMetadata[]>(`/api/tracks/${trackId}/versions`)
}

export async function uploadVersion(
  trackId: string,
  file: File,
  versionName?: string,
  notes?: string
): Promise<VersionWithMetadata> {
  const formData = new FormData()
  formData.append('file', file)
  
  if (versionName) {
    formData.append('version_name', versionName)
  }
  
  if (notes) {
    formData.append('notes', notes)
  }

	const response = await fetch(`${API_BASE_URL}/api/tracks/${trackId}/versions/upload`, {
		method: 'POST',
		credentials: 'include',
		headers: getCSRFToken() ? { 'X-CSRF-Token': getCSRFToken() as string } : {},
		body: formData,
	})

  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: 'Upload failed' }))
    throw new Error(error.error || 'Upload failed')
  }

  return response.json()
}

export async function updateVersion(
  versionId: number,
  data: UpdateVersionRequest
): Promise<VersionWithMetadata> {
  return put<VersionWithMetadata>(`/api/versions/${versionId}`, data)
}

export async function activateVersion(versionId: number): Promise<void> {
	const response = await fetch(`${API_BASE_URL}/api/versions/${versionId}/activate`, {
		method: 'POST',
		credentials: 'include',
		headers: getCSRFToken() ? { 'X-CSRF-Token': getCSRFToken() as string } : {},
	})

  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: 'Failed to activate version' }))
    throw new Error(error.error || 'Failed to activate version')
  }
}

export async function deleteVersion(versionId: number): Promise<void> {
  return del<void>(`/api/versions/${versionId}`)
}

export function getVersionDownloadUrl(trackId: string, versionId: number): string {
  return `${API_BASE_URL}/api/tracks/${trackId}/versions/${versionId}/download`
}

export async function downloadVersion(trackId: string, versionId: number): Promise<void> {
	const response = await fetch(getVersionDownloadUrl(trackId, versionId), {
		method: 'GET',
		credentials: 'include',
	})

  if (!response.ok) {
    throw new Error('Failed to download version')
  }

  const contentDisposition = response.headers.get('Content-Disposition')
  let filename = `version_${versionId}.wav`

  if (contentDisposition) {
    const filenameMatch = contentDisposition.match(/filename="([^"]+)"|filename=([^;]+)/i)
    if (filenameMatch) {
      filename = (filenameMatch[1] || filenameMatch[2]).trim()
    }
  }

  const blob = await response.blob()
  const url = window.URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  window.URL.revokeObjectURL(url)
  document.body.removeChild(a)
}
