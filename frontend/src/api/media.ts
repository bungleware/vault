import { get } from './client'

export async function getStreamUrl(
	trackId: string,
	params?: { quality?: string; versionId?: number | null }
): Promise<{ url: string }> {
	const query = new URLSearchParams()
	if (params?.quality) {
		query.set('quality', params.quality)
	}
	if (params?.versionId) {
		query.set('version_id', String(params.versionId))
	}
	const suffix = query.toString() ? `?${query.toString()}` : ''
	return get<{ url: string }>(`/api/media/stream/${trackId}${suffix}`)
}

export async function getProjectCoverUrl(
	projectId: string,
	params?: { size?: string }
): Promise<{ url: string }> {
	const query = new URLSearchParams()
	if (params?.size) {
		query.set('size', params.size)
	}
	const suffix = query.toString() ? `?${query.toString()}` : ''
	return get<{ url: string }>(`/api/media/projects/${projectId}/cover${suffix}`)
}
