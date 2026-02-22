import { useEffect, useState } from 'react'
import type { Project } from '@/types/api'
import { fetchProjectCover, type CoverSize } from '@/api/projects'

const coverCache = new Map<string, string>()
const coverRefCounts = new Map<string, number>()

export function getCachedCoverUrl(
  project?: { public_id: string; cover_url?: string | null },
  size?: CoverSize
): string | null {
  if (!project?.cover_url) return null
  const cacheKey = `${project.public_id}|${project.cover_url}|${size ?? 'default'}`
  return coverCache.get(cacheKey) ?? null
}

export function preloadCover(
  project: { public_id: string; cover_url?: string | null },
  size?: CoverSize
): void {
  if (!project?.cover_url) return
  const cacheKey = `${project.public_id}|${project.cover_url}|${size ?? 'default'}`
  if (coverCache.has(cacheKey)) return

  fetchProjectCover(project.public_id, project.cover_url, size)
    .then((blob) => {
      const url = URL.createObjectURL(blob)
      retainCover(cacheKey, url)
    })
    .catch(() => {})
}

function retainCover(key: string, url: string) {
  coverCache.set(key, url)
  coverRefCounts.set(key, (coverRefCounts.get(key) ?? 0) + 1)
}

function releaseCover(key: string) {
  const nextCount = (coverRefCounts.get(key) ?? 0) - 1
  if (nextCount <= 0) {
    coverRefCounts.delete(key)
    const cachedUrl = coverCache.get(key)
    if (cachedUrl) {
      URL.revokeObjectURL(cachedUrl)
      coverCache.delete(key)
    }
  } else {
    coverRefCounts.set(key, nextCount)
  }
}

export function useProjectCoverImage(
  project?: Pick<Project, 'public_id' | 'cover_url'> | Project,
  size?: CoverSize
) {
  const cacheKey = project?.cover_url
    ? `${project.public_id}|${project.cover_url}|${size ?? 'default'}`
    : null
  const cachedValue = cacheKey ? coverCache.get(cacheKey) ?? null : null
  if (cachedValue && cacheKey) {
    retainCover(cacheKey, cachedValue)
  }
  const [imageUrl, setImageUrl] = useState<string | null>(cachedValue)
  const [isLoading, setIsLoading] = useState(!cachedValue && !!cacheKey && !!project?.cover_url)

  useEffect(() => {
    if (!project?.public_id || !project?.cover_url) {
      setImageUrl(null)
      setIsLoading(false)
      return
    }
    const currentCacheKey = `${project.public_id}|${project.cover_url}|${size ?? 'default'}`

    const cached = coverCache.get(currentCacheKey)
    if (cached) {
      if (cached !== imageUrl) {
        retainCover(currentCacheKey, cached)
        setImageUrl(cached)
      }
      setIsLoading(false)
      return () => releaseCover(currentCacheKey)
    }
    if (imageUrl && !cached) {
      setImageUrl(null)
    }

    let cancelled = false
    let localUrl: string | null = null
    setIsLoading(true)

    fetchProjectCover(project.public_id, project.cover_url, size)
      .then((blob) => {
        if (cancelled) {
          return
        }
        localUrl = URL.createObjectURL(blob)
        retainCover(currentCacheKey, localUrl)
        setImageUrl(localUrl)
      })
      .catch(() => {
        if (!cancelled) {
          setImageUrl(null)
        }
      })
      .finally(() => {
        if (!cancelled) {
          setIsLoading(false)
        }
      })

    return () => {
      cancelled = true
      if (localUrl && !coverCache.has(currentCacheKey)) {
        URL.revokeObjectURL(localUrl)
      } else {
        releaseCover(currentCacheKey)
      }
    }
  }, [project?.public_id, project?.cover_url, size])

  return { imageUrl, isLoading }
}


