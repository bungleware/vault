import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import * as tracksApi from '../api/tracks'

export const trackKeys = {
  all: ['tracks'] as const,
  lists: () => [...trackKeys.all, 'list'] as const,
  list: (projectId?: number) => [...trackKeys.lists(), { projectId }] as const,
  details: () => [...trackKeys.all, 'detail'] as const,
  detail: (id: string) => [...trackKeys.details(), id] as const,
}

export function useTracks(projectId?: number | null) {
  const normalizedProjectId = typeof projectId === 'number' ? projectId : undefined
  const shouldEnable = projectId !== null

  return useQuery({
    queryKey: trackKeys.list(normalizedProjectId),
    queryFn: () => tracksApi.getTracks(normalizedProjectId),
    enabled: shouldEnable,
  })
}

export function useTrack(id: string) {
  return useQuery({
    queryKey: trackKeys.detail(id),
    queryFn: () => tracksApi.getTrack(id),
    enabled: !!id,
    retry: (failureCount, error: any) => {
      if (error?.response?.status === 404 || error?.response?.status === 403) {
        return false
      }
      return failureCount < 3
    },
  })
}

export function useUpdateTrackNotes() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ trackId, notes, authorName }: { trackId: string; notes: string; authorName?: string }) =>
      tracksApi.updateTrackNotes(trackId, notes, authorName),
    onSuccess: (updatedTrack) => {
      queryClient.invalidateQueries({ queryKey: trackKeys.lists() })
      queryClient.setQueryData(trackKeys.detail(updatedTrack.public_id), updatedTrack)
    },
  })
}
