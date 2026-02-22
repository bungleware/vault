import { useQuery, useQueryClient } from '@tanstack/react-query'
import { listUsersPublic } from '../api/admin'
import { listProjectShareUsers, listTrackShareUsers } from '../api/sharing'

export const sharingKeys = {
  all: ['sharing'] as const,
  users: () => [...sharingKeys.all, 'users'] as const,
  projectShareUsers: (projectId: string) => [...sharingKeys.all, 'project-users', projectId] as const,
  trackShareUsers: (trackId: string) => [...sharingKeys.all, 'track-users', trackId] as const,
}

export function useAllUsers() {
  return useQuery({
    queryKey: sharingKeys.users(),
    queryFn: listUsersPublic,
    staleTime: 5 * 60 * 1000, // 5 minutes
  })
}

export function useProjectShareUsers(projectId: string | undefined) {
  return useQuery({
    queryKey: sharingKeys.projectShareUsers(projectId as string),
    queryFn: () => listProjectShareUsers(projectId as string),
    enabled: projectId !== undefined,
    staleTime: 60 * 1000, // 1 minute
  })
}

export function useTrackShareUsers(trackId: string | undefined) {
  return useQuery({
    queryKey: sharingKeys.trackShareUsers(trackId as string),
    queryFn: () => listTrackShareUsers(trackId as string),
    enabled: trackId !== undefined,
    staleTime: 60 * 1000, // 1 minute
  })
}

export function usePrefetchSharingData() {
  const queryClient = useQueryClient()

  return (resourceType: 'project' | 'track', resourceId: string) => {
    // Prefetch all users
    queryClient.prefetchQuery({
      queryKey: sharingKeys.users(),
      queryFn: listUsersPublic,
      staleTime: 5 * 60 * 1000,
    })

    // Prefetch share users for the specific resource
    if (resourceType === 'project') {
      queryClient.prefetchQuery({
        queryKey: sharingKeys.projectShareUsers(resourceId),
        queryFn: () => listProjectShareUsers(resourceId),
        staleTime: 60 * 1000,
      })
    } else {
      queryClient.prefetchQuery({
        queryKey: sharingKeys.trackShareUsers(resourceId),
        queryFn: () => listTrackShareUsers(resourceId),
        staleTime: 60 * 1000,
      })
    }
  }
}
