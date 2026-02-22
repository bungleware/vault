import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import type { Project, UpdateProjectRequest } from '../types/api'
import * as projectsApi from '../api/projects'

export const projectKeys = {
  all: ['projects'] as const,
  lists: () => [...projectKeys.all, 'list'] as const,
  list: (folderId?: number | 'root') => [...projectKeys.lists(), { folderId }] as const,
  details: () => [...projectKeys.all, 'detail'] as const,
  detail: (id: string) => [...projectKeys.details(), id] as const,
}

/** @param folderId - If 'root', returns root-level projects. If number, returns projects in that folder. If undefined, returns all. */
export function useProjects(folderId?: number | 'root') {
  return useQuery({
    queryKey: projectKeys.list(folderId),
    queryFn: () => projectsApi.getProjects(folderId),
  })
}

export function useProject(id: string | undefined) {
  return useQuery({
    queryKey: projectKeys.detail(id as string),
    queryFn: () => projectsApi.getProject(id as string),
    enabled: !!id,
  })
}

export function useCreateProject() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: projectsApi.createProject,
    onSuccess: (newProject) => {
      queryClient.invalidateQueries({ queryKey: projectKeys.lists() })
      queryClient.setQueryData(projectKeys.detail(newProject.public_id), newProject)
    },
  })
}

export function useUpdateProject() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: UpdateProjectRequest }) =>
      projectsApi.updateProject(id, data),
    onMutate: async ({ id, data }) => {
      await queryClient.cancelQueries({ queryKey: projectKeys.detail(id) })
      const previousProject = queryClient.getQueryData<Project>(
        projectKeys.detail(id)
      )
      if (previousProject) {
        queryClient.setQueryData<Project>(projectKeys.detail(id), {
          ...previousProject,
          ...data,
          updated_at: new Date().toISOString(),
        })
      }
      return { previousProject }
    },
    onError: (_err, { id }, context) => {
      if (context?.previousProject) {
        queryClient.setQueryData(projectKeys.detail(id), context.previousProject)
      }
    },
    onSettled: (_data, _error, { id }) => {
      queryClient.invalidateQueries({ queryKey: projectKeys.detail(id) })
      queryClient.invalidateQueries({ queryKey: projectKeys.lists() })
    },
  })
}

export function useDeleteProject() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: projectsApi.deleteProject,
    onMutate: async (id) => {
      await queryClient.cancelQueries({ queryKey: projectKeys.lists() })
      const previousProjects = queryClient.getQueryData<Project[]>(
        projectKeys.list()
      )
      if (previousProjects) {
        queryClient.setQueryData<Project[]>(
          projectKeys.list(),
          previousProjects.filter((p) => p.public_id !== id)
        )
      }
      return { previousProjects }
    },
    onError: (_err, _id, context) => {
      if (context?.previousProjects) {
        queryClient.setQueryData(projectKeys.list(), context.previousProjects)
      }
    },
    onSettled: () => {
      queryClient.invalidateQueries({ queryKey: projectKeys.lists() })
      queryClient.invalidateQueries({ queryKey: ['folders'] })
    },
  })
}

export function useMoveProject() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ id, folderId }: { id: string; folderId: number | null }) =>
      projectsApi.moveProject(id, { folder_id: folderId }),
    onSettled: () => {
      queryClient.invalidateQueries({ queryKey: projectKeys.lists() })
      queryClient.invalidateQueries({ queryKey: ['folders'] })
    },
  })
}

export function useMoveProjectsToFolder() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (params: {
      projectIds?: string[]
      projects?: projectsApi.ProjectWithOrder[]
      folderId: number
    }) => projectsApi.moveProjectsToFolder(params),
    onSettled: () => {
      queryClient.invalidateQueries({ queryKey: projectKeys.lists() })
      queryClient.invalidateQueries({ queryKey: ['folders'] })
    },
  })
}

export function useDuplicateProject() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (id: string) => projectsApi.duplicateProject(id),
    onSuccess: (newProject) => {
      queryClient.invalidateQueries({ queryKey: projectKeys.lists() })
      queryClient.invalidateQueries({ queryKey: ['folders'] })
      queryClient.setQueryData(projectKeys.detail(newProject.public_id), newProject)
    },
  })
}

export function useExportProject() {
  return useMutation({
    mutationFn: async ({ id, projectName }: { id: string; projectName: string }) => {
      const blob = await projectsApi.exportProject(id)
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = `${projectName}.zip`
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
      URL.revokeObjectURL(url)

      return blob
    },
  })
}

export function useUpdateProjectNotes() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ id, notes, authorName }: { id: string; notes: string; authorName?: string }) =>
      projectsApi.updateProjectNotes(id, notes, authorName),
    onSuccess: (updatedProject) => {
      queryClient.setQueryData(projectKeys.detail(updatedProject.public_id), updatedProject)
      queryClient.invalidateQueries({ queryKey: projectKeys.lists() })
    },
  })
}

export function usePrefetchProjects() {
  const queryClient = useQueryClient()

  return () => {
    queryClient.prefetchQuery({
      queryKey: projectKeys.list(),
      queryFn: () => projectsApi.getProjects(),
    })
  }
}
