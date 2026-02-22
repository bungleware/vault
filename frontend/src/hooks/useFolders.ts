import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import type { Folder, CreateFolderRequest, UpdateFolderRequest } from '../types/api'
import * as foldersApi from '../api/folders'
import { projectKeys } from './useProjects'

export const folderKeys = {
  all: ['folders'] as const,
  lists: () => [...folderKeys.all, 'list'] as const,
  list: (parentId?: number) => [...folderKeys.lists(), { parentId }] as const,
  allList: () => [...folderKeys.all, 'all'] as const,
  details: () => [...folderKeys.all, 'detail'] as const,
  detail: (id: number) => [...folderKeys.details(), id] as const,
  contents: (id: number) => [...folderKeys.all, 'contents', id] as const,
}

/** @param parentId - If provided, returns subfolders of that folder. Otherwise returns root folders. */
export function useFolders(parentId?: number) {
  return useQuery({
    queryKey: folderKeys.list(parentId),
    queryFn: () => foldersApi.getFolders(parentId),
  })
}

export function useAllFolders() {
  return useQuery({
    queryKey: folderKeys.allList(),
    queryFn: foldersApi.getAllFolders,
  })
}

export function useFolder(id: number | undefined) {
  return useQuery({
    queryKey: folderKeys.detail(id as number),
    queryFn: () => foldersApi.getFolder(id as number),
    enabled: id !== undefined,
  })
}

export function useFolderContents(id: number | undefined) {
  return useQuery({
    queryKey: folderKeys.contents(id as number),
    queryFn: () => foldersApi.getFolderContents(id as number),
    enabled: id !== undefined,
  })
}

export function useCreateFolder() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (data: CreateFolderRequest) => foldersApi.createFolder(data),
    onSuccess: (newFolder) => {
      queryClient.invalidateQueries({ queryKey: folderKeys.lists() })
      queryClient.invalidateQueries({ queryKey: folderKeys.allList() })
      queryClient.setQueryData(folderKeys.detail(newFolder.id), newFolder)
      if (newFolder.parent_id) {
        queryClient.invalidateQueries({ queryKey: folderKeys.contents(newFolder.parent_id) })
      }
    },
  })
}

export function useUpdateFolder() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ id, data }: { id: number; data: UpdateFolderRequest }) =>
      foldersApi.updateFolder(id, data),
    onMutate: async ({ id, data }) => {
      await queryClient.cancelQueries({ queryKey: folderKeys.detail(id) })
      const previousFolder = queryClient.getQueryData<Folder>(
        folderKeys.detail(id)
      )
      if (previousFolder) {
        queryClient.setQueryData<Folder>(folderKeys.detail(id), {
          ...previousFolder,
          ...data,
          updated_at: new Date().toISOString(),
        })
      }

      return { previousFolder }
    },
    onError: (_err, { id }, context) => {
      if (context?.previousFolder) {
        queryClient.setQueryData(folderKeys.detail(id), context.previousFolder)
      }
    },
    onSettled: (data, _error, { id }) => {
      queryClient.invalidateQueries({ queryKey: folderKeys.detail(id) })
      queryClient.invalidateQueries({ queryKey: folderKeys.contents(id) })
      queryClient.invalidateQueries({ queryKey: folderKeys.lists() })
      queryClient.invalidateQueries({ queryKey: folderKeys.allList() })
      const folder = data || queryClient.getQueryData<Folder>(folderKeys.detail(id))
      if (folder?.parent_id) {
        queryClient.invalidateQueries({ queryKey: folderKeys.contents(folder.parent_id) })
      }
    },
  })
}

export function useEmptyFolder() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async (id: number) => {
      const folder = await foldersApi.getFolder(id)
      await foldersApi.emptyFolder(id)
      return { folder, emptiedFolderId: id }
    },
    onSuccess: (data, _id) => {
      const { folder, emptiedFolderId } = data
      queryClient.invalidateQueries({ queryKey: folderKeys.contents(emptiedFolderId) })
      if (folder.parent_id) {
        queryClient.invalidateQueries({ queryKey: folderKeys.contents(folder.parent_id) })
        queryClient.invalidateQueries({ queryKey: projectKeys.list(folder.parent_id) })
      } else {
        queryClient.invalidateQueries({ queryKey: projectKeys.list('root') })
      }
      queryClient.invalidateQueries({ queryKey: folderKeys.lists() })
      queryClient.invalidateQueries({ queryKey: folderKeys.allList() })
      queryClient.invalidateQueries({ queryKey: projectKeys.lists() })
    },
  })
}

export function useMoveFolder() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async ({ id, parentId }: { id: number; parentId: number | null }) => {
      const currentFolder = await foldersApi.getFolder(id)
      const oldParentId = currentFolder.parent_id
      const parentIdForApi = parentId === null ? 0 : parentId
      const updatedFolder = await foldersApi.updateFolder(id, { parent_id: parentIdForApi })
      
      return { updatedFolder, oldParentId, newParentId: parentId }
    },
    onSuccess: (data) => {
      const { updatedFolder, oldParentId, newParentId } = data
      queryClient.invalidateQueries({ queryKey: folderKeys.lists() })
      queryClient.invalidateQueries({ queryKey: folderKeys.allList() })
      if (oldParentId) {
        queryClient.invalidateQueries({ queryKey: folderKeys.contents(oldParentId) })
      }
      if (newParentId) {
        queryClient.invalidateQueries({ queryKey: folderKeys.contents(newParentId) })
      } else {
        queryClient.invalidateQueries({ queryKey: folderKeys.list() })
      }
      queryClient.invalidateQueries({ queryKey: folderKeys.contents(updatedFolder.id) })
      queryClient.invalidateQueries({ queryKey: projectKeys.lists() })
    },
  })
}

export function useDeleteFolder() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (id: number) => foldersApi.deleteFolder(id),
    onSettled: () => {
      queryClient.invalidateQueries({ queryKey: folderKeys.all })
      queryClient.invalidateQueries({ queryKey: ['projects'] })
    },
  })
}

export function usePrefetchFolders() {
  const queryClient = useQueryClient()

  return () => {
    queryClient.prefetchQuery({
      queryKey: folderKeys.allList(),
      queryFn: foldersApi.getAllFolders,
    })
  }
}
