import { get, post, put, del } from './client'
import type { Folder, FolderContents, CreateFolderRequest, UpdateFolderRequest } from '../types/api'

export async function getFolders(parentId?: number): Promise<Folder[]> {
  const params = parentId !== undefined ? `?parent_id=${parentId}` : ''
  return get<Folder[]>(`/api/folders${params}`)
}

export async function getAllFolders(): Promise<Folder[]> {
  return get<Folder[]>('/api/folders/all')
}

export async function getFolder(id: number): Promise<Folder> {
  return get<Folder>(`/api/folders/${id}`)
}

export async function getFolderContents(id: number): Promise<FolderContents> {
  return get<FolderContents>(`/api/folders/${id}/contents`)
}

export async function createFolder(data: CreateFolderRequest): Promise<Folder> {
  return post<Folder>('/api/folders', data)
}

export async function updateFolder(id: number, data: UpdateFolderRequest): Promise<Folder> {
  return put<Folder>(`/api/folders/${id}`, data)
}

export async function emptyFolder(id: number): Promise<void> {
  return post<void>(`/api/folders/${id}/empty`, {})
}

export async function deleteFolder(id: number): Promise<void> {
  return del<void>(`/api/folders/${id}`)
}
