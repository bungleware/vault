import { get, put, del } from './client'
import type { Note, UpsertNoteRequest } from '../types/api'

export async function getTrackNotes(trackId: string): Promise<Note[]> {
  return get<Note[]>(`/api/tracks/${trackId}/notes`)
}

export async function getProjectNotes(projectId: string): Promise<Note[]> {
  return get<Note[]>(`/api/projects/${projectId}/notes`)
}

export async function upsertTrackNote(trackId: string, data: UpsertNoteRequest): Promise<Note> {
  return put<Note>(`/api/tracks/${trackId}/notes`, data)
}

export async function upsertProjectNote(projectId: string, data: UpsertNoteRequest): Promise<Note> {
  return put<Note>(`/api/projects/${projectId}/notes`, data)
}

export async function deleteNote(noteId: number): Promise<void> {
  return del<void>(`/api/notes/${noteId}`)
}
