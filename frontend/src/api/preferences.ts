import { get, put } from './client'
import type { UserPreferences, UpdatePreferencesRequest } from '../types/api'

export async function getPreferences(): Promise<UserPreferences> {
  return get<UserPreferences>('/api/preferences')
}

export async function updatePreferences(
  data: UpdatePreferencesRequest
): Promise<UserPreferences> {
  return put<UserPreferences>('/api/preferences', data)
}
