import { get, put } from './client'
import type { StorageStats, InstanceInfo, InstanceVersion, UpdateInstanceNameRequest } from '../types/api'

export async function getStorageStats(): Promise<StorageStats> {
  return get<StorageStats>('/api/stats/storage')
}

export async function getGlobalStorageStats(): Promise<StorageStats> {
  return get<StorageStats>('/api/stats/storage/global')
}

export async function getInstanceInfo(): Promise<InstanceInfo> {
  return get<InstanceInfo>('/api/instance')
}

export async function getInstanceVersion(): Promise<InstanceVersion> {
  return get<InstanceVersion>('/api/instance/version', { requiresAuth: false })
}

export async function updateInstanceName(data: UpdateInstanceNameRequest): Promise<InstanceInfo> {
  return put<InstanceInfo>('/api/instance/name', data)
}
