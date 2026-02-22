import { get, post, put, del } from './client'
import type { User, LoginRequest, RegisterRequest, AuthResponse } from '../types/api'

export async function register(data: RegisterRequest): Promise<AuthResponse> {
  return post<AuthResponse>('/api/auth/register', data, { requiresAuth: false })
}

export async function login(credentials: LoginRequest): Promise<AuthResponse> {
	return post<AuthResponse>('/api/auth/login', credentials, { requiresAuth: false })
}

export async function refresh(): Promise<AuthResponse> {
	return post<AuthResponse>('/api/auth/refresh', {}, { requiresAuth: false })
}

export async function getMe(): Promise<User> {
  return get<User>('/api/auth/me')
}

export async function checkUsersExist(): Promise<{ users_exist: boolean }> {
  return get<{ users_exist: boolean }>('/api/auth/check-users', {
    requiresAuth: false,
  })
}

export async function updateUsername(username: string): Promise<User> {
  return put<User>('/api/auth/username', { username })
}

export async function deleteAccount(password: string): Promise<void> {
	return del<void>('/api/auth/me', { body: JSON.stringify({ password }) })
}

export async function logout(): Promise<{ status: string }> {
	return post<{ status: string }>('/api/auth/logout', {})
}
