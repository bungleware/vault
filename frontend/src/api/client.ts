import { env } from '../env'

const API_BASE_URL = env.VITE_API_URL || ''

export class ApiError extends Error {
  constructor(
    message: string,
    public status: number,
    public data?: any
  ) {
    super(message)
    this.name = 'ApiError'
  }
}

export interface RequestOptions extends RequestInit {
  requiresAuth?: boolean
}


function getCookieValue(name: string): string | null {
	if (typeof document === 'undefined') return null
	const match = document.cookie.match(new RegExp(`(?:^|; )${name}=([^;]*)`))
	return match ? decodeURIComponent(match[1]) : null
}

export function getCSRFToken(): string | null {
	return getCookieValue('csrf_token')
}

async function apiClient<T>(
  endpoint: string,
  options: RequestOptions = {}
): Promise<T> {
  const { requiresAuth = true, headers = {}, ...restOptions } = options

  const url = `${API_BASE_URL}${endpoint}`

	const requestHeaders: Record<string, string> = {
		'Content-Type': 'application/json',
		...(headers as Record<string, string>),
	}

	if (requiresAuth) {
		const method = (restOptions.method || 'GET').toUpperCase()
		if (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS') {
			const csrfToken = getCSRFToken()
			if (csrfToken) {
				requestHeaders['X-CSRF-Token'] = csrfToken
			}
		}
	}

  try {
		const response = await fetch(url, {
			...restOptions,
			headers: requestHeaders,
			credentials: 'include',
		})

		if (response.status === 401) {
			if (!endpoint.startsWith('/api/auth/me') && !endpoint.startsWith('/api/auth/refresh')) {
				const pathname = window.location.pathname
				if (!pathname.includes('/login') && !pathname.includes('/share/')) {
					window.location.href = '/login'
				}
			}
			throw new ApiError('Unauthorized', 401)
		}

    if (!response.ok) {
      let errorMessage = `HTTP ${response.status}: ${response.statusText}`
      let errorData: any

      try {
        errorData = await response.json()
        errorMessage = errorData.error || errorData.message || errorMessage
      } catch {
      }

      throw new ApiError(errorMessage, response.status, errorData)
    }

    if (response.status === 204 || response.headers.get('content-length') === '0') {
      return undefined as T
    }

    return await response.json()
  } catch (error) {
    if (error instanceof ApiError) {
      throw error
    }

    throw new ApiError(
      error instanceof Error ? error.message : 'Network error',
      0
    )
  }
}

export async function get<T>(endpoint: string, options?: RequestOptions): Promise<T> {
  return apiClient<T>(endpoint, { ...options, method: 'GET' })
}

export async function post<T>(
  endpoint: string,
  data?: any,
  options?: RequestOptions
): Promise<T> {
  return apiClient<T>(endpoint, {
    ...options,
    method: 'POST',
    body: data ? JSON.stringify(data) : undefined,
  })
}

export async function put<T>(
  endpoint: string,
  data?: any,
  options?: RequestOptions
): Promise<T> {
  return apiClient<T>(endpoint, {
    ...options,
    method: 'PUT',
    body: data ? JSON.stringify(data) : undefined,
  })
}

export async function del<T>(endpoint: string, options?: RequestOptions): Promise<T> {
  return apiClient<T>(endpoint, { ...options, method: 'DELETE' })
}

export async function patch<T>(
  endpoint: string,
  data?: any,
  options?: RequestOptions
): Promise<T> {
  return apiClient<T>(endpoint, {
    ...options,
    method: 'PATCH',
    body: data ? JSON.stringify(data) : undefined,
  })
}

// debugAuth helpers removed with cookie-based auth
