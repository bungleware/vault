import { post, getCSRFToken } from './client'

export async function exportInstance(): Promise<void> {
	try {
		const response = await fetch('/api/admin/instance/export', {
			method: 'GET',
			credentials: 'include',
		})

    if (!response.ok) {
      throw new Error('Failed to export instance')
    }

    const contentDisposition = response.headers.get('content-disposition')
    let filename = 'vault-backup.zip'
    if (contentDisposition) {
      const match = contentDisposition.match(/filename="(.+?)"/)
      if (match) {
        filename = match[1]
      }
    }

    const blob = await response.blob()
    const url = window.URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = filename
    document.body.appendChild(link)
    link.click()
    link.remove()
    window.URL.revokeObjectURL(url)
  } catch (error) {
    console.error('Failed to export instance:', error)
    throw error
  }
}

export async function importInstance(file: File): Promise<void> {
	const formData = new FormData()
	formData.append('backup', file)

	const response = await fetch('/api/admin/instance/import', {
		method: 'POST',
		credentials: 'include',
		headers: getCSRFToken() ? { 'X-CSRF-Token': getCSRFToken() as string } : {},
		body: formData,
	})

  if (!response.ok) {
    const error = await response.text()
    throw new Error(error || 'Failed to import instance')
  }

  return await response.json()
}

export async function resetInstance(
  confirmName: string,
  newAdmin: { username: string; email: string; password: string }
): Promise<void> {
  return post('/api/admin/instance/reset', {
    confirm_name: confirmName,
    new_admin: newAdmin,
  })
}
