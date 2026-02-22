export function formatTrackDuration(seconds?: number | null): string | undefined {
  if (seconds == null || Number.isNaN(seconds)) {
    return undefined
  }

  const totalSeconds = Math.max(0, Math.round(seconds))
  const minutes = Math.floor(totalSeconds / 60)
  const remainingSeconds = totalSeconds % 60

  return `${minutes}:${remainingSeconds.toString().padStart(2, "0")}`
}

export function formatDurationLong(seconds?: number | null): string {
  if (seconds == null || seconds <= 0 || Number.isNaN(seconds)) {
    return "0m"
  }

  const totalSeconds = Math.round(seconds)
  const hours = Math.floor(totalSeconds / 3600)
  const minutes = Math.floor((totalSeconds % 3600) / 60)
  const remainingSeconds = totalSeconds % 60

  const parts: string[] = []

  if (hours > 0) {
    parts.push(`${hours}h`)
  }

  if (minutes > 0 || hours > 0) {
    parts.push(`${minutes}m`)
  }

  if (hours === 0 && minutes === 0) {
    parts.push(`${remainingSeconds}s`)
  } else if (remainingSeconds > 0) {
    parts.push(`${remainingSeconds}s`)
  }

  return parts.join(" ")
}

