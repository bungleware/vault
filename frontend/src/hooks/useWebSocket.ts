import { useEffect, useCallback } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { trackKeys } from './useTracks'
import { env } from '@/env'

const API_BASE_URL = env.VITE_API_URL || ''

interface WSMessage {
  type: string
  payload: unknown
}

let globalWs: WebSocket | null = null
let globalReconnectTimeout: ReturnType<typeof setTimeout> | null = null
let globalConnectTimeout: ReturnType<typeof setTimeout> | null = null
let isIntentionalDisconnect = false

/** @param enabled - Whether the WebSocket should connect (default: true) */
export function useWebSocket(enabled: boolean = true) {
  const queryClient = useQueryClient()

  useEffect(() => {
    if (!enabled) {
      return
    }

    isIntentionalDisconnect = false

    const connect = () => {
      if (globalWs && (globalWs.readyState === WebSocket.OPEN || globalWs.readyState === WebSocket.CONNECTING)) {
        return
      }

		const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
		const wsHost = API_BASE_URL
			? new URL(API_BASE_URL).host
			: window.location.host
		const wsUrl = `${wsProtocol}//${wsHost}/api/ws`

      const ws = new WebSocket(wsUrl)

      ws.onmessage = (event) => {
        try {
          const message: WSMessage = JSON.parse(event.data)

          if (message.type === 'transcoding_update') {
            queryClient.invalidateQueries({ queryKey: trackKeys.all })
          }
        } catch (error) {
          console.error('[WebSocket] Failed to parse message:', error)
        }
      }

      ws.onclose = (event) => {
        globalWs = null
        if (!isIntentionalDisconnect && event.code !== 1000) {
          globalReconnectTimeout = setTimeout(() => {
            connect()
          }, 3000)
        }
      }

      ws.onerror = (error) => {
        console.error('[WebSocket] Error:', error)
      }

      globalWs = ws
    }

    if (globalConnectTimeout) {
      clearTimeout(globalConnectTimeout)
    }
    globalConnectTimeout = setTimeout(() => {
      globalConnectTimeout = null
      connect()
    }, 50)

    return () => {}
  }, [enabled, queryClient])

  const disconnect = useCallback(() => {
    isIntentionalDisconnect = true
    if (globalConnectTimeout) {
      clearTimeout(globalConnectTimeout)
      globalConnectTimeout = null
    }
    if (globalReconnectTimeout) {
      clearTimeout(globalReconnectTimeout)
      globalReconnectTimeout = null
    }
    if (globalWs) {
      globalWs.close(1000, 'Client disconnect')
      globalWs = null
    }
  }, [])

  const reconnect = useCallback(() => {
    disconnect()
    isIntentionalDisconnect = false
    setTimeout(() => {
		const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
		const wsHost = API_BASE_URL
			? new URL(API_BASE_URL).host
			: window.location.host
		const wsUrl = `${wsProtocol}//${wsHost}/api/ws`

      globalWs = new WebSocket(wsUrl)
    }, 100)
  }, [disconnect])

  return { disconnect, reconnect }
}
