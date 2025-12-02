"use client"

import { useEffect, useRef, useState, useCallback } from "react"
import { io, type Socket } from "socket.io-client"
import type { Message, KeyExchangeMessage } from "@/lib/types"

const SOCKET_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:5000"

interface UseSocketOptions {
  userId: string | null
  onNewMessage?: (message: Message) => void
  onKeyExchange?: (data: KeyExchangeMessage) => void
  onNewFile?: (data: { senderId: string; fileId: string; filename: string }) => void
  onError?: (error: { type: string; message: string }) => void
}

export function useSocket({ userId, onNewMessage, onKeyExchange, onNewFile, onError }: UseSocketOptions) {
  const socketRef = useRef<Socket | null>(null)
  const [isConnected, setIsConnected] = useState(false)

  useEffect(() => {
    if (!userId) return

    const socket = io(SOCKET_URL, {
      transports: ["websocket", "polling"],
    })

    socketRef.current = socket

    socket.on("connect", () => {
      setIsConnected(true)
      socket.emit("join", userId)
    })

    socket.on("disconnect", () => {
      setIsConnected(false)
    })

    socket.on("new_message", (message: Message) => {
      onNewMessage?.(message)
    })

    socket.on("key_exchange", (data: KeyExchangeMessage) => {
      onKeyExchange?.(data)
    })

    socket.on("new_file", (data: { senderId: string; fileId: string; filename: string }) => {
      onNewFile?.(data)
    })

    socket.on("error", (error: { type: string; message: string }) => {
      onError?.(error)
    })

    return () => {
      socket.disconnect()
    }
  }, [userId, onNewMessage, onKeyExchange, onNewFile, onError])

  const sendEncryptedMessage = useCallback(
    (data: {
      senderId: string
      recipientId: string
      ciphertext: string
      iv: string
      authTag: string
      nonce: string
      sequenceNumber: number
    }) => {
      socketRef.current?.emit("send_message", data)
    },
    [],
  )

  const sendKeyExchange = useCallback((data: KeyExchangeMessage) => {
    socketRef.current?.emit("key_exchange", data)
  }, [])

  const notifyFileShared = useCallback(
    (data: {
      senderId: string
      recipientId: string
      fileId: string
      filename: string
    }) => {
      socketRef.current?.emit("file_shared", data)
    },
    [],
  )

  return {
    isConnected,
    sendEncryptedMessage,
    sendKeyExchange,
    notifyFileShared,
  }
}
