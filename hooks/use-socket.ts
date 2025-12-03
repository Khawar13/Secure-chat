"use client"

import { useEffect, useRef, useState, useCallback } from "react"
import { io, type Socket } from "socket.io-client"
import type { Message, KeyExchangeMessage, KeyConfirmationMessage } from "@/lib/types"

const SOCKET_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:5000"

interface UseSocketOptions {
  userId: string | null
  onNewMessage?: (message: Message) => void
  onKeyExchange?: (data: KeyExchangeMessage) => void
  onKeyConfirmation?: (data: KeyConfirmationMessage) => void
  onNewFile?: (data: { senderId: string; fileId: string; filename: string }) => void
  onError?: (error: { type: string; message: string }) => void
}

export function useSocket({
  userId,
  onNewMessage,
  onKeyExchange,
  onKeyConfirmation,
  onNewFile,
  onError,
}: UseSocketOptions) {
  const socketRef = useRef<Socket | null>(null)
  const [isConnected, setIsConnected] = useState(false)

  const onNewMessageRef = useRef(onNewMessage)
  const onKeyExchangeRef = useRef(onKeyExchange)
  const onKeyConfirmationRef = useRef(onKeyConfirmation)
  const onNewFileRef = useRef(onNewFile)
  const onErrorRef = useRef(onError)

  useEffect(() => {
    onNewMessageRef.current = onNewMessage
  }, [onNewMessage])

  useEffect(() => {
    onKeyExchangeRef.current = onKeyExchange
  }, [onKeyExchange])

  useEffect(() => {
    onKeyConfirmationRef.current = onKeyConfirmation
  }, [onKeyConfirmation])

  useEffect(() => {
    onNewFileRef.current = onNewFile
  }, [onNewFile])

  useEffect(() => {
    onErrorRef.current = onError
  }, [onError])

  useEffect(() => {
    if (!userId) return

    if (socketRef.current?.connected) {
      return
    }

    const socket = io(SOCKET_URL, {
      transports: ["websocket", "polling"],
      reconnectionAttempts: 5,
      reconnectionDelay: 1000,
    })

    socketRef.current = socket

    socket.on("connect", () => {
      console.log("[v0] Socket connected, joining room:", userId)
      setIsConnected(true)
      socket.emit("join", userId)
    })

    socket.on("disconnect", () => {
      console.log("[v0] Socket disconnected")
      setIsConnected(false)
    })

    socket.on("new_message", (message: Message) => {
      console.log("[v0] Received new_message:", message)
      onNewMessageRef.current?.(message)
    })

    socket.on("key_exchange", (data: KeyExchangeMessage) => {
      console.log("[v0] Received key_exchange event:", data.type, "from:", data.senderId)
      onKeyExchangeRef.current?.(data)
    })

    socket.on("key_confirmation", (data: KeyConfirmationMessage) => {
      console.log("[v0] Received key_confirmation from:", data.senderId)
      onKeyConfirmationRef.current?.(data)
    })

    socket.on("new_file", (data: { senderId: string; fileId: string; filename: string }) => {
      console.log("[v0] Received new_file:", data)
      onNewFileRef.current?.(data)
    })

    socket.on("error", (error: { type: string; message: string }) => {
      console.error("[v0] Socket error:", error)
      onErrorRef.current?.(error)
    })

    return () => {
      console.log("[v0] Cleaning up socket connection")
      socket.disconnect()
      socketRef.current = null
    }
  }, [userId]) // Only userId in dependency array

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
      console.log("[v0] Sending encrypted message")
      socketRef.current?.emit("send_message", data)
    },
    [],
  )

  const sendKeyExchange = useCallback((data: KeyExchangeMessage) => {
    console.log("[v0] Sending key_exchange:", data.type, "to:", data.recipientId)
    socketRef.current?.emit("key_exchange", data)
  }, [])

  const sendKeyConfirmation = useCallback((data: KeyConfirmationMessage) => {
    console.log("[v0] Sending key_confirmation to:", data.recipientId)
    socketRef.current?.emit("key_confirmation", data)
  }, [])

  const notifyFileShared = useCallback(
    (data: {
      senderId: string
      recipientId: string
      fileId: string
      filename: string
    }) => {
      console.log("[v0] Notifying file shared:", data.filename)
      socketRef.current?.emit("file_shared", data)
    },
    [],
  )

  return {
    isConnected,
    sendEncryptedMessage,
    sendKeyExchange,
    sendKeyConfirmation,
    notifyFileShared,
  }
}
