// Socket.io server setup for real-time messaging
import { Server as SocketIOServer } from "socket.io"
import type { Server as HTTPServer } from "http"
import { store } from "./store"
import { v4 as uuidv4 } from "uuid"

let io: SocketIOServer | null = null

export function initializeSocketServer(httpServer: HTTPServer): SocketIOServer {
  if (io) return io

  io = new SocketIOServer(httpServer, {
    cors: {
      origin: "*",
      methods: ["GET", "POST"],
    },
    path: "/api/socketio",
  })

  io.on("connection", (socket) => {
    console.log("Client connected:", socket.id)

    // User joins their room
    socket.on("join", (userId: string) => {
      socket.join(userId)
      console.log(`User ${userId} joined their room`)

      store.addSecurityLog({
        id: uuidv4(),
        type: "auth_success",
        userId,
        details: `User ${userId.substring(0, 8)}... connected to real-time channel`,
        timestamp: Date.now(),
        success: true,
      })
    })

    // Handle encrypted messages
    socket.on("encrypted_message", async (data) => {
      const { senderId, recipientId, ciphertext, iv, authTag, nonce, sequenceNumber } = data

      // Replay protection
      if (await store.isNonceUsed(nonce)) {
        socket.emit("error", { type: "replay_detected", message: "Replay attack detected" })
        store.addSecurityLog({
          id: uuidv4(),
          type: "replay_detected",
          userId: senderId,
          details: `Replay attack detected via WebSocket`,
          timestamp: Date.now(),
          success: false,
        })
        return
      }

      store.markNonceUsed(nonce)

      // Store message
      const message = store.addMessage({
        id: uuidv4(),
        senderId,
        recipientId,
        ciphertext,
        iv,
        authTag,
        timestamp: Date.now(),
        nonce,
        sequenceNumber,
      })

      // Send to recipient
      io?.to(recipientId).emit("new_message", message)
      // Send confirmation to sender
      socket.emit("message_sent", message)

      store.addSecurityLog({
        id: uuidv4(),
        type: "message_sent",
        userId: senderId,
        details: `Real-time encrypted message sent`,
        timestamp: Date.now(),
        success: true,
      })
    })

    // Handle key exchange messages
    socket.on("key_exchange", (data) => {
      const { type, senderId, recipientId, ephemeralPublicKey, signature, timestamp, nonce, confirmationHash } = data

      // Validate timestamp
      if (Math.abs(Date.now() - timestamp) > 5 * 60 * 1000) {
        socket.emit("error", { type: "key_exchange_failed", message: "Timestamp too old" })
        return
      }

      // Relay to recipient
      io?.to(recipientId).emit("key_exchange_message", {
        type,
        senderId,
        recipientId,
        ephemeralPublicKey,
        signature,
        timestamp,
        nonce,
        confirmationHash,
      })

      store.addSecurityLog({
        id: uuidv4(),
        type: "key_exchange",
        userId: senderId,
        details: `Key exchange ${type} relayed to ${recipientId.substring(0, 8)}...`,
        timestamp: Date.now(),
        success: true,
      })
    })

    // Handle file sharing notification
    socket.on("file_shared", (data) => {
      const { senderId, recipientId, fileId, filename } = data

      io?.to(recipientId).emit("new_file", {
        senderId,
        fileId,
        filename,
        timestamp: Date.now(),
      })
    })

    socket.on("disconnect", () => {
      console.log("Client disconnected:", socket.id)
    })
  })

  return io
}

export function getIO(): SocketIOServer | null {
  return io
}
