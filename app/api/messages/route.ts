import { type NextRequest, NextResponse } from "next/server"
import { store } from "@/lib/store"
import { v4 as uuidv4 } from "uuid"

// Get messages between two users
export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url)
    const userId = searchParams.get("userId")
    const recipientId = searchParams.get("recipientId")

    if (!userId || !recipientId) {
      return NextResponse.json({ error: "userId and recipientId are required" }, { status: 400 })
    }

    const messages = await store.getMessagesBetweenUsers(userId, recipientId)
    return NextResponse.json(messages)
  } catch (error) {
    console.error("Get messages error:", error)
    return NextResponse.json({ error: "Failed to get messages" }, { status: 500 })
  }
}

// Store encrypted message
export async function POST(request: NextRequest) {
  try {
    const { senderId, recipientId, ciphertext, iv, authTag, nonce, sequenceNumber } = await request.json()

    // Validate required fields
    if (!senderId || !recipientId || !ciphertext || !iv || !authTag || !nonce) {
      return NextResponse.json({ error: "Missing required fields" }, { status: 400 })
    }

    // Replay protection: Check if nonce was already used
    if (await store.isNonceUsed(nonce)) {
      await store.addSecurityLog({
        id: uuidv4(),
        type: "replay_detected",
        userId: senderId,
        details: `Replay attack detected: Nonce ${nonce.substring(0, 8)}... already used`,
        timestamp: Date.now(),
        success: false,
      })
      return NextResponse.json({ error: "Replay attack detected: Nonce already used" }, { status: 400 })
    }

    // Mark nonce as used
    await store.markNonceUsed(nonce)

    const message = await store.addMessage({
      id: uuidv4(),
      senderId,
      recipientId,
      ciphertext,
      iv,
      authTag,
      timestamp: Date.now(),
      nonce,
      sequenceNumber: sequenceNumber || 0,
    })

    await store.addSecurityLog({
      id: uuidv4(),
      type: "message_sent",
      userId: senderId,
      details: `Encrypted message sent from ${senderId.substring(0, 8)}... to ${recipientId.substring(0, 8)}...`,
      timestamp: Date.now(),
      success: true,
    })

    return NextResponse.json(message)
  } catch (error) {
    console.error("Send message error:", error)
    return NextResponse.json({ error: "Failed to send message" }, { status: 500 })
  }
}
