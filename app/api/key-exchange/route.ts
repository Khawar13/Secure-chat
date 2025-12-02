import { type NextRequest, NextResponse } from "next/server"
import { store } from "@/lib/store"
import { v4 as uuidv4 } from "uuid"

// Handle key exchange messages
export async function POST(request: NextRequest) {
  try {
    const keyExchangeMessage = await request.json()
    const { type, senderId, recipientId, timestamp, nonce } = keyExchangeMessage

    // Validate timestamp (reject if older than 5 minutes)
    const now = Date.now()
    if (Math.abs(now - timestamp) > 5 * 60 * 1000) {
      await store.addSecurityLog({
        id: uuidv4(),
        type: "key_exchange_failure",
        userId: senderId,
        details: `Key exchange failed: Timestamp too old (${type})`,
        timestamp: now,
        success: false,
      })
      return NextResponse.json({ error: "Key exchange failed: Timestamp too old" }, { status: 400 })
    }

    // Check for replay
    if (await store.isNonceUsed(nonce)) {
      await store.addSecurityLog({
        id: uuidv4(),
        type: "replay_detected",
        userId: senderId,
        details: `Replay attack detected in key exchange: Nonce ${nonce.substring(0, 8)}...`,
        timestamp: now,
        success: false,
      })
      return NextResponse.json({ error: "Replay attack detected" }, { status: 400 })
    }

    await store.markNonceUsed(nonce)

    await store.addSecurityLog({
      id: uuidv4(),
      type: "key_exchange",
      userId: senderId,
      details: `Key exchange ${type} from ${senderId.substring(0, 8)}... to ${recipientId.substring(0, 8)}...`,
      timestamp: now,
      success: true,
    })

    return NextResponse.json({ success: true, message: keyExchangeMessage })
  } catch (error) {
    console.error("Key exchange error:", error)
    return NextResponse.json({ error: "Key exchange failed" }, { status: 500 })
  }
}
