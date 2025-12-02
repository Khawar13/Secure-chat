import { type NextRequest, NextResponse } from "next/server"
import { store } from "@/lib/store"
import { v4 as uuidv4 } from "uuid"

// Store or retrieve shared session key
export async function POST(request: NextRequest) {
  try {
    const { userId1, userId2, exportedKey } = await request.json()

    if (!userId1 || !userId2 || !exportedKey) {
      return NextResponse.json({ error: "Missing required fields" }, { status: 400 })
    }

    await store.storeSharedSessionKey(userId1, userId2, exportedKey)

    await store.addSecurityLog({
      id: uuidv4(),
      type: "key_exchange",
      userId: userId1,
      details: `Session key established between ${userId1.substring(0, 8)}... and ${userId2.substring(0, 8)}...`,
      timestamp: Date.now(),
      success: true,
    })

    return NextResponse.json({ success: true })
  } catch (error) {
    console.error("Session key storage error:", error)
    return NextResponse.json({ error: "Failed to store session key" }, { status: 500 })
  }
}

export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url)
    const userId1 = searchParams.get("userId1")
    const userId2 = searchParams.get("userId2")

    if (!userId1 || !userId2) {
      return NextResponse.json({ error: "Missing user IDs" }, { status: 400 })
    }

    const exportedKey = await store.getSharedSessionKey(userId1, userId2)

    if (!exportedKey) {
      return NextResponse.json({ exists: false })
    }

    return NextResponse.json({ exists: true, exportedKey })
  } catch (error) {
    console.error("Session key retrieval error:", error)
    return NextResponse.json({ error: "Failed to retrieve session key" }, { status: 500 })
  }
}
