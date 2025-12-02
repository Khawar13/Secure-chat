import { type NextRequest, NextResponse } from "next/server"
import { store } from "@/lib/store"
import { v4 as uuidv4 } from "uuid"

// Get files for a user or between two users
export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url)
    const userId = searchParams.get("userId")
    const recipientId = searchParams.get("recipientId")

    if (!userId) {
      return NextResponse.json({ error: "userId is required" }, { status: 400 })
    }

    let files
    if (recipientId) {
      files = await store.getFilesBetweenUsers(userId, recipientId)
    } else {
      files = await store.getFilesByUser(userId)
    }
    return NextResponse.json(files)
  } catch (error) {
    console.error("Get files error:", error)
    return NextResponse.json({ error: "Failed to get files" }, { status: 500 })
  }
}

// Upload encrypted file
export async function POST(request: NextRequest) {
  try {
    const { senderId, recipientId, filename, encryptedData, iv, authTag, size } = await request.json()

    if (!senderId || !recipientId || !filename || !encryptedData || !iv || !authTag) {
      return NextResponse.json({ error: "Missing required fields" }, { status: 400 })
    }

    const file = await store.addFile({
      id: uuidv4(),
      senderId,
      recipientId,
      filename,
      encryptedData,
      iv,
      authTag,
      size: size || 0,
      timestamp: Date.now(),
    })

    await store.addSecurityLog({
      id: uuidv4(),
      type: "file_upload",
      userId: senderId,
      details: `Encrypted file "${filename}" uploaded from ${senderId.substring(0, 8)}... to ${recipientId.substring(0, 8)}...`,
      timestamp: Date.now(),
      success: true,
    })

    return NextResponse.json(file)
  } catch (error) {
    console.error("Upload file error:", error)
    return NextResponse.json({ error: "Failed to upload file" }, { status: 500 })
  }
}
