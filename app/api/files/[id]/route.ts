import { type NextRequest, NextResponse } from "next/server"
import { store } from "@/lib/store"
import { v4 as uuidv4 } from "uuid"

export async function GET(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params
    const { searchParams } = new URL(request.url)
    const userId = searchParams.get("userId")

    const file = await store.getFile(id)

    if (!file) {
      return NextResponse.json({ error: "File not found" }, { status: 404 })
    }

    // Log file download
    if (userId) {
      await store.addSecurityLog({
        id: uuidv4(),
        type: "file_download",
        userId,
        details: `File "${file.filename}" downloaded by ${userId.substring(0, 8)}...`,
        timestamp: Date.now(),
        success: true,
      })
    }

    return NextResponse.json(file)
  } catch (error) {
    console.error("Get file error:", error)
    return NextResponse.json({ error: "Failed to get file" }, { status: 500 })
  }
}
