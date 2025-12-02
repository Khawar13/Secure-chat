import { type NextRequest, NextResponse } from "next/server"
import { store } from "@/lib/store"

export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url)
    const limit = Number.parseInt(searchParams.get("limit") || "100")

    const logs = await store.getSecurityLogs(limit)
    return NextResponse.json(logs)
  } catch (error) {
    console.error("Get logs error:", error)
    return NextResponse.json({ error: "Failed to get security logs" }, { status: 500 })
  }
}
