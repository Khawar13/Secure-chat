import { NextResponse } from "next/server"
import { store } from "@/lib/store"

export async function GET() {
  try {
    const users = await store.getAllUsers()
    const sanitizedUsers = users.map((u) => ({
      id: u.id,
      username: u.username,
      publicKey: u.publicKey,
    }))
    return NextResponse.json(sanitizedUsers)
  } catch (error) {
    console.error("Get users error:", error)
    return NextResponse.json({ error: "Failed to get users" }, { status: 500 })
  }
}
