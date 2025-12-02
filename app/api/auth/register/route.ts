import { type NextRequest, NextResponse } from "next/server"
import bcrypt from "bcryptjs"
import { store } from "@/lib/store"
import { v4 as uuidv4 } from "uuid"

export async function POST(request: NextRequest) {
  try {
    const { username, password, publicKey } = await request.json()

    // Validate input
    if (!username || !password || !publicKey) {
      await store.addSecurityLog({
        id: uuidv4(),
        type: "auth_failure",
        details: `Registration failed: Missing fields for username "${username}"`,
        timestamp: Date.now(),
        success: false,
      })
      return NextResponse.json({ error: "Username, password, and public key are required" }, { status: 400 })
    }

    // Check if username exists
    const existingUser = await store.getUserByUsername(username)
    if (existingUser) {
      await store.addSecurityLog({
        id: uuidv4(),
        type: "auth_failure",
        details: `Registration failed: Username "${username}" already exists`,
        timestamp: Date.now(),
        success: false,
      })
      return NextResponse.json({ error: "Username already exists" }, { status: 409 })
    }

    // Hash password with bcrypt (salt rounds = 12)
    const passwordHash = await bcrypt.hash(password, 12)

    // Create user
    const user = await store.createUser({
      id: uuidv4(),
      username,
      passwordHash,
      publicKey,
      createdAt: Date.now(),
    })

    await store.addSecurityLog({
      id: uuidv4(),
      type: "auth_success",
      userId: user.id,
      details: `User "${username}" registered successfully`,
      timestamp: Date.now(),
      success: true,
    })

    return NextResponse.json({
      id: user.id,
      username: user.username,
      publicKey: user.publicKey,
    })
  } catch (error) {
    console.error("Registration error:", error)
    return NextResponse.json({ error: "Registration failed" }, { status: 500 })
  }
}
