import { type NextRequest, NextResponse } from "next/server"
import bcrypt from "bcryptjs"
import { store } from "@/lib/store"
import { v4 as uuidv4 } from "uuid"

export async function POST(request: NextRequest) {
  try {
    const { username, password } = await request.json()

    await store.addSecurityLog({
      id: uuidv4(),
      type: "auth_attempt",
      details: `Login attempt for username "${username}"`,
      timestamp: Date.now(),
      success: false,
    })

    // Validate input
    if (!username || !password) {
      return NextResponse.json({ error: "Username and password are required" }, { status: 400 })
    }

    // Find user
    const user = await store.getUserByUsername(username)
    if (!user) {
      await store.addSecurityLog({
        id: uuidv4(),
        type: "auth_failure",
        details: `Login failed: User "${username}" not found`,
        timestamp: Date.now(),
        success: false,
      })
      return NextResponse.json({ error: "Invalid credentials" }, { status: 401 })
    }

    // Verify password
    const isValid = await bcrypt.compare(password, user.passwordHash)
    if (!isValid) {
      await store.addSecurityLog({
        id: uuidv4(),
        type: "auth_failure",
        userId: user.id,
        details: `Login failed: Invalid password for user "${username}"`,
        timestamp: Date.now(),
        success: false,
      })
      return NextResponse.json({ error: "Invalid credentials" }, { status: 401 })
    }

    await store.addSecurityLog({
      id: uuidv4(),
      type: "auth_success",
      userId: user.id,
      details: `User "${username}" logged in successfully`,
      timestamp: Date.now(),
      success: true,
    })

    return NextResponse.json({
      id: user.id,
      username: user.username,
      publicKey: user.publicKey,
    })
  } catch (error) {
    console.error("Login error:", error)
    return NextResponse.json({ error: "Login failed" }, { status: 500 })
  }
}
