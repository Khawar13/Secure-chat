// Express.js Backend Server
// Run with: npx ts-node server/index.ts OR node server/dist/index.js

import "dotenv/config"
import express from "express"
import cors from "cors"
import { createServer } from "http"
import { Server as SocketIOServer } from "socket.io"
import bcrypt from "bcryptjs"
import { v4 as uuidv4 } from "uuid"
import { MongoClient, type Db, type Collection } from "mongodb"
// TOTP functions (using Node.js crypto only)
import * as crypto from "crypto"

function generateTOTPSecret(): string {
  const randomBytes = crypto.randomBytes(16)
  return base32Encode(randomBytes)
}

function generateTOTPURI(secret: string, accountName: string, issuer: string = "CipherChat"): string {
  return `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(accountName)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`
}

function verifyTOTP(secret: string, code: string, timeStep: number = 30, window: number = 1): boolean {
  const currentCounter = Math.floor(Date.now() / 1000 / timeStep)
  for (let i = -window; i <= window; i++) {
    const testCounter = currentCounter + i
    const testCode = generateTOTPAtCounter(secret, testCounter)
    if (testCode === code) return true
  }
  return false
}

function generateTOTPAtCounter(secret: string, counter: number, digits: number = 6): string {
  const key = base32Decode(secret)
  const counterBuffer = Buffer.alloc(8)
  counterBuffer.writeUInt32BE(0, 0)
  counterBuffer.writeUInt32BE(counter, 4)
  const hmac = crypto.createHmac("sha1", key)
  hmac.update(counterBuffer)
  const hmacResult = hmac.digest()
  const offset = hmacResult[19] & 0x0f
  const binary =
    ((hmacResult[offset] & 0x7f) << 24) |
    ((hmacResult[offset + 1] & 0xff) << 16) |
    ((hmacResult[offset + 2] & 0xff) << 8) |
    (hmacResult[offset + 3] & 0xff)
  const otp = binary % Math.pow(10, digits)
  return otp.toString().padStart(digits, "0")
}

function base32Encode(buffer: Buffer): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
  let bits = 0
  let value = 0
  let output = ""
  for (let i = 0; i < buffer.length; i++) {
    value = (value << 8) | buffer[i]
    bits += 8
    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31]
      bits -= 5
    }
  }
  if (bits > 0) {
    output += alphabet[(value << (5 - bits)) & 31]
  }
  return output
}

function base32Decode(encoded: string): Buffer {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
  const lookup: { [key: string]: number } = {}
  for (let i = 0; i < alphabet.length; i++) {
    lookup[alphabet[i]] = i
  }
  encoded = encoded.toUpperCase().replace(/=+$/, "")
  let bits = 0
  let value = 0
  const output: number[] = []
  for (let i = 0; i < encoded.length; i++) {
    const char = encoded[i]
    if (!(char in lookup)) continue
    value = (value << 5) | lookup[char]
    bits += 5
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 255)
      bits -= 8
    }
  }
  return Buffer.from(output)
}

const app = express()
const httpServer = createServer(app)
const io = new SocketIOServer(httpServer, {
  cors: {
    origin: "http://localhost:3000",
    methods: ["GET", "POST"],
  },
})

// Middleware
app.use(cors({ origin: "http://localhost:3000" }))
app.use(express.json({ limit: "50mb" }))

// MongoDB Connection
const MONGODB_URI =
  process.env.MONGODB_URI ||
  "mongodb+srv://i222657:goku1356@a3p2.p7u3y.mongodb.net/?retryWrites=true&w=majority&appName=a3p2"

let db: Db
let usersCollection: Collection
let messagesCollection: Collection
let filesCollection: Collection
let logsCollection: Collection
let sessionsCollection: Collection
let keyExchangesCollection: Collection
let keyConfirmationsCollection: Collection

async function connectToMongoDB() {
  try {
    const client = new MongoClient(MONGODB_URI)
    await client.connect()
    db = client.db("secure_messaging")

    // Initialize collections
    usersCollection = db.collection("users")
    messagesCollection = db.collection("messages")
    filesCollection = db.collection("files")
    logsCollection = db.collection("logs")
    sessionsCollection = db.collection("sessions")
    keyExchangesCollection = db.collection("key_exchanges")
    keyConfirmationsCollection = db.collection("key_confirmations")

    // Create indexes
    await usersCollection.createIndex({ username: 1 }, { unique: true })
    await messagesCollection.createIndex({ senderId: 1, recipientId: 1 })
    await messagesCollection.createIndex({ timestamp: -1 })
    await filesCollection.createIndex({ senderId: 1, recipientId: 1 })
    await logsCollection.createIndex({ timestamp: -1 })
    await sessionsCollection.createIndex({ sessionId: 1 }, { unique: true })
    await keyConfirmationsCollection.createIndex({ senderId: 1, recipientId: 1 })

    console.log("Connected to MongoDB Atlas")
  } catch (error) {
    console.error("MongoDB connection error:", error)
    process.exit(1)
  }
}

// Helper: Add security log
async function addSecurityLog(
  event: string,
  userId: string | null,
  details: string,
  severity: "info" | "warning" | "error",
) {
  await logsCollection.insertOne({
    id: uuidv4(),
    timestamp: Date.now(),
    event,
    userId,
    details,
    severity,
    ipAddress: "127.0.0.1",
  })
}

// ==================== AUTH ROUTES ====================

// Register
app.post("/api/auth/register", async (req, res) => {
  try {
    const { username, password, publicKey } = req.body

    if (!username || !password || !publicKey) {
      return res.status(400).json({ error: "Missing required fields" })
    }

    // Check if user exists
    const existingUser = await usersCollection.findOne({ username })
    if (existingUser) {
      await addSecurityLog("REGISTRATION_FAILED", null, `Username ${username} already exists`, "warning")
      return res.status(400).json({ error: "Username already exists" })
    }

    // Hash password with bcrypt (12 salt rounds)
    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password, salt)

    // Create user
    const user = {
      id: uuidv4(),
      username,
      passwordHash,
      publicKey,
      twoFactorEnabled: false,
      twoFactorSecret: null, // Will be set when user enables 2FA
      createdAt: Date.now(),
    }

    await usersCollection.insertOne(user)
    await addSecurityLog("USER_REGISTERED", user.id, `User ${username} registered successfully`, "info")

    res.json({
      id: user.id,
      username: user.username,
      publicKey: user.publicKey,
      twoFactorEnabled: false,
    })
  } catch (error) {
    console.error("Registration error:", error)
    res.status(500).json({ error: "Registration failed" })
  }
})

// Login
app.post("/api/auth/login", async (req, res) => {
  try {
    const { username, password, totpCode } = req.body

    if (!username || !password) {
      return res.status(400).json({ error: "Missing credentials" })
    }

    const user = await usersCollection.findOne({ username })
    if (!user) {
      await addSecurityLog("LOGIN_FAILED", null, `Invalid username: ${username}`, "warning")
      return res.status(401).json({ error: "Invalid credentials" })
    }

    // Verify password
    const isValid = await bcrypt.compare(password, user.passwordHash)
    if (!isValid) {
      await addSecurityLog("LOGIN_FAILED", user.id, `Invalid password for user ${username}`, "warning")
      return res.status(401).json({ error: "Invalid credentials" })
    }

    // Check if 2FA is enabled
    if (user.twoFactorEnabled && user.twoFactorSecret) {
      if (!totpCode) {
        await addSecurityLog("LOGIN_2FA_REQUIRED", user.id, `2FA code required for user ${username}`, "info")
        return res.status(200).json({
          requires2FA: true,
          message: "2FA code required",
        })
      }

      // Verify TOTP code
      const isValidTOTP = verifyTOTP(user.twoFactorSecret, totpCode)
      if (!isValidTOTP) {
        await addSecurityLog("LOGIN_2FA_FAILED", user.id, `Invalid 2FA code for user ${username}`, "warning")
        return res.status(401).json({ error: "Invalid 2FA code" })
      }

      await addSecurityLog("LOGIN_2FA_SUCCESS", user.id, `2FA verified for user ${username}`, "info")
    }

    await addSecurityLog("LOGIN_SUCCESS", user.id, `User ${username} logged in`, "info")

    res.json({
      id: user.id,
      username: user.username,
      publicKey: user.publicKey,
      twoFactorEnabled: user.twoFactorEnabled || false,
    })
  } catch (error) {
    console.error("Login error:", error)
    res.status(500).json({ error: "Login failed" })
  }
})

// Setup 2FA - Generate secret and QR code
app.post("/api/auth/2fa/setup", async (req, res) => {
  try {
    const { userId, password } = req.body

    if (!userId || !password) {
      return res.status(400).json({ error: "Missing required fields" })
    }

    const user = await usersCollection.findOne({ id: userId })
    if (!user) {
      return res.status(404).json({ error: "User not found" })
    }

    // Verify password before allowing 2FA setup
    const isValid = await bcrypt.compare(password, user.passwordHash)
    if (!isValid) {
      await addSecurityLog("2FA_SETUP_FAILED", userId, `Invalid password for 2FA setup`, "warning")
      return res.status(401).json({ error: "Invalid password" })
    }

    // Generate new TOTP secret
    const secret = generateTOTPSecret()
    const totpURI = generateTOTPURI(secret, user.username, "CipherChat")

    // Store secret temporarily (not enabled yet - user needs to verify first)
    await usersCollection.updateOne(
      { id: userId },
      { $set: { twoFactorSecret: secret, twoFactorEnabled: false } },
    )

    await addSecurityLog("2FA_SETUP_INITIATED", userId, `2FA setup initiated for user ${user.username}`, "info")

    res.json({
      secret,
      totpURI,
      qrCodeData: totpURI, // Can be used to generate QR code on client
    })
  } catch (error) {
    console.error("2FA setup error:", error)
    res.status(500).json({ error: "2FA setup failed" })
  }
})

// Verify and enable 2FA
app.post("/api/auth/2fa/verify", async (req, res) => {
  try {
    const { userId, totpCode } = req.body

    if (!userId || !totpCode) {
      return res.status(400).json({ error: "Missing required fields" })
    }

    const user = await usersCollection.findOne({ id: userId })
    if (!user || !user.twoFactorSecret) {
      return res.status(400).json({ error: "2FA not set up. Please set up 2FA first." })
    }

    // Verify TOTP code
    const isValid = verifyTOTP(user.twoFactorSecret, totpCode)
    if (!isValid) {
      await addSecurityLog("2FA_VERIFY_FAILED", userId, `Invalid 2FA code during setup`, "warning")
      return res.status(401).json({ error: "Invalid 2FA code" })
    }

    // Enable 2FA
    await usersCollection.updateOne({ id: userId }, { $set: { twoFactorEnabled: true } })

    await addSecurityLog("2FA_ENABLED", userId, `2FA enabled for user ${user.username}`, "info")

    res.json({
      success: true,
      message: "2FA enabled successfully",
    })
  } catch (error) {
    console.error("2FA verify error:", error)
    res.status(500).json({ error: "2FA verification failed" })
  }
})

// Disable 2FA
app.post("/api/auth/2fa/disable", async (req, res) => {
  try {
    const { userId, password, totpCode } = req.body

    if (!userId || !password) {
      return res.status(400).json({ error: "Missing required fields" })
    }

    const user = await usersCollection.findOne({ id: userId })
    if (!user) {
      return res.status(404).json({ error: "User not found" })
    }

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.passwordHash)
    if (!isValidPassword) {
      await addSecurityLog("2FA_DISABLE_FAILED", userId, `Invalid password for 2FA disable`, "warning")
      return res.status(401).json({ error: "Invalid password" })
    }

    // If 2FA is enabled, require TOTP code
    if (user.twoFactorEnabled && user.twoFactorSecret) {
      if (!totpCode) {
        return res.status(400).json({ error: "2FA code required to disable 2FA" })
      }

      const isValidTOTP = verifyTOTP(user.twoFactorSecret, totpCode)
      if (!isValidTOTP) {
        await addSecurityLog("2FA_DISABLE_FAILED", userId, `Invalid 2FA code for disable`, "warning")
        return res.status(401).json({ error: "Invalid 2FA code" })
      }
    }

    // Disable 2FA
    await usersCollection.updateOne(
      { id: userId },
      { $set: { twoFactorEnabled: false, twoFactorSecret: null } },
    )

    await addSecurityLog("2FA_DISABLED", userId, `2FA disabled for user ${user.username}`, "info")

    res.json({
      success: true,
      message: "2FA disabled successfully",
    })
  } catch (error) {
    console.error("2FA disable error:", error)
    res.status(500).json({ error: "2FA disable failed" })
  }
})

// ==================== USER ROUTES ====================

// Get all users
app.get("/api/users", async (req, res) => {
  try {
    const users = await usersCollection.find({}).toArray()
    res.json(
      users.map((u) => ({
        id: u.id,
        username: u.username,
        publicKey: u.publicKey,
      })),
    )
  } catch (error) {
    console.error("Get users error:", error)
    res.status(500).json({ error: "Failed to fetch users" })
  }
})

// ==================== MESSAGE ROUTES ====================

// Send encrypted message
app.post("/api/messages", async (req, res) => {
  try {
    const { senderId, recipientId, ciphertext, iv, authTag, nonce, sequenceNumber, timestamp } = req.body

    // Basic validation
    if (!senderId || !recipientId || !ciphertext || !iv || !authTag || !nonce || timestamp == null) {
      return res.status(400).json({ error: "Missing required fields" })
    }

    if (typeof sequenceNumber !== "number") {
      return res.status(400).json({ error: "Invalid sequence number" })
    }

    const now = Date.now()

    // Timestamp window check (5 minutes)
    if (Math.abs(now - timestamp) > 5 * 60 * 1000) {
      await addSecurityLog(
        "MESSAGE_TIMESTAMP_INVALID",
        senderId,
        `Message timestamp outside allowed window from ${senderId} to ${recipientId}`,
        "warning",
      )
      return res.status(400).json({ error: "Message timestamp outside allowed window" })
    }

    // Replay attack protection: duplicate nonce
    const existingWithSameNonce = await messagesCollection.findOne({
      nonce,
      senderId,
      recipientId,
    })

    if (existingWithSameNonce) {
      await addSecurityLog(
        "REPLAY_ATTACK_DETECTED_NONCE",
        senderId,
        `Duplicate nonce detected from ${senderId} to ${recipientId}`,
        "error",
      )
      return res.status(400).json({ error: "Replay attack detected: duplicate nonce" })
    }

    // Replay protection: enforce monotonically increasing sequence numbers per sender/recipient
    const [lastMessage] = await messagesCollection
      .find({ senderId, recipientId })
      .sort({ sequenceNumber: -1 })
      .limit(1)
      .toArray()

    if (lastMessage && typeof lastMessage.sequenceNumber === "number") {
      if (sequenceNumber <= lastMessage.sequenceNumber) {
        await addSecurityLog(
          "REPLAY_ATTACK_DETECTED_SEQUENCE",
          senderId,
          `Non-increasing sequence number from ${senderId} to ${recipientId}. Received=${sequenceNumber}, Last=${lastMessage.sequenceNumber}`,
          "error",
        )
        return res.status(400).json({ error: "Replay attack detected: invalid sequence number" })
      }

      // Optional: also enforce strictly increasing timestamps
      if (timestamp <= lastMessage.timestamp) {
        await addSecurityLog(
          "REPLAY_ATTACK_DETECTED_TIMESTAMP_ORDER",
          senderId,
          `Non-increasing timestamp from ${senderId} to ${recipientId}. Received=${timestamp}, Last=${lastMessage.timestamp}`,
          "error",
        )
        return res.status(400).json({ error: "Replay attack detected: invalid timestamp ordering" })
      }
    }

    const message = {
      id: uuidv4(),
      senderId,
      recipientId,
      ciphertext,
      iv,
      authTag,
      nonce,
      sequenceNumber,
      timestamp,
    }

    await messagesCollection.insertOne(message)
    await addSecurityLog("MESSAGE_SENT", senderId, `Encrypted message sent to ${recipientId}`, "info")

    // Emit via Socket.io for real-time
    io.to(recipientId).emit("new_message", message)

    res.json(message)
  } catch (error) {
    console.error("Send message error:", error)
    res.status(500).json({ error: "Failed to send message" })
  }
})

// Get messages between two users
app.get("/api/messages", async (req, res) => {
  try {
    const { userId, recipientId } = req.query

    if (!userId || !recipientId) {
      return res.status(400).json({ error: "Missing user IDs" })
    }

    const messages = await messagesCollection
      .find({
        $or: [
          { senderId: userId, recipientId: recipientId },
          { senderId: recipientId, recipientId: userId },
        ],
      })
      .sort({ timestamp: 1 })
      .toArray()

    res.json(messages)
  } catch (error) {
    console.error("Get messages error:", error)
    res.status(500).json({ error: "Failed to fetch messages" })
  }
})

// ==================== FILE ROUTES ====================

// Upload encrypted file
app.post("/api/files", async (req, res) => {
  try {
    const { senderId, recipientId, filename, encryptedData, iv, authTag, size } = req.body

    if (!senderId || !recipientId || !filename || !encryptedData || !iv || !authTag) {
      return res.status(400).json({ error: "Missing required fields" })
    }

    const file = {
      id: uuidv4(),
      senderId,
      recipientId,
      filename,
      encryptedData,
      iv,
      authTag,
      size,
      timestamp: Date.now(),
    }

    await filesCollection.insertOne(file)
    await addSecurityLog("FILE_SHARED", senderId, `Encrypted file "${filename}" shared with ${recipientId}`, "info")

    // Notify recipient via Socket.io
    io.to(recipientId).emit("new_file", {
      senderId,
      fileId: file.id,
      filename,
    })

    res.json({
      id: file.id,
      filename: file.filename,
      senderId: file.senderId,
      timestamp: file.timestamp,
    })
  } catch (error) {
    console.error("Upload file error:", error)
    res.status(500).json({ error: "Failed to upload file" })
  }
})

// Get files for user
app.get("/api/files", async (req, res) => {
  try {
    const { userId } = req.query

    if (!userId) {
      return res.status(400).json({ error: "Missing user ID" })
    }

    const files = await filesCollection
      .find({
        $or: [{ senderId: userId }, { recipientId: userId }],
      })
      .sort({ timestamp: -1 })
      .toArray()

    res.json(
      files.map((f) => ({
        id: f.id,
        filename: f.filename,
        senderId: f.senderId,
        recipientId: f.recipientId,
        timestamp: f.timestamp,
        size: f.size,
      })),
    )
  } catch (error) {
    console.error("Get files error:", error)
    res.status(500).json({ error: "Failed to fetch files" })
  }
})

// Download encrypted file
app.get("/api/files/:id", async (req, res) => {
  try {
    const { id } = req.params
    const { userId } = req.query

    const file = await filesCollection.findOne({ id })

    if (!file) {
      return res.status(404).json({ error: "File not found" })
    }

    // Check if user has access
    if (file.senderId !== userId && file.recipientId !== userId) {
      await addSecurityLog("UNAUTHORIZED_FILE_ACCESS", userId as string, `Unauthorized access to file ${id}`, "error")
      return res.status(403).json({ error: "Access denied" })
    }

    res.json({
      id: file.id,
      filename: file.filename,
      encryptedData: file.encryptedData,
      iv: file.iv,
      authTag: file.authTag,
    })
  } catch (error) {
    console.error("Download file error:", error)
    res.status(500).json({ error: "Failed to download file" })
  }
})

// ==================== KEY EXCHANGE ROUTES ====================

// Store/retrieve session key
app.post("/api/session-key", async (req, res) => {
  try {
    const { userId1, userId2, exportedKey } = req.body

    if (!userId1 || !userId2 || !exportedKey) {
      return res.status(400).json({ error: "Missing required fields" })
    }

    const sessionId = [userId1, userId2].sort().join(":")

    await sessionsCollection.updateOne(
      { sessionId },
      {
        $set: {
          sessionId,
          exportedKey,
          createdAt: Date.now(),
        },
      },
      { upsert: true },
    )

    await addSecurityLog("SESSION_KEY_STORED", userId1, `Session key stored for ${userId1} <-> ${userId2}`, "info")

    res.json({ success: true })
  } catch (error) {
    console.error("Store session key error:", error)
    res.status(500).json({ error: "Failed to store session key" })
  }
})

app.get("/api/session-key", async (req, res) => {
  try {
    const { userId1, userId2 } = req.query

    if (!userId1 || !userId2) {
      return res.status(400).json({ error: "Missing user IDs" })
    }

    const sessionId = [userId1, userId2].sort().join(":")
    const session = await sessionsCollection.findOne({ sessionId })

    if (session) {
      res.json({ exists: true, exportedKey: session.exportedKey })
    } else {
      res.json({ exists: false })
    }
  } catch (error) {
    console.error("Get session key error:", error)
    res.status(500).json({ error: "Failed to get session key" })
  }
})

// Key exchange
app.post("/api/key-exchange", async (req, res) => {
  try {
    const { type, senderId, recipientId, senderPublicKey, ephemeralPublicKey, signature, timestamp, nonce } = req.body

    if (
      !type ||
      !senderId ||
      !recipientId ||
      !senderPublicKey ||
      !ephemeralPublicKey ||
      !signature ||
      !timestamp ||
      !nonce
    ) {
      return res.status(400).json({ error: "Missing required fields" })
    }

    const exchange = {
      id: uuidv4(),
      type,
      senderId,
      recipientId,
      senderPublicKey,
      ephemeralPublicKey,
      signature,
      timestamp,
      nonce,
      createdAt: Date.now(),
    }

    await keyExchangesCollection.insertOne(exchange)
    await addSecurityLog("KEY_EXCHANGE", senderId, `Key exchange ${type} from ${senderId} to ${recipientId}`, "info")

    // Notify recipient via Socket.io
    io.to(recipientId).emit("key_exchange", exchange)

    res.json(exchange)
  } catch (error) {
    console.error("Key exchange error:", error)
    res.status(500).json({ error: "Key exchange failed" })
  }
})

app.post("/api/key-confirmation", async (req, res) => {
  try {
    const { senderId, recipientId, confirmationHash, confirmationNonce, originalNonce, timestamp } = req.body

    if (!senderId || !recipientId || !confirmationHash || !confirmationNonce || !originalNonce) {
      return res.status(400).json({ error: "Missing required fields" })
    }

    // Verify timestamp (within 5 minutes)
    if (Math.abs(Date.now() - timestamp) > 5 * 60 * 1000) {
      await addSecurityLog(
        "KEY_CONFIRMATION_EXPIRED",
        senderId,
        `Key confirmation timestamp expired from ${senderId} to ${recipientId}`,
        "warning",
      )
      return res.status(400).json({ error: "Key confirmation timestamp expired" })
    }

    const confirmation = {
      id: uuidv4(),
      type: "confirm",
      senderId,
      recipientId,
      confirmationHash,
      confirmationNonce,
      originalNonce,
      timestamp,
      createdAt: Date.now(),
    }

    await keyConfirmationsCollection.insertOne(confirmation)
    await addSecurityLog(
      "KEY_CONFIRMATION",
      senderId,
      `Key confirmation sent from ${senderId} to ${recipientId}`,
      "info",
    )

    // Notify recipient via Socket.io
    io.to(recipientId).emit("key_confirmation", confirmation)

    res.json(confirmation)
  } catch (error) {
    console.error("Key confirmation error:", error)
    res.status(500).json({ error: "Key confirmation failed" })
  }
})

// ==================== LOGS ROUTES ====================

app.get("/api/logs", async (req, res) => {
  try {
    const { limit = 100 } = req.query

    const logs = await logsCollection.find({}).sort({ timestamp: -1 }).limit(Number(limit)).toArray()

    res.json(logs)
  } catch (error) {
    console.error("Get logs error:", error)
    res.status(500).json({ error: "Failed to fetch logs" })
  }
})

app.post("/api/logs", async (req, res) => {
  try {
    const { event, userId, details, severity } = req.body

    await addSecurityLog(event, userId, details, severity)

    res.json({ success: true })
  } catch (error) {
    console.error("Add log error:", error)
    res.status(500).json({ error: "Failed to add log" })
  }
})

// ==================== SOCKET.IO ====================

io.on("connection", (socket) => {
  console.log("Client connected:", socket.id)

  // Join user's room for targeted messages
  socket.on("join", (userId: string) => {
    socket.join(userId)
    console.log(`User ${userId} joined their room`)
  })

  // Leave room
  socket.on("leave", (userId: string) => {
    socket.leave(userId)
  })

  // Relay encrypted message
  socket.on("send_message", (data) => {
    io.to(data.recipientId).emit("new_message", data)
  })

  // Relay key exchange
  socket.on("key_exchange", (data) => {
    io.to(data.recipientId).emit("key_exchange", data)
  })

  socket.on("key_confirmation", (data) => {
    io.to(data.recipientId).emit("key_confirmation", data)
  })

  // Relay file notification
  socket.on("file_shared", (data) => {
    io.to(data.recipientId).emit("new_file", data)
  })

  socket.on("disconnect", () => {
    console.log("Client disconnected:", socket.id)
  })
})

// ==================== START SERVER ====================

const PORT = process.env.PORT || 5000

connectToMongoDB().then(() => {
  httpServer.listen(PORT, () => {
    console.log(`
====================================
  Secure Messaging Express Server
====================================
  Server running on port ${PORT}
  MongoDB: Connected
  Socket.io: Enabled
====================================
    `)
  })
})
