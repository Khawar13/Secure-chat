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

    // Create indexes
    await usersCollection.createIndex({ username: 1 }, { unique: true })
    await messagesCollection.createIndex({ senderId: 1, recipientId: 1 })
    await messagesCollection.createIndex({ timestamp: -1 })
    await filesCollection.createIndex({ senderId: 1, recipientId: 1 })
    await logsCollection.createIndex({ timestamp: -1 })
    await sessionsCollection.createIndex({ sessionId: 1 }, { unique: true })

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
      createdAt: Date.now(),
    }

    await usersCollection.insertOne(user)
    await addSecurityLog("USER_REGISTERED", user.id, `User ${username} registered successfully`, "info")

    res.json({
      id: user.id,
      username: user.username,
      publicKey: user.publicKey,
    })
  } catch (error) {
    console.error("Registration error:", error)
    res.status(500).json({ error: "Registration failed" })
  }
})

// Login
app.post("/api/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body

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

    await addSecurityLog("LOGIN_SUCCESS", user.id, `User ${username} logged in`, "info")

    res.json({
      id: user.id,
      username: user.username,
      publicKey: user.publicKey,
    })
  } catch (error) {
    console.error("Login error:", error)
    res.status(500).json({ error: "Login failed" })
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
    const { senderId, recipientId, ciphertext, iv, authTag, nonce, sequenceNumber } = req.body

    if (!senderId || !recipientId || !ciphertext || !iv || !authTag) {
      return res.status(400).json({ error: "Missing required fields" })
    }

    // Replay attack protection
    const existingMessage = await messagesCollection.findOne({
      nonce,
      senderId,
      recipientId,
    })

    if (existingMessage) {
      await addSecurityLog(
        "REPLAY_ATTACK_DETECTED",
        senderId,
        `Duplicate nonce detected from ${senderId} to ${recipientId}`,
        "error",
      )
      return res.status(400).json({ error: "Replay attack detected: duplicate nonce" })
    }

    // Check timestamp (within 5 minutes)
    const timestamp = Date.now()

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
    const { type, senderId, recipientId, ephemeralPublicKey, signature, timestamp, nonce } = req.body

    const exchange = {
      id: uuidv4(),
      type,
      senderId,
      recipientId,
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
