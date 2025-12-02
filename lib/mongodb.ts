// MongoDB connection utility for Secure Messaging System
import { MongoClient, type Db, type Collection } from "mongodb"

const MONGODB_URI =
  process.env.MONGODB_URI ||
  "mongodb+srv://i222657:goku1356@a3p2.p7u3y.mongodb.net/?retryWrites=true&w=majority&appName=a3p2"
const DB_NAME = "secure_messaging"

// Cached connection
let cachedClient: MongoClient | null = null
let cachedDb: Db | null = null

export async function connectToDatabase(): Promise<{ client: MongoClient; db: Db }> {
  if (cachedClient && cachedDb) {
    return { client: cachedClient, db: cachedDb }
  }

  const client = new MongoClient(MONGODB_URI)
  await client.connect()
  const db = client.db(DB_NAME)

  cachedClient = client
  cachedDb = db

  // Create indexes for better performance
  await createIndexes(db)

  return { client, db }
}

async function createIndexes(db: Db) {
  try {
    // Users collection indexes
    await db.collection("users").createIndex({ username: 1 }, { unique: true })

    // Messages collection indexes
    await db.collection("messages").createIndex({ senderId: 1, recipientId: 1 })
    await db.collection("messages").createIndex({ timestamp: -1 })

    // Files collection indexes
    await db.collection("files").createIndex({ senderId: 1 })
    await db.collection("files").createIndex({ recipientId: 1 })

    // Security logs index
    await db.collection("security_logs").createIndex({ timestamp: -1 })
    await db.collection("security_logs").createIndex({ userId: 1 })

    // Nonces index with TTL (auto-expire after 24 hours)
    await db.collection("nonces").createIndex({ createdAt: 1 }, { expireAfterSeconds: 86400 })

    // Session keys index
    await db.collection("session_keys").createIndex({ sessionId: 1 }, { unique: true })
  } catch (error) {
    // Indexes might already exist, that's fine
    console.log("Indexes already exist or created")
  }
}

// Collection getters
export async function getUsersCollection(): Promise<Collection> {
  const { db } = await connectToDatabase()
  return db.collection("users")
}

export async function getMessagesCollection(): Promise<Collection> {
  const { db } = await connectToDatabase()
  return db.collection("messages")
}

export async function getFilesCollection(): Promise<Collection> {
  const { db } = await connectToDatabase()
  return db.collection("files")
}

export async function getSecurityLogsCollection(): Promise<Collection> {
  const { db } = await connectToDatabase()
  return db.collection("security_logs")
}

export async function getNoncesCollection(): Promise<Collection> {
  const { db } = await connectToDatabase()
  return db.collection("nonces")
}

export async function getSessionKeysCollection(): Promise<Collection> {
  const { db } = await connectToDatabase()
  return db.collection("session_keys")
}

export async function getSessionsCollection(): Promise<Collection> {
  const { db } = await connectToDatabase()
  return db.collection("sessions")
}
