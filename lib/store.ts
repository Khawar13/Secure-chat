// MongoDB Store for Secure Messaging System
// Replaces the in-memory store with persistent MongoDB Atlas storage

import {
  getUsersCollection,
  getMessagesCollection,
  getFilesCollection,
  getSecurityLogsCollection,
  getNoncesCollection,
  getSessionKeysCollection,
  getSessionsCollection,
} from "./mongodb"
import type { User, Message, EncryptedFile, SecurityLog, Session } from "./types"

function getSymmetricSessionId(userId1: string, userId2: string): string {
  return [userId1, userId2].sort().join("-")
}

class MongoDBStore {
  // User operations
  async createUser(user: User): Promise<User> {
    const users = await getUsersCollection()
    await users.insertOne(user)
    return user
  }

  async getUserById(id: string): Promise<User | null> {
    const users = await getUsersCollection()
    return users.findOne({ id }) as Promise<User | null>
  }

  async getUserByUsername(username: string): Promise<User | null> {
    const users = await getUsersCollection()
    return users.findOne({ username }) as Promise<User | null>
  }

  async getAllUsers(): Promise<User[]> {
    const usersCollection = await getUsersCollection()
    const docs = await usersCollection.find({}).toArray()

    // Map MongoDB documents to User type
    return docs.map(doc => ({
      id: doc.id,
      username: doc.username,
      passwordHash: doc.passwordHash,
      publicKey: doc.publicKey,
      createdAt: doc.createdAt,
    }))
  }


  // Message operations
  async addMessage(message: Message): Promise<Message> {
    const messages = await getMessagesCollection()
    await messages.insertOne(message)
    return message
  }

  async getMessagesBetweenUsers(userId1: string, userId2: string): Promise<Message[]> {
    const messagesCollection = await getMessagesCollection()
    const docs = await messagesCollection
      .find({
        $or: [
          { senderId: userId1, recipientId: userId2 },
          { senderId: userId2, recipientId: userId1 },
        ],
      })
      .sort({ timestamp: 1 })
      .toArray()

    // Map MongoDB documents to Message type
    return docs.map(doc => ({
      id: doc.id,
      senderId: doc.senderId,
      recipientId: doc.recipientId,
      ciphertext: doc.ciphertext,
      iv: doc.iv,
      authTag: doc.authTag,
      timestamp: doc.timestamp,
      nonce: doc.nonce,
      sequenceNumber: doc.sequenceNumber,
    }))
  }


  // File operations
  async addFile(file: EncryptedFile): Promise<EncryptedFile> {
    const files = await getFilesCollection()
    await files.insertOne(file)
    return file
  }

  async getFile(id: string): Promise<EncryptedFile | null> {
    const files = await getFilesCollection()
    return files.findOne({ id }) as Promise<EncryptedFile | null>
  }

  async getFilesByUser(userId: string): Promise<EncryptedFile[]> {
    const filesCollection = await getFilesCollection()
    const docs = await filesCollection
      .find({
        $or: [{ senderId: userId }, { recipientId: userId }],
      })
      .toArray()

    return docs.map(doc => ({
      id: doc.id,
      senderId: doc.senderId,
      recipientId: doc.recipientId,
      filename: doc.filename,
      encryptedData: doc.encryptedData,
      iv: doc.iv,
      authTag: doc.authTag,
      size: doc.size,
      timestamp: doc.timestamp,
    }))
  }


  async getFilesBetweenUsers(userId1: string, userId2: string): Promise<EncryptedFile[]> {
    const filesCollection = await getFilesCollection()
    const docs = await filesCollection
      .find({
        $or: [
          { senderId: userId1, recipientId: userId2 },
          { senderId: userId2, recipientId: userId1 },
        ],
      })
      .sort({ timestamp: -1 })
      .toArray()

    return docs.map(doc => ({
      id: doc.id,
      senderId: doc.senderId,
      recipientId: doc.recipientId,
      filename: doc.filename,
      encryptedData: doc.encryptedData,
      iv: doc.iv,
      authTag: doc.authTag,
      size: doc.size,
      timestamp: doc.timestamp,
    }))
  }


  // Security log operations
  async addSecurityLog(log: SecurityLog): Promise<SecurityLog> {
    const logs = await getSecurityLogsCollection()
    await logs.insertOne(log)
    return log
  }

  async getSecurityLogs(limit = 100): Promise<SecurityLog[]> {
    const logsCollection = await getSecurityLogsCollection()
    const docs = await logsCollection
      .find({})
      .sort({ timestamp: -1 })
      .limit(limit)
      .toArray()

    return docs.map(doc => ({
      id: doc.id,
      type: doc.type,
      userId: doc.userId,
      details: doc.details,
      timestamp: doc.timestamp,
      success: doc.success,
    }))
  }


  // Session operations
  async createSession(session: Session): Promise<Session> {
    const sessions = await getSessionsCollection()
    const sessionId = getSymmetricSessionId(session.oderId, session.recipientId)
    await sessions.updateOne({ sessionId }, { $set: { ...session, sessionId } }, { upsert: true })
    return session
  }

  async getSession(userId1: string, userId2: string): Promise<Session | null> {
    const sessions = await getSessionsCollection()
    const sessionId = getSymmetricSessionId(userId1, userId2)
    return sessions.findOne({ sessionId }) as Promise<Session | null>
  }

  // Shared session key operations (for key exchange)
  async storeSharedSessionKey(userId1: string, userId2: string, exportedKey: string): Promise<void> {
    const sessionKeys = await getSessionKeysCollection()
    const sessionId = getSymmetricSessionId(userId1, userId2)
    await sessionKeys.updateOne(
      { sessionId },
      { $set: { sessionId, exportedKey, createdAt: new Date() } },
      { upsert: true },
    )
  }

  async getSharedSessionKey(userId1: string, userId2: string): Promise<string | null> {
    const sessionKeys = await getSessionKeysCollection()
    const sessionId = getSymmetricSessionId(userId1, userId2)
    const result = await sessionKeys.findOne({ sessionId })
    return result?.exportedKey || null
  }

  async hasSharedSessionKey(userId1: string, userId2: string): Promise<boolean> {
    const sessionKeys = await getSessionKeysCollection()
    const sessionId = getSymmetricSessionId(userId1, userId2)
    const count = await sessionKeys.countDocuments({ sessionId })
    return count > 0
  }

  // Replay protection with MongoDB
  async isNonceUsed(nonce: string): Promise<boolean> {
    const nonces = await getNoncesCollection()
    const count = await nonces.countDocuments({ nonce })
    return count > 0
  }

  async markNonceUsed(nonce: string): Promise<void> {
    const nonces = await getNoncesCollection()
    await nonces.insertOne({ nonce, createdAt: new Date() })
  }
}

// Singleton instance
export const store = new MongoDBStore()
