// Core types for the secure messaging system

export interface User {
  id: string
  username: string
  passwordHash: string
  publicKey: string // ECDSA P-256 public key (for signatures)
  createdAt: number
}

export interface Session {
  id: string
  oderId: string
  recipientId: string
  sessionKey: string // Derived session key (base64)
  createdAt: number
  expiresAt: number
  sequenceNumber: number
}

export interface Message {
  id: string
  senderId: string
  recipientId: string
  ciphertext: string // AES-256-GCM encrypted
  iv: string // Base64 encoded IV
  authTag: string // GCM authentication tag
  timestamp: number
  nonce: string // For replay protection
  sequenceNumber: number
}

export interface EncryptedFile {
  id: string
  senderId: string
  recipientId: string
  filename: string
  encryptedData: string // Base64 encoded
  iv: string
  authTag: string
  size: number
  timestamp: number
}

export interface KeyExchangeMessage {
  type: "init" | "response" | "confirm"
  senderId: string
  recipientId: string
  senderPublicKey?: string // Sender's identity public key (ECDSA) for signature verification
  ephemeralPublicKey: string // ECDH public key (empty for confirm type)
  signature: string // ECDSA signature of the ephemeral key + timestamp
  timestamp: number
  nonce: string
  // Key confirmation fields
  confirmationHash?: string // HMAC-SHA256 hash proving session key derivation
  confirmationNonce?: string // Nonce used in confirmation hash computation
}

export interface KeyConfirmationMessage {
  type: "confirm"
  senderId: string
  recipientId: string
  confirmationHash: string // HMAC-SHA256 hash proving session key derivation
  confirmationNonce: string // Nonce used in confirmation hash computation
  originalNonce: string // Original nonce from key exchange for verification
  timestamp: number
}

export interface SecurityLog {
  id: string
  type: string
  userId?: string
  details: string
  timestamp: number
  success: boolean
  severity?: "info" | "warning" | "error"
  event?: string
  ipAddress?: string
}

export interface ClientKeyPair {
  publicKey: CryptoKey
  privateKey: CryptoKey
}

export interface ExportedKeyPair {
  publicKey: string // JWK format
  privateKey: string // JWK format (encrypted in storage)
}
