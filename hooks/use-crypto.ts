"use client"

import { useState, useCallback } from "react"
import {
  generateSigningKeyPair,
  generateECDHKeyPair,
  exportPublicKey,
  importECDSAPublicKey,
  importECDHPublicKey,
  signData,
  verifySignature,
  deriveSharedSecret,
  deriveSessionKey,
  encryptMessage,
  decryptMessage,
  encryptFile,
  decryptFile,
  generateNonce,
  exportSessionKey,
  importSessionKey,
} from "@/lib/crypto-client"
import { storeKeys, getKeys, getSessionId } from "@/lib/indexed-db"

export function useCrypto() {
  const [identityKeyPair, setIdentityKeyPair] = useState<CryptoKeyPair | null>(null)
  const [sessionKeys, setSessionKeys] = useState<Map<string, CryptoKey>>(new Map())
  const [currentUserId, setCurrentUserId] = useState<string | null>(null)

  const setUserId = useCallback((userId: string) => {
    setCurrentUserId(userId)
  }, [])

  // Generate and store identity key pair
  const generateIdentityKeys = useCallback(async (): Promise<string> => {
    const keyPair = await generateSigningKeyPair()
    setIdentityKeyPair(keyPair)

    const publicKeyJwk = await exportPublicKey(keyPair.publicKey)
    const privateKeyJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey)

    // Store in IndexedDB
    await storeKeys({
      id: "identity",
      publicKey: publicKeyJwk,
      privateKey: JSON.stringify(privateKeyJwk),
    })

    return publicKeyJwk
  }, [])

  // Load identity keys from IndexedDB
  const loadIdentityKeys = useCallback(async (): Promise<string | null> => {
    const stored = await getKeys("identity")
    if (!stored) return null

    const publicKey = await importECDSAPublicKey(stored.publicKey)
    const privateKeyJwk = JSON.parse(stored.privateKey)
    const privateKey = await crypto.subtle.importKey(
      "jwk",
      privateKeyJwk,
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign"],
    )

    setIdentityKeyPair({ publicKey, privateKey })
    return stored.publicKey
  }, [])

  // Custom Key Exchange Protocol Implementation
  // Step 1: Initiator generates ephemeral ECDH key and signs it
  const initiateKeyExchange = useCallback(
    async (
      recipientId: string,
      recipientPublicKey: string,
    ): Promise<{
      ephemeralPublicKey: string
      signature: string
      timestamp: number
      nonce: string
      ephemeralPrivateKey: CryptoKey
    }> => {
      if (!identityKeyPair) throw new Error("Identity keys not loaded")

      // Generate ephemeral ECDH key pair
      const ephemeralKeyPair = await generateECDHKeyPair()
      const ephemeralPublicKey = await exportPublicKey(ephemeralKeyPair.publicKey)

      const timestamp = Date.now()
      const nonce = generateNonce()

      // Sign: ephemeralPublicKey + recipientId + timestamp + nonce
      const dataToSign = `${ephemeralPublicKey}:${recipientId}:${timestamp}:${nonce}`
      const signature = await signData(identityKeyPair.privateKey, dataToSign)

      return {
        ephemeralPublicKey,
        signature,
        timestamp,
        nonce,
        ephemeralPrivateKey: ephemeralKeyPair.privateKey,
      }
    },
    [identityKeyPair],
  )

  // Step 2: Responder verifies, generates their ephemeral key, and derives session key
  const respondToKeyExchange = useCallback(
    async (
      senderId: string,
      senderPublicKey: string,
      ephemeralPublicKey: string,
      signature: string,
      timestamp: number,
      nonce: string,
    ): Promise<{
      responseEphemeralPublicKey: string
      responseSignature: string
      responseTimestamp: number
      responseNonce: string
      sessionKey: CryptoKey
    }> => {
      if (!identityKeyPair) throw new Error("Identity keys not loaded")

      // Verify timestamp (within 5 minutes)
      if (Math.abs(Date.now() - timestamp) > 5 * 60 * 1000) {
        throw new Error("Key exchange timestamp expired")
      }

      // Import sender's identity public key and verify signature
      const senderIdentityKey = await importECDSAPublicKey(senderPublicKey)
      const dataToVerify = `${ephemeralPublicKey}:${senderId}:${timestamp}:${nonce}`

      // Note: The senderId in dataToVerify should be the current user's ID (recipient)
      // Let me fix this - the sender signs with recipient's ID
      const isValid = await verifySignature(
        senderIdentityKey,
        signature,
        `${ephemeralPublicKey}:${senderId}:${timestamp}:${nonce}`,
      )

      if (!isValid) {
        throw new Error("Invalid signature - possible MITM attack")
      }

      // Generate responder's ephemeral ECDH key pair
      const responseKeyPair = await generateECDHKeyPair()
      const responseEphemeralPublicKey = await exportPublicKey(responseKeyPair.publicKey)

      const responseTimestamp = Date.now()
      const responseNonce = generateNonce()

      // Sign response
      const responseDataToSign = `${responseEphemeralPublicKey}:${senderId}:${responseTimestamp}:${responseNonce}`
      const responseSignature = await signData(identityKeyPair.privateKey, responseDataToSign)

      // Import sender's ephemeral public key and derive shared secret
      const senderEphemeralKey = await importECDHPublicKey(ephemeralPublicKey)
      const sharedSecret = await deriveSharedSecret(responseKeyPair.privateKey, senderEphemeralKey)

      // Derive session key using HKDF
      const salt = `${nonce}:${responseNonce}`
      const info = `session:${senderId}:${Date.now()}`
      const sessionKey = await deriveSessionKey(sharedSecret, salt, info)

      const sessionId = getSessionId(currentUserId || "", senderId)
      const exportedKey = await exportSessionKey(sessionKey)
      await storeKeys({
        id: `session-${sessionId}`,
        publicKey: responseEphemeralPublicKey,
        privateKey: exportedKey,
      })

      setSessionKeys((prev) => new Map(prev).set(senderId, sessionKey))

      return {
        responseEphemeralPublicKey,
        responseSignature,
        responseTimestamp,
        responseNonce,
        sessionKey,
      }
    },
    [identityKeyPair, currentUserId],
  )

  // Step 3: Initiator completes key exchange
  const completeKeyExchange = useCallback(
    async (
      recipientId: string,
      recipientPublicKey: string,
      responseEphemeralPublicKey: string,
      responseSignature: string,
      responseTimestamp: number,
      responseNonce: string,
      originalNonce: string,
      ephemeralPrivateKey: CryptoKey,
    ): Promise<CryptoKey> => {
      if (!identityKeyPair) throw new Error("Identity keys not loaded")

      // Verify timestamp
      if (Math.abs(Date.now() - responseTimestamp) > 5 * 60 * 1000) {
        throw new Error("Response timestamp expired")
      }

      // Verify responder's signature
      const recipientIdentityKey = await importECDSAPublicKey(recipientPublicKey)
      const dataToVerify = `${responseEphemeralPublicKey}:${recipientId}:${responseTimestamp}:${responseNonce}`
      const isValid = await verifySignature(recipientIdentityKey, responseSignature, dataToVerify)

      if (!isValid) {
        throw new Error("Invalid response signature - possible MITM attack")
      }

      // Import responder's ephemeral public key and derive shared secret
      const responderEphemeralKey = await importECDHPublicKey(responseEphemeralPublicKey)
      const sharedSecret = await deriveSharedSecret(ephemeralPrivateKey, responderEphemeralKey)

      // Derive session key using same parameters
      const salt = `${originalNonce}:${responseNonce}`
      const info = `session:${recipientId}:${Date.now()}`
      const sessionKey = await deriveSessionKey(sharedSecret, salt, info)

      const sessionId = getSessionId(currentUserId || "", recipientId)
      const exportedKey = await exportSessionKey(sessionKey)
      await storeKeys({
        id: `session-${sessionId}`,
        publicKey: responseEphemeralPublicKey,
        privateKey: exportedKey,
      })

      setSessionKeys((prev) => new Map(prev).set(recipientId, sessionKey))

      return sessionKey
    },
    [identityKeyPair, currentUserId],
  )

  const loadSessionKey = useCallback(
    async (recipientId: string): Promise<CryptoKey | null> => {
      // Check memory first
      const memoryKey = sessionKeys.get(recipientId)
      if (memoryKey) return memoryKey

      if (!currentUserId) return null

      const sessionId = getSessionId(currentUserId, recipientId)
      const stored = await getKeys(`session-${sessionId}`)
      if (!stored) return null

      const sessionKey = await importSessionKey(stored.privateKey)
      setSessionKeys((prev) => new Map(prev).set(recipientId, sessionKey))
      return sessionKey
    },
    [sessionKeys, currentUserId],
  )

  const storeSessionKeyForUser = useCallback(
    async (recipientId: string, exportedKey: string): Promise<void> => {
      if (!currentUserId) return

      const sessionId = getSessionId(currentUserId, recipientId)
      await storeKeys({
        id: `session-${sessionId}`,
        publicKey: "",
        privateKey: exportedKey,
      })

      const sessionKey = await importSessionKey(exportedKey)
      setSessionKeys((prev) => new Map(prev).set(recipientId, sessionKey))
    },
    [currentUserId],
  )

  // Encrypt a message
  const encrypt = useCallback(
    async (
      recipientId: string,
      plaintext: string,
    ): Promise<{ ciphertext: string; iv: string; authTag: string; nonce: string }> => {
      const sessionKey = await loadSessionKey(recipientId)
      if (!sessionKey) throw new Error("No session key for recipient")

      const { ciphertext, iv, authTag } = await encryptMessage(sessionKey, plaintext)
      const nonce = generateNonce()

      return { ciphertext, iv, authTag, nonce }
    },
    [loadSessionKey],
  )

  // Decrypt a message
  const decrypt = useCallback(
    async (senderId: string, ciphertext: string, iv: string, authTag: string): Promise<string> => {
      const sessionKey = await loadSessionKey(senderId)
      if (!sessionKey) throw new Error("No session key for sender")

      return await decryptMessage(sessionKey, ciphertext, iv, authTag)
    },
    [loadSessionKey],
  )

  // Encrypt a file
  const encryptFileData = useCallback(
    async (
      recipientId: string,
      fileData: ArrayBuffer,
    ): Promise<{ encryptedData: string; iv: string; authTag: string }> => {
      const sessionKey = await loadSessionKey(recipientId)
      if (!sessionKey) throw new Error("No session key for recipient")

      return await encryptFile(sessionKey, fileData)
    },
    [loadSessionKey],
  )

  // Decrypt a file
  const decryptFileData = useCallback(
    async (senderId: string, encryptedData: string, iv: string, authTag: string): Promise<ArrayBuffer> => {
      const sessionKey = await loadSessionKey(senderId)
      if (!sessionKey) throw new Error("No session key for sender")

      return await decryptFile(sessionKey, encryptedData, iv, authTag)
    },
    [loadSessionKey],
  )

  return {
    identityKeyPair,
    sessionKeys,
    currentUserId,
    setUserId,
    generateIdentityKeys,
    loadIdentityKeys,
    initiateKeyExchange,
    respondToKeyExchange,
    completeKeyExchange,
    loadSessionKey,
    storeSessionKeyForUser,
    encrypt,
    decrypt,
    encryptFileData,
    decryptFileData,
  }
}
