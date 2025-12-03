"use client"

import { useState, useCallback } from "react"
import {
  generateSigningKeyPair,
  generateECDHKeyPair,
  exportPublicKey,
  exportPublicKeySPKI,
  importECDSAPublicKey,
  importECDHPublicKey,
  importECDHPublicKeyFromSPKI,
  importECDSAPublicKeyFromSPKI,
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
  generateKeyConfirmation,
  verifyKeyConfirmation,
} from "@/lib/crypto-client"
import { storeKeys, getKeys, getSessionId } from "@/lib/indexed-db"

export function useCrypto() {
  const [identityKeyPair, setIdentityKeyPair] = useState<CryptoKeyPair | null>(null)
  const [sessionKeys, setSessionKeys] = useState<Map<string, CryptoKey>>(new Map())
  const [currentUserId, setCurrentUserId] = useState<string | null>(null)
  const [confirmedSessions, setConfirmedSessions] = useState<Set<string>>(new Set())

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
      const ephemeralPublicKey = await exportPublicKeySPKI(ephemeralKeyPair.publicKey)

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
      if (!currentUserId) throw new Error("Current user ID not set")

      // Verify timestamp (within 5 minutes)
      if (Math.abs(Date.now() - timestamp) > 5 * 60 * 1000) {
        throw new Error("Key exchange timestamp expired")
      }

      // Import sender's identity public key and verify signature
      const senderIdentityKey = await importECDSAPublicKey(senderPublicKey)
      const dataToVerify = `${ephemeralPublicKey}:${currentUserId}:${timestamp}:${nonce}`
      const isValid = await verifySignature(senderIdentityKey, signature, dataToVerify)
      if (!isValid) {
        console.error("Signature verification failed on responder. Debug info:", {
          senderId,
          senderPublicKey,
          ephemeralPublicKey,
          signature,
          dataToVerify,
        })
      }

      if (!isValid) {
        throw new Error("Invalid signature - possible MITM attack")
      }

      // Generate responder's ephemeral ECDH key pair
      const responseKeyPair = await generateECDHKeyPair()
      const responseEphemeralPublicKey = await exportPublicKeySPKI(responseKeyPair.publicKey)

      const responseTimestamp = Date.now()
      const responseNonce = generateNonce()

      const responseDataToSign = `${responseEphemeralPublicKey}:${senderId}:${responseTimestamp}:${responseNonce}`
      const responseSignature = await signData(identityKeyPair.privateKey, responseDataToSign)

      // Import sender's ephemeral public key and derive shared secret
      const senderEphemeralKey = await importECDHPublicKeyFromSPKI(ephemeralPublicKey)
      const sharedSecret = await deriveSharedSecret(responseKeyPair.privateKey, senderEphemeralKey)

      const salt = `${nonce}:${responseNonce}`
      const info = `session:${senderId}:${currentUserId}`
      const sessionKey = await deriveSessionKey(sharedSecret, salt, info)

      const sessionId = getSessionId(currentUserId, senderId)
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
      if (!currentUserId) throw new Error("Current user ID not set")

      // Verify timestamp
      if (Math.abs(Date.now() - responseTimestamp) > 5 * 60 * 1000) {
        throw new Error("Response timestamp expired")
      }

      // Verify responder's signature
      const recipientIdentityKey = await importECDSAPublicKey(recipientPublicKey)
      const dataToVerify = `${responseEphemeralPublicKey}:${currentUserId}:${responseTimestamp}:${responseNonce}`
      const isValid = await verifySignature(recipientIdentityKey, responseSignature, dataToVerify)

      if (!isValid) {
        console.error("Signature verification failed on initiator when verifying responder's signature. Debug info:", {
          recipientId,
          recipientPublicKey,
          responseEphemeralPublicKey,
          responseSignature,
          dataToVerify,
        })
        throw new Error("Invalid response signature - possible MITM attack")
      }

      // Import responder's ephemeral public key and derive shared secret
      const responderEphemeralKey = await importECDHPublicKeyFromSPKI(responseEphemeralPublicKey)
      const sharedSecret = await deriveSharedSecret(ephemeralPrivateKey, responderEphemeralKey)

      const salt = `${originalNonce}:${responseNonce}`
      const info = `session:${currentUserId}:${recipientId}`
      const sessionKey = await deriveSessionKey(sharedSecret, salt, info)

      const sessionId = getSessionId(currentUserId, recipientId)
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

  const createKeyConfirmation = useCallback(
    async (
      recipientId: string,
      originalNonce: string,
    ): Promise<{
      confirmationHash: string
      confirmationNonce: string
      timestamp: number
    }> => {
      if (!currentUserId) throw new Error("User ID not set")

      const sessionKey = await loadSessionKeyInternal(recipientId)
      if (!sessionKey) throw new Error("No session key for recipient")

      const { confirmationHash, confirmationNonce } = await generateKeyConfirmation(
        sessionKey,
        currentUserId,
        recipientId,
        originalNonce,
      )

      return {
        confirmationHash,
        confirmationNonce,
        timestamp: Date.now(),
      }
    },
    [currentUserId],
  )

  const verifyReceivedKeyConfirmation = useCallback(
    async (
      senderId: string,
      confirmationHash: string,
      confirmationNonce: string,
      originalNonce: string,
    ): Promise<boolean> => {
      if (!currentUserId) throw new Error("User ID not set")

      const sessionKey = await loadSessionKeyInternal(senderId)
      if (!sessionKey) throw new Error("No session key for sender")

      const isValid = await verifyKeyConfirmation(
        sessionKey,
        senderId,
        currentUserId,
        originalNonce,
        confirmationNonce,
        confirmationHash,
      )

      if (isValid) {
        setConfirmedSessions((prev) => new Set(prev).add(senderId))
      }

      return isValid
    },
    [currentUserId],
  )

  const markSessionConfirmed = useCallback((recipientId: string) => {
    setConfirmedSessions((prev) => new Set(prev).add(recipientId))
  }, [])

  const isSessionConfirmed = useCallback(
    (recipientId: string): boolean => {
      return confirmedSessions.has(recipientId)
    },
    [confirmedSessions],
  )

  // Internal helper to load session key without state updates
  const loadSessionKeyInternal = async (recipientId: string): Promise<CryptoKey | null> => {
    const memoryKey = sessionKeys.get(recipientId)
    if (memoryKey) return memoryKey

    if (!currentUserId) return null

    const sessionId = getSessionId(currentUserId, recipientId)
    const stored = await getKeys(`session-${sessionId}`)
    if (!stored) return null

    return await importSessionKey(stored.privateKey)
  }

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
      setConfirmedSessions((prev) => new Set(prev).add(recipientId))
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
    confirmedSessions,
    currentUserId,
    setUserId,
    generateIdentityKeys,
    loadIdentityKeys,
    initiateKeyExchange,
    respondToKeyExchange,
    completeKeyExchange,
    createKeyConfirmation,
    verifyReceivedKeyConfirmation,
    markSessionConfirmed,
    isSessionConfirmed,
    loadSessionKey,
    storeSessionKeyForUser,
    encrypt,
    decrypt,
    encryptFileData,
    decryptFileData,
  }
}
