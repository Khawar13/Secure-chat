// Client-side cryptographic operations using Web Crypto API
// This file handles all encryption/decryption on the client side

// Generate ECDSA P-256 key pair for digital signatures (identity key)
export async function generateSigningKeyPair(): Promise<CryptoKeyPair> {
  return await crypto.subtle.generateKey(
    {
      name: "ECDSA",
      namedCurve: "P-256",
    },
    true, // extractable
    ["sign", "verify"],
  )
}

// Generate ECDH P-256 key pair for key exchange (ephemeral)
export async function generateECDHKeyPair(): Promise<CryptoKeyPair> {
  return await crypto.subtle.generateKey(
    {
      name: "ECDH",
      namedCurve: "P-256",
    },
    true,
    ["deriveBits"],
  )
}

// Export public key to JWK format
export async function exportPublicKey(key: CryptoKey): Promise<string> {
  const jwk = await crypto.subtle.exportKey("jwk", key)
  return JSON.stringify(jwk)
}

// Export public key in SPKI format and base64-encode it for canonical representation
export async function exportPublicKeySPKI(key: CryptoKey): Promise<string> {
  const spki = await crypto.subtle.exportKey("spki", key)
  return arrayBufferToBase64(spki)
}

// Import public key from JWK format
export async function importECDSAPublicKey(jwkString: string): Promise<CryptoKey> {
  const jwk = JSON.parse(jwkString)
  return await crypto.subtle.importKey(
    "jwk",
    jwk,
    {
      name: "ECDSA",
      namedCurve: "P-256",
    },
    true,
    ["verify"],
  )
}

// Import ECDH public key
export async function importECDHPublicKey(jwkString: string): Promise<CryptoKey> {
  const jwk = JSON.parse(jwkString)
  return await crypto.subtle.importKey(
    "jwk",
    jwk,
    {
      name: "ECDH",
      namedCurve: "P-256",
    },
    true,
    [],
  )
}

// Import ECDH public key from base64-encoded SPKI
export async function importECDHPublicKeyFromSPKI(spkiBase64: string): Promise<CryptoKey> {
  return await crypto.subtle.importKey(
    "spki",
    base64ToArrayBuffer(spkiBase64),
    {
      name: "ECDH",
      namedCurve: "P-256",
    },
    true,
    [],
  )
}

// Import ECDSA public key from base64-encoded SPKI
export async function importECDSAPublicKeyFromSPKI(spkiBase64: string): Promise<CryptoKey> {
  return await crypto.subtle.importKey(
    "spki",
    base64ToArrayBuffer(spkiBase64),
    {
      name: "ECDSA",
      namedCurve: "P-256",
    },
    true,
    ["verify"],
  )
}

// Sign data with ECDSA private key
export async function signData(privateKey: CryptoKey, data: string): Promise<string> {
  const encoder = new TextEncoder()
  const signature = await crypto.subtle.sign(
    {
      name: "ECDSA",
      hash: "SHA-256",
    },
    privateKey,
    encoder.encode(data),
  )
  return arrayBufferToBase64(signature)
}

// Verify ECDSA signature
export async function verifySignature(publicKey: CryptoKey, signature: string, data: string): Promise<boolean> {
  const encoder = new TextEncoder()
  return await crypto.subtle.verify(
    {
      name: "ECDSA",
      hash: "SHA-256",
    },
    publicKey,
    base64ToArrayBuffer(signature),
    encoder.encode(data),
  )
}

// Derive shared secret using ECDH
export async function deriveSharedSecret(privateKey: CryptoKey, publicKey: CryptoKey): Promise<ArrayBuffer> {
  return await crypto.subtle.deriveBits(
    {
      name: "ECDH",
      public: publicKey,
    },
    privateKey,
    256, // 256 bits
  )
}

// HKDF key derivation for session key
export async function deriveSessionKey(sharedSecret: ArrayBuffer, salt: string, info: string): Promise<CryptoKey> {
  // Import the shared secret as HKDF key material
  const keyMaterial = await crypto.subtle.importKey("raw", sharedSecret, "HKDF", false, ["deriveBits", "deriveKey"])

  // Derive the session key using HKDF
  return await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new TextEncoder().encode(salt),
      info: new TextEncoder().encode(info),
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"],
  )
}

// Generate random IV for AES-GCM (12 bytes recommended)
export function generateIV(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(12))
}

// Generate random nonce for replay protection
export function generateNonce(): string {
  return arrayBufferToBase64(crypto.getRandomValues(new Uint8Array(16)))
}

// Encrypt message with AES-256-GCM
export async function encryptMessage(
  sessionKey: CryptoKey,
  plaintext: string,
): Promise<{ ciphertext: string; iv: string; authTag: string }> {
  const encoder = new TextEncoder()
  const iv = generateIV()

  const encrypted = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: new Uint8Array(iv).buffer,
      tagLength: 128, // 128-bit auth tag
    },
    sessionKey,
    encoder.encode(plaintext),
  )

  // GCM mode appends the auth tag to the ciphertext
  const encryptedArray = new Uint8Array(encrypted)
  const ciphertext = encryptedArray.slice(0, -16)
  const authTag = encryptedArray.slice(-16)

  return {
    ciphertext: arrayBufferToBase64(ciphertext),
    iv: arrayBufferToBase64(iv),
    authTag: arrayBufferToBase64(authTag),
  }
}

// Decrypt message with AES-256-GCM
export async function decryptMessage(
  sessionKey: CryptoKey,
  ciphertext: string,
  iv: string,
  authTag: string,
): Promise<string> {
  const decoder = new TextDecoder()

  // Reconstruct the encrypted data (ciphertext + auth tag)
  const ciphertextArray = base64ToArrayBuffer(ciphertext)
  const authTagArray = base64ToArrayBuffer(authTag)
  const combined = new Uint8Array(ciphertextArray.byteLength + authTagArray.byteLength)
  combined.set(new Uint8Array(ciphertextArray), 0)
  combined.set(new Uint8Array(authTagArray), ciphertextArray.byteLength)

  const decrypted = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: base64ToArrayBuffer(iv),
      tagLength: 128,
    },
    sessionKey,
    combined,
  )

  return decoder.decode(decrypted)
}

// Encrypt file with AES-256-GCM
export async function encryptFile(
  sessionKey: CryptoKey,
  fileData: ArrayBuffer,
): Promise<{ encryptedData: string; iv: string; authTag: string }> {
  const iv = generateIV()

  const encrypted = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: new Uint8Array(iv).buffer,
      tagLength: 128,
    },
    sessionKey,
    fileData,
  )

  const encryptedArray = new Uint8Array(encrypted)
  const ciphertext = encryptedArray.slice(0, -16)
  const authTag = encryptedArray.slice(-16)

  return {
    encryptedData: arrayBufferToBase64(ciphertext),
    iv: arrayBufferToBase64(iv),
    authTag: arrayBufferToBase64(authTag),
  }
}

// Decrypt file with AES-256-GCM
export async function decryptFile(
  sessionKey: CryptoKey,
  encryptedData: string,
  iv: string,
  authTag: string,
): Promise<ArrayBuffer> {
  const ciphertextArray = base64ToArrayBuffer(encryptedData)
  const authTagArray = base64ToArrayBuffer(authTag)
  const combined = new Uint8Array(ciphertextArray.byteLength + authTagArray.byteLength)
  combined.set(new Uint8Array(ciphertextArray), 0)
  combined.set(new Uint8Array(authTagArray), ciphertextArray.byteLength)

  return await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: base64ToArrayBuffer(iv),
      tagLength: 128,
    },
    sessionKey,
    combined,
  )
}

// This proves both parties derived the same session key without revealing it
export async function generateKeyConfirmation(
  sessionKey: CryptoKey,
  senderId: string,
  recipientId: string,
  nonce: string,
): Promise<{ confirmationHash: string; confirmationNonce: string }> {
  // Export session key to compute confirmation hash
  const exportedKey = await crypto.subtle.exportKey("raw", sessionKey)

  // Generate a confirmation nonce for this specific confirmation message
  const confirmationNonce = generateNonce()

  // Create deterministic data to hash: KEY_CONFIRM:senderId:recipientId:nonce:confirmationNonce
  const confirmationData = `KEY_CONFIRM:${senderId}:${recipientId}:${nonce}:${confirmationNonce}`

  // Compute HMAC-SHA256 of the confirmation data using session key as the key
  const hmacKey = await crypto.subtle.importKey("raw", exportedKey, { name: "HMAC", hash: "SHA-256" }, false, ["sign"])

  const confirmationHash = await crypto.subtle.sign("HMAC", hmacKey, new TextEncoder().encode(confirmationData))

  return {
    confirmationHash: arrayBufferToBase64(confirmationHash),
    confirmationNonce,
  }
}

// Verifies that the other party has derived the same session key
export async function verifyKeyConfirmation(
  sessionKey: CryptoKey,
  senderId: string,
  recipientId: string,
  nonce: string,
  confirmationNonce: string,
  receivedHash: string,
): Promise<boolean> {
  // Export session key to compute expected confirmation hash
  const exportedKey = await crypto.subtle.exportKey("raw", sessionKey)

  // Recreate the same confirmation data the sender used
  const confirmationData = `KEY_CONFIRM:${senderId}:${recipientId}:${nonce}:${confirmationNonce}`

  // Compute expected HMAC-SHA256
  const hmacKey = await crypto.subtle.importKey("raw", exportedKey, { name: "HMAC", hash: "SHA-256" }, false, ["sign"])

  const expectedHash = await crypto.subtle.sign("HMAC", hmacKey, new TextEncoder().encode(confirmationData))

  // Compare hashes (constant-time comparison)
  const expectedHashBase64 = arrayBufferToBase64(expectedHash)

  if (expectedHashBase64.length !== receivedHash.length) {
    return false
  }

  let result = 0
  for (let i = 0; i < expectedHashBase64.length; i++) {
    result |= expectedHashBase64.charCodeAt(i) ^ receivedHash.charCodeAt(i)
  }

  return result === 0
}

// Utility functions
export function arrayBufferToBase64(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer)
  let binary = ""
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i])
  }
  return btoa(binary)
}

export function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = atob(base64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes.buffer
}

// Export session key for storage
export async function exportSessionKey(key: CryptoKey): Promise<string> {
  const exported = await crypto.subtle.exportKey("raw", key)
  return arrayBufferToBase64(exported)
}

// Import session key from storage
export async function importSessionKey(keyString: string): Promise<CryptoKey> {
  return await crypto.subtle.importKey("raw", base64ToArrayBuffer(keyString), { name: "AES-GCM", length: 256 }, true, [
    "encrypt",
    "decrypt",
  ])
}
