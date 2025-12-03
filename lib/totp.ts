/**
 * TOTP (Time-based One-Time Password) Implementation
 * Uses only Node.js built-in crypto module (no third-party libraries)
 * Implements RFC 6238 TOTP standard
 */

import * as crypto from "crypto"

/**
 * Generate a random secret for TOTP (base32 encoded, 16 bytes = 26 characters)
 */
export function generateTOTPSecret(): string {
  const randomBytes = crypto.randomBytes(16)
  return base32Encode(randomBytes)
}

/**
 * Generate TOTP code from secret
 * @param secret - Base32 encoded secret
 * @param timeStep - Time step (default 30 seconds)
 * @param digits - Number of digits (default 6)
 */
export function generateTOTP(secret: string, timeStep: number = 30, digits: number = 6): string {
  const key = base32Decode(secret)
  const counter = Math.floor(Date.now() / 1000 / timeStep)
  
  // Convert counter to 8-byte buffer (big-endian)
  const counterBuffer = Buffer.alloc(8)
  counterBuffer.writeUInt32BE(0, 0) // High 4 bytes
  counterBuffer.writeUInt32BE(counter, 4) // Low 4 bytes
  
  // Compute HMAC-SHA1
  const hmac = crypto.createHmac("sha1", key)
  hmac.update(counterBuffer)
  const hmacResult = hmac.digest()
  
  // Dynamic truncation (RFC 4226)
  const offset = hmacResult[19] & 0x0f
  const binary =
    ((hmacResult[offset] & 0x7f) << 24) |
    ((hmacResult[offset + 1] & 0xff) << 16) |
    ((hmacResult[offset + 2] & 0xff) << 8) |
    (hmacResult[offset + 3] & 0xff)
  
  const otp = binary % Math.pow(10, digits)
  return otp.toString().padStart(digits, "0")
}

/**
 * Verify TOTP code (allows time window for clock skew)
 * @param secret - Base32 encoded secret
 * @param code - Code to verify
 * @param timeStep - Time step (default 30 seconds)
 * @param window - Time window in steps (default 1, allows ±1 step = ±30 seconds)
 */
export function verifyTOTP(secret: string, code: string, timeStep: number = 30, window: number = 1): boolean {
  const currentCounter = Math.floor(Date.now() / 1000 / timeStep)
  
  // Check current time step and adjacent steps (for clock skew tolerance)
  for (let i = -window; i <= window; i++) {
    const testCounter = currentCounter + i
    const testCode = generateTOTPAtCounter(secret, testCounter)
    if (testCode === code) {
      return true
    }
  }
  
  return false
}

/**
 * Generate TOTP at specific counter (for verification with time window)
 */
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

/**
 * Generate TOTP URI for QR code
 * @param secret - Base32 encoded secret
 * @param accountName - Account name (username)
 * @param issuer - Issuer name (app name)
 */
export function generateTOTPURI(secret: string, accountName: string, issuer: string = "CipherChat"): string {
  return `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(accountName)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`
}

/**
 * Base32 encoding (RFC 4648)
 */
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

/**
 * Base32 decoding (RFC 4648)
 */
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

