/**
 * MITM Attack Demonstration - SECURE SCENARIO
 * 
 * This script demonstrates how digital signatures prevent MITM attacks in ECDH.
 * 
 * Shows: With digital signatures, an attacker cannot successfully MITM the key exchange
 * because signature verification detects tampered messages and rejects them.
 * 
 * Run with: npm run mitm-secure
 * Or: npx ts-node scripts/mitm-secure.ts
 * 
 * Optional: Set BACKEND_URL environment variable to log attack attempts to database
 * Example: BACKEND_URL=http://localhost:5000 npx ts-node scripts/mitm-secure.ts
 * 
 * NOTE: This uses ONLY Node.js built-in crypto module (no third-party libraries)
 */

import * as crypto from "crypto"

function arrayBufferToBase64(buffer: Buffer): string {
  return buffer.toString("base64")
}

function base64ToArrayBuffer(base64: string): Buffer {
  return Buffer.from(base64, "base64")
}

interface SecureECDHMessage {
  type: "init" | "response"
  ephemeralPublicKey: string
  senderId: string
  recipientId: string
  senderPublicKey: string 
  signature: string 
  timestamp: number
  nonce: string
}

async function demonstrateSecureECDH() {
  console.log("\n" + "█".repeat(80))
  console.log(" ".repeat(15) + "MITM ATTACK - SECURE SCENARIO")
  console.log("█".repeat(80))
  console.log("\n" + "=".repeat(80))
  console.log("SCENARIO: SECURE ECDH EXCHANGE (WITH SIGNATURES)")
  console.log("=".repeat(80))
  console.log("Participants: Alice (sender), Bob (recipient), Mallory (attacker)\n")

  console.log("[ALICE] Generating identity key pair (ECDSA for signatures)...")
  const aliceIdentityKeyPair = crypto.generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  })
  console.log(`[ALICE] Identity public key: ${aliceIdentityKeyPair.publicKey.substring(0, 50)}...`)

  console.log("[ALICE] Generating ephemeral ECDH key pair...")
  const aliceKeyPair = crypto.createECDH("prime256v1")
  aliceKeyPair.generateKeys()
  const alicePublicKey = aliceKeyPair.getPublicKey()

  const timestamp = Date.now()
  const nonce = arrayBufferToBase64(crypto.randomBytes(16))

  const dataToSign = `${arrayBufferToBase64(alicePublicKey)}:bob:${timestamp}:${nonce}`
  const sign = crypto.createSign("SHA256")
  sign.update(dataToSign)
  sign.end()
  const aliceSignature = sign.sign(aliceIdentityKeyPair.privateKey, "base64")

  console.log(`[ALICE] Signed ephemeral public key with identity key`)
  console.log(`[ALICE] Signature: ${aliceSignature.substring(0, 32)}...`)

  const aliceInit: SecureECDHMessage = {
    type: "init",
    ephemeralPublicKey: arrayBufferToBase64(alicePublicKey),
    senderId: "alice",
    recipientId: "bob",
    senderPublicKey: aliceIdentityKeyPair.publicKey,
    signature: aliceSignature,
    timestamp,
    nonce,
  }
  console.log(`[ALICE] Sending signed INIT to Bob`)

  console.log("\n[MALLORY] *** INTERCEPTING MESSAGE ***")
  console.log("[MALLORY] Received Alice's INIT message")
  console.log("[MALLORY] Attempting to replace Alice's ephemeral public key...")

  const malloryKeyPair = crypto.createECDH("prime256v1")
  malloryKeyPair.generateKeys()
  const malloryPublicKey = malloryKeyPair.getPublicKey()

  const maliciousInit: SecureECDHMessage = {
    ...aliceInit,
    ephemeralPublicKey: arrayBufferToBase64(malloryPublicKey), // REPLACED!
  }
  console.log(`[MALLORY] Replaced Alice's ephemeral public key with my own`)
  console.log(`[MALLORY] Forwarding malicious INIT to Bob...`)

  console.log("\n[BOB] Received INIT message")
  console.log("[BOB] Verifying signature...")

  const verify = crypto.createVerify("SHA256")
  const dataToVerify = `${maliciousInit.ephemeralPublicKey}:bob:${maliciousInit.timestamp}:${maliciousInit.nonce}`
  verify.update(dataToVerify)
  verify.end()

  const isValid = verify.verify(aliceIdentityKeyPair.publicKey, maliciousInit.signature, "base64")

  if (!isValid) {
    console.log("❌ [BOB] SIGNATURE VERIFICATION FAILED!")
    console.log("❌ [BOB] The ephemeral public key does not match the signature")
    console.log("❌ [BOB] Possible MITM attack detected - REJECTING message")
    
    const backendUrl = process.env.BACKEND_URL || "http://localhost:5000"
    try {
      const response = await fetch(`${backendUrl}/api/logs`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          event: "MITM_ATTACK_DETECTED",
          userId: "bob",
          details: "MITM attack detected during key exchange: signature verification failed. Ephemeral public key was tampered with.",
          severity: "error",
        }),
      })
      if (response.ok) {
        console.log("📝 [SYSTEM] MITM attack attempt logged to database")
      }
    } catch (error) {
      console.log("ℹ️  [SYSTEM] Backend not available - attack not logged to database")
    }
    
    console.log("\n" + "-".repeat(80))
    console.log("RESULT: MITM ATTACK PREVENTED!")
    console.log("-".repeat(80))
    console.log("✅ Bob detected that the message was tampered with")
    console.log("✅ Bob rejected the malicious message")
    console.log("✅ Mallory cannot complete the MITM attack")
    console.log("✅ Alice and Bob remain secure")
    
    console.log("\n" + "=".repeat(80))
    console.log("CONCLUSION")
    console.log("=".repeat(80))
    console.log("With digital signatures, ECDH key exchange is secure against MITM attacks.")
    console.log("Signature verification detects tampered messages and prevents the attack.")
    console.log("=".repeat(80) + "\n")
    return
  }

  console.log("⚠️  ERROR: Signature verification should have failed!")
  console.log("⚠️  This indicates a bug in the demonstration script")
  process.exit(1)
}

demonstrateSecureECDH().catch((error) => {
  console.error("Error running demonstration:", error)
  process.exit(1)
})

