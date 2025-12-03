

import * as crypto from "crypto"

function arrayBufferToBase64(buffer: Buffer): string {
  return buffer.toString("base64")
}

function base64ToArrayBuffer(base64: string): Buffer {
  return Buffer.from(base64, "base64")
}

interface VulnerableECDHMessage {
  type: "init" | "response"
  ephemeralPublicKey: string
  senderId: string
  recipientId: string
}

async function demonstrateVulnerableECDH() {
  console.log("\n" + "█".repeat(80))
  console.log(" ".repeat(15) + "MITM ATTACK - VULNERABLE SCENARIO")
  console.log("█".repeat(80))
  console.log("\n" + "=".repeat(80))
  console.log("SCENARIO: VULNERABLE ECDH EXCHANGE (NO SIGNATURES)")
  console.log("=".repeat(80))
  console.log("Participants: Alice (sender), Bob (recipient), Mallory (attacker)\n")

  console.log("[ALICE] Generating ephemeral ECDH key pair...")
  const aliceKeyPair = crypto.createECDH("prime256v1")
  aliceKeyPair.generateKeys()
  const alicePublicKey = aliceKeyPair.getPublicKey()
  console.log(`[ALICE] Public key generated: ${arrayBufferToBase64(alicePublicKey).substring(0, 32)}...`)

  const aliceInit: VulnerableECDHMessage = {
    type: "init",
    ephemeralPublicKey: arrayBufferToBase64(alicePublicKey),
    senderId: "alice",
    recipientId: "bob",
  }
  console.log(`[ALICE] Sending INIT to Bob: { type: "init", ephemeralPublicKey: "...", senderId: "alice" }`)

  console.log("\n[MALLORY] *** INTERCEPTING MESSAGE ***")
  console.log("[MALLORY] Received Alice's INIT message")
  console.log("[MALLORY] Generating my own key pair to impersonate Alice...")
  const malloryKeyPair = crypto.createECDH("prime256v1")
  malloryKeyPair.generateKeys()
  const malloryPublicKey = malloryKeyPair.getPublicKey()

  const maliciousInit: VulnerableECDHMessage = {
    ...aliceInit,
    ephemeralPublicKey: arrayBufferToBase64(malloryPublicKey), // REPLACED!
  }
  console.log(`[MALLORY] Replaced Alice's public key with my own`)
  console.log(`[MALLORY] Forwarding malicious INIT to Bob (pretending to be Alice)...`)

  console.log("\n[BOB] Received INIT message (from Mallory, but thinks it's from Alice)")
  console.log("[BOB] Generating my ephemeral ECDH key pair...")
  const bobKeyPair = crypto.createECDH("prime256v1")
  bobKeyPair.generateKeys()
  const bobPublicKey = bobKeyPair.getPublicKey()
  console.log(`[BOB] Public key generated: ${arrayBufferToBase64(bobPublicKey).substring(0, 32)}...`)

  const bobSharedSecret = bobKeyPair.computeSecret(base64ToArrayBuffer(maliciousInit.ephemeralPublicKey))
  console.log(`[BOB] Derived shared secret: ${arrayBufferToBase64(bobSharedSecret).substring(0, 32)}...`)

  const bobResponse: VulnerableECDHMessage = {
    type: "response",
    ephemeralPublicKey: arrayBufferToBase64(bobPublicKey),
    senderId: "bob",
    recipientId: "alice",
  }
  console.log(`[BOB] Sending RESPONSE to Alice: { type: "response", ephemeralPublicKey: "...", senderId: "bob" }`)

  console.log("\n[MALLORY] *** INTERCEPTING RESPONSE ***")
  console.log("[MALLORY] Received Bob's RESPONSE")
  console.log("[MALLORY] Deriving shared secret with Bob...")
  const mallorySharedSecretWithBob = malloryKeyPair.computeSecret(bobPublicKey)
  console.log(`[MALLORY] Shared secret with Bob: ${arrayBufferToBase64(mallorySharedSecretWithBob).substring(0, 32)}...`)

  const malloryKeyPair2 = crypto.createECDH("prime256v1")
  malloryKeyPair2.generateKeys()
  const malloryPublicKey2 = malloryKeyPair2.getPublicKey()

  const maliciousResponse: VulnerableECDHMessage = {
    ...bobResponse,
    ephemeralPublicKey: arrayBufferToBase64(malloryPublicKey2),
  }
  console.log(`[MALLORY] Replaced Bob's public key with my own`)
  console.log(`[MALLORY] Forwarding malicious RESPONSE to Alice (pretending to be Bob)...`)

  console.log("\n[ALICE] Received RESPONSE message (from Mallory, but thinks it's from Bob)")
  console.log("[ALICE] Deriving shared secret...")
  const aliceSharedSecret = aliceKeyPair.computeSecret(base64ToArrayBuffer(maliciousResponse.ephemeralPublicKey))
  console.log(`[ALICE] Derived shared secret: ${arrayBufferToBase64(aliceSharedSecret).substring(0, 32)}...`)

  console.log("\n" + "-".repeat(80))
  console.log("RESULT: MITM ATTACK SUCCESSFUL!")
  console.log("-".repeat(80))
  console.log(`[ALICE] thinks she shares secret with Bob: ${arrayBufferToBase64(aliceSharedSecret).substring(0, 32)}...`)
  console.log(`[BOB] thinks he shares secret with Alice: ${arrayBufferToBase64(bobSharedSecret).substring(0, 32)}...`)
  console.log(`[MALLORY] shares secret with Alice: ${arrayBufferToBase64(aliceSharedSecret).substring(0, 32)}...`)
  console.log(`[MALLORY] shares secret with Bob: ${arrayBufferToBase64(mallorySharedSecretWithBob).substring(0, 32)}...`)
  
  console.log("\n❌ PROBLEM: Alice and Bob have DIFFERENT secrets!")
  console.log("❌ Mallory can decrypt all messages between Alice and Bob")
  console.log("❌ Mallory can read, modify, and forward messages without detection")
  console.log("❌ Neither Alice nor Bob knows they're being attacked")
  
  const backendUrl = process.env.BACKEND_URL || "http://localhost:5000"
  try {
    const response = await fetch(`${backendUrl}/api/logs`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        event: "MITM_ATTACK_SUCCESSFUL",
        userId: null,
        details: "MITM attack successful in vulnerable scenario: No signatures enabled. Attacker intercepted and replaced public keys. Both parties derived different secrets.",
        severity: "error",
      }),
    })
    if (response.ok) {
      console.log("📝 [SYSTEM] MITM attack logged to database")
    }
  } catch (error) {
    console.log("ℹ️  [SYSTEM] Backend not available - attack not logged to database")
  }
  
  console.log("\n" + "=".repeat(80))
  console.log("CONCLUSION")
  console.log("=".repeat(80))
  console.log("Without digital signatures, ECDH key exchange is vulnerable to MITM attacks.")
  console.log("The attacker can successfully intercept and modify messages without detection.")
  console.log("=".repeat(80) + "\n")
}

demonstrateVulnerableECDH().catch((error) => {
  console.error("Error running demonstration:", error)
  process.exit(1)
})

