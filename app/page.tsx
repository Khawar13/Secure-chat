"use client"

import { useState, useEffect, useCallback, useRef } from "react"
import { AuthForm } from "@/components/auth-form"
import { ChatSidebar } from "@/components/chat-sidebar"
import { ChatWindow } from "@/components/chat-window"
import { SecurityLogs } from "@/components/security-logs"
import { KeyExchangeModal } from "@/components/key-exchange-modal"
import { useCrypto } from "@/hooks/use-crypto"
import { useSocket } from "@/hooks/use-socket"
import type { Message, KeyExchangeMessage } from "@/lib/types"
import { Shield, Key, Lock } from "lucide-react"
import type { KeyConfirmationMessage } from "@/lib/types" // Declare the variable here

const API_URL = "http://localhost:5000"

interface UserInfo {
  id: string
  username: string
  publicKey: string
}

interface DecryptedMessage extends Message {
  content?: string
  decrypted?: boolean
  error?: string
}

export default function Home() {
  // Auth state
  const [currentUser, setCurrentUser] = useState<UserInfo | null>(null)
  const [isAuthLoading, setIsAuthLoading] = useState(false)
  const [authError, setAuthError] = useState<string | null>(null)

  // Users and messages
  const [users, setUsers] = useState<UserInfo[]>([])
  const [selectedUser, setSelectedUser] = useState<UserInfo | null>(null)
  const [messages, setMessages] = useState<DecryptedMessage[]>([])
  const [files, setFiles] = useState<{ id: string; filename: string; senderId: string; timestamp: number }[]>([])

  // UI state
  const [showLogs, setShowLogs] = useState(false)
  const [showKeyExchange, setShowKeyExchange] = useState(false)
  const [keyExchangeStep, setKeyExchangeStep] = useState(0)
  const [keyExchangeError, setKeyExchangeError] = useState<string | null>(null)
  const [isExchangingKeys, setIsExchangingKeys] = useState(false)

  const selectedUserRef = useRef<UserInfo | null>(null)

  // Pending key exchange data
  const [pendingKeyExchange, setPendingKeyExchange] = useState<{
    recipientId: string
    ephemeralPrivateKey: CryptoKey
    nonce: string
  } | null>(null)

  const [pendingConfirmations, setPendingConfirmations] = useState<Map<string, string>>(new Map())

  // Crypto hooks
  const {
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
    sessionKeys,
    confirmedSessions,
    setUserId,
  } = useCrypto()

  const [myPublicKey, setMyPublicKey] = useState<string | null>(null)

  useEffect(() => {
    if (currentUser) {
      setUserId(currentUser.id)
    }
  }, [currentUser, setUserId])

  useEffect(() => {
    selectedUserRef.current = selectedUser
  }, [selectedUser])

  useEffect(() => {
    // Clear previous chat data immediately when switching users
    setMessages([])
    setFiles([])
  }, [selectedUser?.id])

  useEffect(() => {
    const initCrypto = async () => {
      let publicKey = await loadIdentityKeys()
      if (!publicKey) {
        publicKey = await generateIdentityKeys()
      }
      setMyPublicKey(publicKey)
    }
    initCrypto()
  }, [generateIdentityKeys, loadIdentityKeys])

  const checkAndLoadSessionKey = useCallback(
    async (userId: string, recipientId: string) => {
      try {
        const response = await fetch(`${API_URL}/api/session-key?userId1=${userId}&userId2=${recipientId}`)
        if (response.ok) {
          const data = await response.json()
          if (data.exists && data.exportedKey) {
            await storeSessionKeyForUser(recipientId, data.exportedKey)
            return true
          }
        }
        return false
      } catch (error) {
        console.error("Failed to check session key:", error)
        return false
      }
    },
    [storeSessionKeyForUser],
  )

  // Handle incoming messages
  const handleNewMessage = useCallback(
    async (message: Message) => {
      const currentSelectedUser = selectedUserRef.current

      const isRelevant =
        (message.senderId === currentUser?.id && message.recipientId === currentSelectedUser?.id) ||
        (message.senderId === currentSelectedUser?.id && message.recipientId === currentUser?.id)

      if (!isRelevant) return

      try {
        const otherUserId = message.senderId === currentUser?.id ? message.recipientId : message.senderId
        const content = await decrypt(otherUserId, message.ciphertext, message.iv, message.authTag)

        if (selectedUserRef.current?.id !== currentSelectedUser?.id) return

        setMessages((prev) => {
          if (prev.find((m) => m.id === message.id)) return prev
          return [...prev, { ...message, content, decrypted: true }]
        })
      } catch (error) {
        if (selectedUserRef.current?.id !== currentSelectedUser?.id) return

        setMessages((prev) => {
          if (prev.find((m) => m.id === message.id)) return prev
          return [...prev, { ...message, decrypted: false, error: "Decryption failed" }]
        })
      }
    },
    [currentUser, decrypt],
  )

  // Handle incoming key exchange messages
  const handleKeyExchange = useCallback(
    async (data: KeyExchangeMessage) => {
      console.log("[v0] handleKeyExchange received:", {
        type: data.type,
        senderId: data.senderId,
        recipientId: data.recipientId,
        currentUserId: currentUser?.id,
      })

      if (!currentUser) {
        console.log("[v0] handleKeyExchange: No current user, returning")
        return
      }

      try {
        if (data.type === "init" && data.recipientId === currentUser.id) {
          console.log("[v0] Processing key exchange INIT as responder")

          if (!data.senderPublicKey) {
            console.log("[v0] Missing senderPublicKey in key exchange init")
            return
          }

          console.log("[v0] Calling respondToKeyExchange with senderPublicKey from message...")
          const response = await respondToKeyExchange(
            data.senderId,
            data.senderPublicKey, // Use public key from message
            data.ephemeralPublicKey,
            data.signature,
            data.timestamp,
            data.nonce,
          )
          console.log("[v0] respondToKeyExchange completed")

          console.log("[v0] Sending key exchange response to server...")
          await fetch(`${API_URL}/api/key-exchange`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              type: "response",
              senderId: currentUser.id,
              recipientId: data.senderId,
              senderPublicKey: myPublicKey, // Include responder's identity public key
              ephemeralPublicKey: response.responseEphemeralPublicKey,
              signature: response.responseSignature,
              timestamp: response.responseTimestamp,
              nonce: response.responseNonce,
            }),
          })
          console.log("[v0] Key exchange response sent")

          console.log("[v0] Creating key confirmation...")
          const confirmation = await createKeyConfirmation(data.senderId, data.nonce)
          console.log("[v0] Key confirmation created:", confirmation)

          console.log("[v0] Sending key confirmation to server...")
          await fetch(`${API_URL}/api/key-confirmation`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              type: "confirm",
              senderId: currentUser.id,
              recipientId: data.senderId,
              confirmationHash: confirmation.confirmationHash,
              confirmationNonce: confirmation.confirmationNonce,
              originalNonce: data.nonce,
              timestamp: confirmation.timestamp,
            }),
          })
          console.log("[v0] Key confirmation sent")

          // Store original nonce so we can verify initiator's confirmation later
          setPendingConfirmations((prev) => new Map(prev).set(data.senderId, data.nonce))
        } else if (data.type === "response" && data.recipientId === currentUser.id) {
          console.log("[v0] Processing key exchange RESPONSE as initiator")

          if (!pendingKeyExchange || pendingKeyExchange.recipientId !== data.senderId) {
            console.log("[v0] No pending key exchange or recipient mismatch")
            return
          }

          if (!data.senderPublicKey) {
            console.log("[v0] Missing senderPublicKey in key exchange response")
            return
          }

          setKeyExchangeStep(4)

          const sessionKey = await completeKeyExchange(
            data.senderId,
            data.senderPublicKey, // Use public key from message
            data.ephemeralPublicKey,
            data.signature,
            data.timestamp,
            data.nonce,
            pendingKeyExchange.nonce,
            pendingKeyExchange.ephemeralPrivateKey,
          )
          console.log("[v0] completeKeyExchange done")

          setKeyExchangeStep(5)
          console.log("[v0] Step 5 - Deriving session key...")

          const confirmation = await createKeyConfirmation(data.senderId, pendingKeyExchange.nonce)
          console.log("[v0] Key confirmation created by initiator")

          await fetch(`${API_URL}/api/key-confirmation`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              type: "confirm",
              senderId: currentUser.id,
              recipientId: data.senderId,
              confirmationHash: confirmation.confirmationHash,
              confirmationNonce: confirmation.confirmationNonce,
              originalNonce: pendingKeyExchange.nonce,
              timestamp: confirmation.timestamp,
            }),
          })
          console.log("[v0] Key confirmation sent by initiator")

          setKeyExchangeStep(6)

          // Store original nonce so we can verify responder's confirmation
          setPendingConfirmations((prev) => new Map(prev).set(data.senderId, pendingKeyExchange.nonce))
        }
      } catch (error) {
        console.error("[v0] Key exchange error:", error)
        setKeyExchangeError(error instanceof Error ? error.message : "Key exchange failed")
        setIsExchangingKeys(false)
      }
    },
    [currentUser, respondToKeyExchange, completeKeyExchange, createKeyConfirmation, pendingKeyExchange, myPublicKey],
  )

  const handleKeyConfirmation = useCallback(
    async (data: KeyConfirmationMessage) => {
      console.log("[v0] handleKeyConfirmation received:", {
        senderId: data.senderId,
        recipientId: data.recipientId,
        currentUserId: currentUser?.id,
      })

      if (!currentUser) {
        console.log("[v0] handleKeyConfirmation: No current user")
        return
      }
      if (data.recipientId !== currentUser.id) {
        console.log("[v0] handleKeyConfirmation: Not for this user")
        return
      }

      try {
        console.log("[v0] Verifying received key confirmation...")
        // Verify the confirmation
        const isValid = await verifyReceivedKeyConfirmation(
          data.senderId,
          data.confirmationHash,
          data.confirmationNonce,
          data.originalNonce,
        )
        console.log("[v0] Key confirmation verification result:", isValid)

        if (isValid) {
          console.log(`[v0] Key confirmation verified from ${data.senderId}`)
          markSessionConfirmed(data.senderId)

          // Remove from pending confirmations
          setPendingConfirmations((prev) => {
            const newMap = new Map(prev)
            newMap.delete(data.senderId)
            return newMap
          })

          // If this was the initiator waiting for confirmation, complete the exchange
          if (pendingKeyExchange && pendingKeyExchange.recipientId === data.senderId) {
            console.log("[v0] Completing key exchange as initiator")
            setKeyExchangeStep(7)
            setPendingKeyExchange(null)
            setIsExchangingKeys(false)

            // Store session key on server for persistence
            const { exportSessionKey } = await import("@/lib/crypto-client")
            const sessionKey = await loadSessionKey(data.senderId)
            if (sessionKey) {
              const exportedKey = await exportSessionKey(sessionKey)
              await fetch(`${API_URL}/api/session-key`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                  userId1: currentUser.id,
                  userId2: data.senderId,
                  exportedKey,
                }),
              })
              console.log("[v0] Session key stored on server")
            }

            setTimeout(() => {
              setShowKeyExchange(false)
            }, 2000)
          } else {
            console.log("[v0] Key confirmation received but not initiator or no pending exchange", {
              hasPendingExchange: !!pendingKeyExchange,
              pendingRecipientId: pendingKeyExchange?.recipientId,
              senderId: data.senderId,
            })
          }
        } else {
          console.error("[v0] Key confirmation verification failed - possible attack!")
          setKeyExchangeError("Key confirmation failed - the other party may have a different session key")
          setIsExchangingKeys(false)
        }
      } catch (error) {
        console.error("[v0] Key confirmation error:", error)
        setKeyExchangeError(error instanceof Error ? error.message : "Key confirmation failed")
        setIsExchangingKeys(false)
      }
    },
    [currentUser, pendingKeyExchange, verifyReceivedKeyConfirmation, markSessionConfirmed, loadSessionKey],
  )

  // Handle new file notification
  const handleNewFile = useCallback((data: { senderId: string; fileId: string; filename: string }) => {
    const currentSelectedUser = selectedUserRef.current
    if (data.senderId === currentSelectedUser?.id) {
      setFiles((prev) => [...prev, { ...data, id: data.fileId, timestamp: Date.now() }])
    }
  }, [])

  // Socket connection
  const { isConnected, sendEncryptedMessage, sendKeyExchange, sendKeyConfirmation, notifyFileShared } = useSocket({
    userId: currentUser?.id || null,
    onNewMessage: handleNewMessage,
    onKeyExchange: handleKeyExchange,
    onKeyConfirmation: handleKeyConfirmation,
    onNewFile: handleNewFile,
    onError: (error) => {
      console.error("Socket error:", error)
    },
  })

  const fetchUsers = async () => {
    try {
      const response = await fetch(`${API_URL}/api/users`)
      if (response.ok) {
        const data = await response.json()
        setUsers(data)
      }
    } catch (error) {
      console.error("Failed to fetch users:", error)
    }
  }

  const fetchMessages = useCallback(async () => {
    if (!currentUser || !selectedUser) return

    // Capture the selectedUser at the start of the fetch
    const targetUserId = selectedUser.id

    try {
      const response = await fetch(`${API_URL}/api/messages?userId=${currentUser.id}&recipientId=${targetUserId}`)
      if (response.ok) {
        const data: Message[] = await response.json()

        if (selectedUserRef.current?.id !== targetUserId) {
          return // User switched, discard these messages
        }

        const decryptedMessages: DecryptedMessage[] = await Promise.all(
          data.map(async (msg) => {
            try {
              const otherUserId = msg.senderId === currentUser.id ? targetUserId : msg.senderId
              const content = await decrypt(otherUserId, msg.ciphertext, msg.iv, msg.authTag)
              return { ...msg, content, decrypted: true }
            } catch {
              return { ...msg, decrypted: false, error: "Decryption failed" }
            }
          }),
        )

        if (selectedUserRef.current?.id === targetUserId) {
          setMessages(decryptedMessages)
        }
      }
    } catch (error) {
      console.error("Failed to fetch messages:", error)
    }
  }, [currentUser, selectedUser, decrypt])

  const fetchFiles = useCallback(async () => {
    if (!currentUser || !selectedUser) return

    // Capture the selectedUser at the start of the fetch
    const targetUserId = selectedUser.id

    try {
      const response = await fetch(`${API_URL}/api/files?userId=${currentUser.id}`)
      if (response.ok) {
        const data = await response.json()

        if (selectedUserRef.current?.id !== targetUserId) {
          return // User switched, discard these files
        }

        setFiles(
          data.filter(
            (f: { senderId: string; recipientId: string }) =>
              (f.senderId === currentUser.id && f.recipientId === targetUserId) ||
              (f.senderId === targetUserId && f.recipientId === currentUser.id),
          ),
        )
      }
    } catch (error) {
      console.error("Failed to fetch files:", error)
    }
  }, [currentUser, selectedUser])

  useEffect(() => {
    if (currentUser) {
      fetchUsers()
      const interval = setInterval(fetchUsers, 5000)
      return () => clearInterval(interval)
    }
  }, [currentUser])

  useEffect(() => {
    if (currentUser && selectedUser) {
      checkAndLoadSessionKey(currentUser.id, selectedUser.id).then(() => {
        fetchMessages()
        fetchFiles()
      })
    }
  }, [currentUser, selectedUser, checkAndLoadSessionKey, fetchMessages, fetchFiles])

  useEffect(() => {
    if (currentUser && selectedUser && sessionKeys.has(selectedUser.id)) {
      fetchMessages()
    }
  }, [sessionKeys, currentUser, selectedUser, fetchMessages])

  const handleRegister = async (username: string, password: string) => {
    setIsAuthLoading(true)
    setAuthError(null)

    try {
      const publicKey = await generateIdentityKeys()

      const response = await fetch(`${API_URL}/api/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password, publicKey }),
      })

      if (!response.ok) {
        const data = await response.json()
        throw new Error(data.error || "Registration failed")
      }

      const user = await response.json()
      setCurrentUser(user)
    } catch (error) {
      setAuthError(error instanceof Error ? error.message : "Registration failed")
    } finally {
      setIsAuthLoading(false)
    }
  }

  const handleLogin = async (username: string, password: string) => {
    setIsAuthLoading(true)
    setAuthError(null)

    try {
      const response = await fetch(`${API_URL}/api/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      })

      if (!response.ok) {
        const data = await response.json()
        throw new Error(data.error || "Login failed")
      }

      const user = await response.json()

      const existingKey = await loadIdentityKeys()
      if (!existingKey) {
        await generateIdentityKeys()
      }

      setCurrentUser(user)
    } catch (error) {
      setAuthError(error instanceof Error ? error.message : "Login failed")
    } finally {
      setIsAuthLoading(false)
    }
  }

  const handleLogout = () => {
    setCurrentUser(null)
    setSelectedUser(null)
    setMessages([])
    setFiles([])
  }

  const handleInitiateKeyExchange = async () => {
    if (!currentUser || !selectedUser || !myPublicKey) return

    setIsExchangingKeys(true)
    setShowKeyExchange(true)
    setKeyExchangeStep(0)
    setKeyExchangeError(null)

    try {
      setKeyExchangeStep(0)
      await new Promise((r) => setTimeout(r, 500))

      setKeyExchangeStep(1)
      const exchangeData = await initiateKeyExchange(selectedUser.id, selectedUser.publicKey)
      await new Promise((r) => setTimeout(r, 500))

      setKeyExchangeStep(2)

      setPendingKeyExchange({
        recipientId: selectedUser.id,
        ephemeralPrivateKey: exchangeData.ephemeralPrivateKey,
        nonce: exchangeData.nonce,
      })

      await fetch(`${API_URL}/api/key-exchange`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          type: "init",
          senderId: currentUser.id,
          recipientId: selectedUser.id,
          senderPublicKey: myPublicKey, // Include sender's identity public key
          ephemeralPublicKey: exchangeData.ephemeralPublicKey,
          signature: exchangeData.signature,
          timestamp: exchangeData.timestamp,
          nonce: exchangeData.nonce,
        }),
      })

      setKeyExchangeStep(3)
    } catch (error) {
      console.error("Key exchange error:", error)
      setKeyExchangeError(error instanceof Error ? error.message : "Key exchange failed")
      setIsExchangingKeys(false)
    }
  }

  const handleSendMessage = async (content: string) => {
    if (!currentUser || !selectedUser) return

    try {
      const { ciphertext, iv, authTag, nonce } = await encrypt(selectedUser.id, content)
      const sequenceNumber = messages.length

      const response = await fetch(`${API_URL}/api/messages`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          senderId: currentUser.id,
          recipientId: selectedUser.id,
          ciphertext,
          iv,
          authTag,
          nonce,
          sequenceNumber,
        }),
      })

      if (response.ok) {
        const message = await response.json()
        setMessages((prev) => {
          if (prev.find((m) => m.id === message.id)) return prev
          return [...prev, { ...message, content, decrypted: true }]
        })
      }
    } catch (error) {
      console.error("Failed to send message:", error)
    }
  }

  const handleSendFile = async (file: File) => {
    if (!currentUser || !selectedUser) return

    try {
      const fileData = await file.arrayBuffer()
      const { encryptedData, iv, authTag } = await encryptFileData(selectedUser.id, fileData)

      const response = await fetch(`${API_URL}/api/files`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          senderId: currentUser.id,
          recipientId: selectedUser.id,
          filename: file.name,
          encryptedData,
          iv,
          authTag,
          size: file.size,
        }),
      })

      if (response.ok) {
        const savedFile = await response.json()
        setFiles((prev) => {
          if (prev.find((f) => f.id === savedFile.id)) return prev
          return [...prev, savedFile]
        })
        notifyFileShared({
          senderId: currentUser.id,
          recipientId: selectedUser.id,
          fileId: savedFile.id,
          filename: file.name,
        })
      }
    } catch (error) {
      console.error("Failed to send file:", error)
    }
  }

  const handleDownloadFile = async (fileId: string) => {
    if (!currentUser || !selectedUser) return

    try {
      const response = await fetch(`${API_URL}/api/files/${fileId}?userId=${currentUser.id}`)
      if (!response.ok) throw new Error("Failed to fetch file")

      const file = await response.json()
      const decryptedData = await decryptFileData(selectedUser.id, file.encryptedData, file.iv, file.authTag)

      const blob = new Blob([decryptedData])
      const url = URL.createObjectURL(blob)
      const a = document.createElement("a")
      a.href = url
      a.download = file.filename
      a.click()
      URL.revokeObjectURL(url)
    } catch (error) {
      console.error("Failed to download file:", error)
    }
  }

  const hasSession = selectedUser ? sessionKeys.has(selectedUser.id) : false

  if (!currentUser) {
    return <AuthForm onRegister={handleRegister} onLogin={handleLogin} isLoading={isAuthLoading} error={authError} />
  }

  return (
    <div className="h-screen flex overflow-hidden">
      <ChatSidebar
        currentUser={currentUser}
        users={users}
        selectedUser={selectedUser}
        onSelectUser={setSelectedUser}
        onLogout={handleLogout}
        onOpenLogs={() => setShowLogs(true)}
        sessionKeys={sessionKeys}
      />

      {selectedUser ? (
        <ChatWindow
          currentUser={currentUser}
          selectedUser={selectedUser}
          messages={messages}
          hasSession={hasSession}
          isExchangingKeys={isExchangingKeys}
          onSendMessage={handleSendMessage}
          onInitiateKeyExchange={handleInitiateKeyExchange}
          onSendFile={handleSendFile}
          onDownloadFile={handleDownloadFile}
          files={files}
        />
      ) : (
        <div className="flex-1 flex items-center justify-center bg-background">
          <div className="text-center max-w-md">
            <div className="w-24 h-24 rounded-full bg-primary/10 flex items-center justify-center mx-auto mb-6 border border-primary/30 animate-pulse-glow">
              <Shield className="w-12 h-12 text-primary" />
            </div>
            <h2 className="text-2xl font-bold text-foreground mb-2 terminal-text">Welcome to CipherChat</h2>
            <p className="text-muted-foreground mb-6">
              Select a user from the sidebar to start a secure, end-to-end encrypted conversation.
            </p>
            <div className="grid grid-cols-2 gap-4 text-left">
              <div className="p-4 rounded-lg bg-card border border-border">
                <Key className="w-6 h-6 text-primary mb-2" />
                <h3 className="font-semibold text-foreground">ECDH Key Exchange</h3>
                <p className="text-xs text-muted-foreground">
                  Secure key agreement with digital signatures and key confirmation
                </p>
              </div>
              <div className="p-4 rounded-lg bg-card border border-border">
                <Lock className="w-6 h-6 text-primary mb-2" />
                <h3 className="font-semibold text-foreground">AES-256-GCM</h3>
                <p className="text-xs text-muted-foreground">Military-grade encryption for all messages and files</p>
              </div>
            </div>
          </div>
        </div>
      )}

      {showLogs && <SecurityLogs onClose={() => setShowLogs(false)} />}

      {showKeyExchange && selectedUser && (
        <KeyExchangeModal
          isOpen={showKeyExchange}
          currentStep={keyExchangeStep}
          error={keyExchangeError}
          recipientUsername={selectedUser.username}
          onClose={() => {
            setShowKeyExchange(false)
            setIsExchangingKeys(false)
          }}
        />
      )}
    </div>
  )
}
