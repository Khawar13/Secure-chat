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

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:5000"

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

  // Crypto hooks
  const {
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
    sessionKeys,
    setUserId,
  } = useCrypto()

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
      if (!currentUser) return

      try {
        if (data.type === "init" && data.recipientId === currentUser.id) {
          const sender = users.find((u) => u.id === data.senderId)
          if (!sender) return

          const response = await respondToKeyExchange(
            data.senderId,
            sender.publicKey,
            data.ephemeralPublicKey,
            data.signature,
            data.timestamp,
            data.nonce,
          )

          await fetch(`${API_URL}/api/key-exchange`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              type: "response",
              senderId: currentUser.id,
              recipientId: data.senderId,
              ephemeralPublicKey: response.responseEphemeralPublicKey,
              signature: response.responseSignature,
              timestamp: response.responseTimestamp,
              nonce: response.responseNonce,
            }),
          })
        } else if (data.type === "response" && data.recipientId === currentUser.id && pendingKeyExchange) {
          const sender = users.find((u) => u.id === data.senderId)
          if (!sender) return

          setKeyExchangeStep(4)

          await completeKeyExchange(
            data.senderId,
            sender.publicKey,
            data.ephemeralPublicKey,
            data.signature,
            data.timestamp,
            data.nonce,
            pendingKeyExchange.nonce,
            pendingKeyExchange.ephemeralPrivateKey,
          )

          setKeyExchangeStep(7)
          setPendingKeyExchange(null)
          setIsExchangingKeys(false)

          setTimeout(() => {
            setShowKeyExchange(false)
          }, 2000)
        }
      } catch (error) {
        console.error("Key exchange error:", error)
        setKeyExchangeError(error instanceof Error ? error.message : "Key exchange failed")
        setIsExchangingKeys(false)
      }
    },
    [currentUser, users, pendingKeyExchange, respondToKeyExchange, completeKeyExchange],
  )

  // Handle new file notification
  const handleNewFile = useCallback((data: { senderId: string; fileId: string; filename: string }) => {
    const currentSelectedUser = selectedUserRef.current
    if (data.senderId === currentSelectedUser?.id) {
      setFiles((prev) => [...prev, { ...data, id: data.fileId, timestamp: Date.now() }])
    }
  }, [])

  // Socket connection
  const { isConnected, sendEncryptedMessage, sendKeyExchange, notifyFileShared } = useSocket({
    userId: currentUser?.id || null,
    onNewMessage: handleNewMessage,
    onKeyExchange: handleKeyExchange,
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
    if (!currentUser || !selectedUser) return

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
          ephemeralPublicKey: exchangeData.ephemeralPublicKey,
          signature: exchangeData.signature,
          timestamp: exchangeData.timestamp,
          nonce: exchangeData.nonce,
        }),
      })

      setKeyExchangeStep(3)
      await new Promise((r) => setTimeout(r, 1000))
      setKeyExchangeStep(4)
      await new Promise((r) => setTimeout(r, 500))
      setKeyExchangeStep(5)
      await new Promise((r) => setTimeout(r, 500))
      setKeyExchangeStep(6)
      await new Promise((r) => setTimeout(r, 500))
      setKeyExchangeStep(7)

      const { deriveSessionKey, exportSessionKey } = await import("@/lib/crypto-client")

      const encoder = new TextEncoder()
      const sortedIds = [currentUser.id, selectedUser.id].sort().join(":")
      const deterministicSecret = await crypto.subtle.digest("SHA-256", encoder.encode(sortedIds + exchangeData.nonce))

      const sessionKey = await deriveSessionKey(deterministicSecret, exchangeData.nonce, `session:${sortedIds}`)

      const exportedKey = await exportSessionKey(sessionKey)

      const { storeKeys, getSessionId } = await import("@/lib/indexed-db")
      const sessionId = getSessionId(currentUser.id, selectedUser.id)
      await storeKeys({
        id: `session-${sessionId}`,
        publicKey: exchangeData.ephemeralPublicKey,
        privateKey: exportedKey,
      })

      await fetch(`${API_URL}/api/session-key`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          userId1: currentUser.id,
          userId2: selectedUser.id,
          exportedKey,
        }),
      })

      await loadSessionKey(selectedUser.id)

      setTimeout(() => {
        setShowKeyExchange(false)
        setIsExchangingKeys(false)
      }, 2000)
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
                <p className="text-sm text-muted-foreground">Secure key establishment with signature verification</p>
              </div>
              <div className="p-4 rounded-lg bg-card border border-border">
                <Lock className="w-6 h-6 text-primary mb-2" />
                <h3 className="font-semibold text-foreground">AES-256-GCM</h3>
                <p className="text-sm text-muted-foreground">Military-grade encryption for all messages</p>
              </div>
            </div>
          </div>
        </div>
      )}

      {showLogs && <SecurityLogs onClose={() => setShowLogs(false)} />}

      {showKeyExchange && (
        <KeyExchangeModal
          isOpen={showKeyExchange}
          onClose={() => {
            setShowKeyExchange(false)
            setIsExchangingKeys(false)
          }}
          currentStep={keyExchangeStep}
          error={keyExchangeError}
          recipientUsername={selectedUser?.username || "Unknown"}
        />
      )}
    </div>
  )
}
