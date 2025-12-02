"use client"

import type React from "react"

import { useState, useRef, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Badge } from "@/components/ui/badge"
import {
  Send,
  Lock,
  Shield,
  Key,
  Loader2,
  CheckCircle2,
  AlertCircle,
  Paperclip,
  Download,
  FileIcon,
} from "lucide-react"

interface Message {
  id: string
  senderId: string
  recipientId: string
  content?: string // Decrypted content
  ciphertext: string
  iv: string
  authTag: string
  timestamp: number
  nonce: string
  sequenceNumber: number
  decrypted?: boolean
  error?: string
}

interface UserInfo {
  id: string
  username: string
  publicKey: string
}

interface FileInfo {
  id: string
  filename: string
  senderId: string
  recipientId?: string
  timestamp: number
}

interface ChatWindowProps {
  currentUser: UserInfo
  selectedUser: UserInfo
  messages: Message[]
  hasSession: boolean
  isExchangingKeys: boolean
  onSendMessage: (content: string) => Promise<void>
  onInitiateKeyExchange: () => Promise<void>
  onSendFile: (file: File) => Promise<void>
  onDownloadFile: (fileId: string) => Promise<void>
  files: FileInfo[]
}

export function ChatWindow({
  currentUser,
  selectedUser,
  messages,
  hasSession,
  isExchangingKeys,
  onSendMessage,
  onInitiateKeyExchange,
  onSendFile,
  onDownloadFile,
  files,
}: ChatWindowProps) {
  const [messageInput, setMessageInput] = useState("")
  const [isSending, setIsSending] = useState(false)
  const scrollRef = useRef<HTMLDivElement>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight
    }
  }, [messages])

  const handleSend = async () => {
    if (!messageInput.trim() || !hasSession || isSending) return

    setIsSending(true)
    try {
      await onSendMessage(messageInput)
      setMessageInput("")
    } finally {
      setIsSending(false)
    }
  }

  const handleFileSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (file && hasSession) {
      await onSendFile(file)
    }
    if (fileInputRef.current) {
      fileInputRef.current.value = ""
    }
  }

  const formatTime = (timestamp: number) => {
    return new Date(timestamp).toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
    })
  }

  return (
    <div className="flex-1 flex flex-col h-full bg-background">
      {/* Chat header */}
      <div className="p-4 border-b border-border flex items-center justify-between bg-card">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-full bg-primary/10 flex items-center justify-center border border-primary/30">
            <Shield className="w-5 h-5 text-primary" />
          </div>
          <div>
            <h2 className="font-semibold text-foreground">{selectedUser.username}</h2>
            <div className="flex items-center gap-2">
              <span className="text-xs text-muted-foreground font-mono">{selectedUser.id.substring(0, 12)}...</span>
              {hasSession ? (
                <Badge className="bg-primary/20 text-primary border-primary/30 text-xs">
                  <Lock className="w-2 h-2 mr-1" />
                  E2E Encrypted
                </Badge>
              ) : (
                <Badge variant="secondary" className="text-xs">
                  <Key className="w-2 h-2 mr-1" />
                  Key Exchange Required
                </Badge>
              )}
            </div>
          </div>
        </div>

        {!hasSession && (
          <Button
            onClick={onInitiateKeyExchange}
            disabled={isExchangingKeys}
            className="bg-primary hover:bg-primary/90"
          >
            {isExchangingKeys ? (
              <>
                <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                Exchanging Keys...
              </>
            ) : (
              <>
                <Key className="w-4 h-4 mr-2" />
                Establish Secure Channel
              </>
            )}
          </Button>
        )}
      </div>

      {/* Messages area */}
      <ScrollArea className="flex-1 p-4" ref={scrollRef}>
        {!hasSession ? (
          <div className="h-full flex items-center justify-center">
            <div className="text-center max-w-md">
              <div className="w-20 h-20 rounded-full bg-secondary/50 flex items-center justify-center mx-auto mb-4">
                <Key className="w-10 h-10 text-muted-foreground" />
              </div>
              <h3 className="text-lg font-semibold text-foreground mb-2">Secure Channel Required</h3>
              <p className="text-muted-foreground text-sm mb-4">
                Before you can exchange messages with {selectedUser.username}, you need to establish a secure encrypted
                channel using the ECDH key exchange protocol.
              </p>
              <div className="p-4 rounded-lg bg-secondary/30 border border-border text-left">
                <h4 className="font-medium text-foreground mb-2 flex items-center gap-2">
                  <Shield className="w-4 h-4 text-primary" />
                  Key Exchange Protocol
                </h4>
                <ol className="text-xs text-muted-foreground space-y-1 list-decimal list-inside">
                  <li>Generate ephemeral ECDH P-256 key pair</li>
                  <li>Sign public key with your identity key (ECDSA)</li>
                  <li>Exchange signed public keys</li>
                  <li>Verify signatures (prevents MITM)</li>
                  <li>Derive shared secret via ECDH</li>
                  <li>Generate session key using HKDF</li>
                  <li>Key confirmation message exchange</li>
                </ol>
              </div>
            </div>
          </div>
        ) : (
          <div className="space-y-4">
            {/* Encryption indicator */}
            <div className="flex justify-center">
              <Badge className="bg-primary/10 text-primary border-primary/20">
                <Lock className="w-3 h-3 mr-1" />
                Messages are end-to-end encrypted with AES-256-GCM
              </Badge>
            </div>

            {/* Messages */}
            {messages.map((message, index) => {
              const isMine = message.senderId === currentUser.id
              return (
                <div key={`${message.id}-${index}`} className={`flex ${isMine ? "justify-end" : "justify-start"}`}>
                  <div
                    className={`max-w-[70%] rounded-lg p-3 ${
                      isMine ? "bg-primary text-primary-foreground" : "bg-secondary text-secondary-foreground"
                    }`}
                  >
                    {message.error ? (
                      <div className="flex items-center gap-2 text-destructive">
                        <AlertCircle className="w-4 h-4" />
                        <span className="text-sm">Decryption failed</span>
                      </div>
                    ) : message.decrypted ? (
                      <p className="text-sm break-words">{message.content}</p>
                    ) : (
                      <div className="flex items-center gap-2 text-muted-foreground">
                        <Loader2 className="w-4 h-4 animate-spin" />
                        <span className="text-sm">Decrypting...</span>
                      </div>
                    )}
                    <div
                      className={`flex items-center gap-2 mt-1 text-xs ${
                        isMine ? "text-primary-foreground/70" : "text-muted-foreground"
                      }`}
                    >
                      <Lock className="w-3 h-3" />
                      <span>{formatTime(message.timestamp)}</span>
                      {message.decrypted && <CheckCircle2 className="w-3 h-3" />}
                    </div>
                  </div>
                </div>
              )
            })}

            {/* Shared files */}
            {files.length > 0 && (
              <div className="pt-4 border-t border-border">
                <h4 className="text-sm font-medium text-foreground mb-2 flex items-center gap-2">
                  <FileIcon className="w-4 h-4" />
                  Shared Files
                </h4>
                <div className="space-y-2">
                  {files.map((file, index) => {
                    const isMine = file.senderId === currentUser.id
                    return (
                      <div
                        key={`${file.id}-${index}`}
                        className={`flex items-center justify-between p-2 rounded-lg border ${
                          isMine ? "bg-primary/10 border-primary/30" : "bg-secondary/30 border-border"
                        }`}
                      >
                        <div className="flex items-center gap-2">
                          <FileIcon className={`w-4 h-4 ${isMine ? "text-primary" : "text-muted-foreground"}`} />
                          <div className="flex flex-col">
                            <span className="text-sm text-foreground">{file.filename}</span>
                            <span className="text-xs text-muted-foreground">
                              {isMine ? "Sent by you" : `Received from ${selectedUser.username}`}
                            </span>
                          </div>
                        </div>
                        <Button size="sm" variant="ghost" onClick={() => onDownloadFile(file.id)} className="h-8">
                          <Download className="w-4 h-4" />
                        </Button>
                      </div>
                    )
                  })}
                </div>
              </div>
            )}
          </div>
        )}
      </ScrollArea>

      {/* Message input */}
      <div className="p-4 border-t border-border bg-card">
        <div className="flex items-center gap-2">
          <input type="file" ref={fileInputRef} onChange={handleFileSelect} className="hidden" />
          <Button
            variant="outline"
            size="icon"
            onClick={() => fileInputRef.current?.click()}
            disabled={!hasSession}
            className="border-border"
          >
            <Paperclip className="w-4 h-4" />
          </Button>
          <Input
            value={messageInput}
            onChange={(e) => setMessageInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleSend()}
            placeholder={hasSession ? "Type an encrypted message..." : "Establish secure channel first..."}
            disabled={!hasSession}
            className="flex-1 bg-input border-border"
          />
          <Button
            onClick={handleSend}
            disabled={!hasSession || !messageInput.trim() || isSending}
            className="bg-primary hover:bg-primary/90"
          >
            {isSending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
          </Button>
        </div>
        {hasSession && (
          <p className="text-xs text-muted-foreground mt-2 flex items-center gap-1">
            <Lock className="w-3 h-3" />
            Messages encrypted with AES-256-GCM using your session key
          </p>
        )}
      </div>
    </div>
  )
}
