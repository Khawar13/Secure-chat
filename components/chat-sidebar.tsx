"use client"

import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Badge } from "@/components/ui/badge"
import { Shield, Users, Search, LogOut, Lock, Unlock, User, KeyRound, Activity } from "lucide-react"

interface UserInfo {
  id: string
  username: string
  publicKey: string
}

interface ChatSidebarProps {
  currentUser: UserInfo
  users: UserInfo[]
  selectedUser: UserInfo | null
  onSelectUser: (user: UserInfo) => void
  onLogout: () => void
  onOpenLogs: () => void
  sessionKeys: Map<string, CryptoKey>
}

export function ChatSidebar({
  currentUser,
  users,
  selectedUser,
  onSelectUser,
  onLogout,
  onOpenLogs,
  sessionKeys,
}: ChatSidebarProps) {
  const [searchQuery, setSearchQuery] = useState("")

  const filteredUsers = users.filter(
    (u) => u.id !== currentUser.id && u.username.toLowerCase().includes(searchQuery.toLowerCase()),
  )

  return (
    <div className="w-80 h-full flex flex-col bg-card border-r border-border">
      {/* Header */}
      <div className="p-4 border-b border-border">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <div className="w-10 h-10 rounded-full bg-primary/10 flex items-center justify-center border border-primary/30">
              <Shield className="w-5 h-5 text-primary" />
            </div>
            <div>
              <h1 className="font-bold text-foreground terminal-text">CipherChat</h1>
              <p className="text-xs text-muted-foreground">E2E Encrypted</p>
            </div>
          </div>
        </div>

        {/* Current user info */}
        <div className="p-3 rounded-lg bg-secondary/30 border border-border">
          <div className="flex items-center gap-2 mb-2">
            <User className="w-4 h-4 text-primary" />
            <span className="font-medium text-foreground">{currentUser.username}</span>
          </div>
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <KeyRound className="w-3 h-3" />
            <span className="font-mono truncate">{currentUser.id.substring(0, 8)}...</span>
          </div>
        </div>
      </div>

      {/* Search */}
      <div className="p-4 border-b border-border">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input
            placeholder="Search users..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-10 bg-input border-border"
          />
        </div>
      </div>

      {/* Users list */}
      <ScrollArea className="flex-1">
        <div className="p-2">
          <div className="flex items-center gap-2 px-3 py-2 text-xs text-muted-foreground uppercase tracking-wider">
            <Users className="w-3 h-3" />
            Users ({filteredUsers.length})
          </div>

          {filteredUsers.map((user) => {
            const hasSession = sessionKeys.has(user.id)
            const isSelected = selectedUser?.id === user.id

            return (
              <button
                key={user.id}
                onClick={() => onSelectUser(user)}
                className={`w-full p-3 rounded-lg flex items-center gap-3 transition-all mb-1 ${
                  isSelected
                    ? "bg-primary/20 border border-primary/30"
                    : "hover:bg-secondary/50 border border-transparent"
                }`}
              >
                <div className="relative">
                  <div
                    className={`w-10 h-10 rounded-full flex items-center justify-center ${
                      hasSession ? "bg-primary/20" : "bg-secondary"
                    }`}
                  >
                    <User className={`w-5 h-5 ${hasSession ? "text-primary" : "text-muted-foreground"}`} />
                  </div>
                  {hasSession && (
                    <div className="absolute -bottom-1 -right-1 w-4 h-4 rounded-full bg-primary flex items-center justify-center">
                      <Lock className="w-2 h-2 text-primary-foreground" />
                    </div>
                  )}
                </div>

                <div className="flex-1 text-left">
                  <div className="font-medium text-foreground">{user.username}</div>
                  <div className="text-xs text-muted-foreground font-mono">{user.id.substring(0, 8)}...</div>
                </div>

                <Badge
                  variant={hasSession ? "default" : "secondary"}
                  className={`text-xs ${
                    hasSession ? "bg-primary/20 text-primary border-primary/30" : "bg-secondary text-muted-foreground"
                  }`}
                >
                  {hasSession ? (
                    <>
                      <Lock className="w-2 h-2 mr-1" />
                      Secure
                    </>
                  ) : (
                    <>
                      <Unlock className="w-2 h-2 mr-1" />
                      Setup
                    </>
                  )}
                </Badge>
              </button>
            )
          })}

          {filteredUsers.length === 0 && (
            <div className="text-center py-8 text-muted-foreground">
              <Users className="w-8 h-8 mx-auto mb-2 opacity-50" />
              <p className="text-sm">No users found</p>
            </div>
          )}
        </div>
      </ScrollArea>

      {/* Footer actions */}
      <div className="p-4 border-t border-border space-y-2">
        <Button
          variant="outline"
          className="w-full justify-start border-border hover:bg-secondary/50 hover:text-foreground bg-transparent"
          onClick={onOpenLogs}
        >
          <Activity className="w-4 h-4 mr-2" />
          Security Logs
        </Button>
        <Button
          variant="outline"
          className="w-full justify-start border-destructive/50 text-destructive hover:bg-destructive/10 bg-transparent"
          onClick={onLogout}
        >
          <LogOut className="w-4 h-4 mr-2" />
          Logout
        </Button>
      </div>
    </div>
  )
}
