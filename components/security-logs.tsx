"use client"

import type React from "react"

import { useEffect, useState } from "react"
import { Button } from "@/components/ui/button"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Badge } from "@/components/ui/badge"
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet"
import {
  Activity,
  Shield,
  Key,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  RefreshCw,
  MessageSquare,
  Upload,
  Lock,
} from "lucide-react"
import type { SecurityLog } from "@/lib/types"

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:5000"

interface SecurityLogsProps {
  onClose: () => void
}

const logTypeConfig: Record<string, { icon: React.ReactNode; color: string }> = {
  USER_REGISTERED: { icon: <CheckCircle2 className="w-4 h-4" />, color: "text-primary" },
  LOGIN_SUCCESS: { icon: <CheckCircle2 className="w-4 h-4" />, color: "text-primary" },
  LOGIN_FAILED: { icon: <XCircle className="w-4 h-4" />, color: "text-destructive" },
  REGISTRATION_FAILED: { icon: <XCircle className="w-4 h-4" />, color: "text-destructive" },
  KEY_EXCHANGE: { icon: <Lock className="w-4 h-4" />, color: "text-primary" },
  SESSION_KEY_STORED: { icon: <Key className="w-4 h-4" />, color: "text-primary" },
  MESSAGE_SENT: { icon: <MessageSquare className="w-4 h-4" />, color: "text-primary" },
  FILE_SHARED: { icon: <Upload className="w-4 h-4" />, color: "text-primary" },
  REPLAY_ATTACK_DETECTED: { icon: <AlertTriangle className="w-4 h-4" />, color: "text-destructive" },
  UNAUTHORIZED_FILE_ACCESS: { icon: <Shield className="w-4 h-4" />, color: "text-destructive" },
}

export function SecurityLogs({ onClose }: SecurityLogsProps) {
  const [logs, setLogs] = useState<SecurityLog[]>([])
  const [isLoading, setIsLoading] = useState(false)

  const fetchLogs = async () => {
    setIsLoading(true)
    try {
      const response = await fetch(`${API_URL}/api/logs?limit=100`)
      if (response.ok) {
        const data = await response.json()
        setLogs(data)
      }
    } catch (error) {
      console.error("Failed to fetch logs:", error)
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    fetchLogs()
  }, [])

  const formatTime = (timestamp: number) => {
    return new Date(timestamp).toLocaleString()
  }

  const getLogConfig = (event: string) => {
    return logTypeConfig[event] || { icon: <Activity className="w-4 h-4" />, color: "text-muted-foreground" }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "error":
        return "bg-destructive/20 text-destructive"
      case "warning":
        return "bg-yellow-500/20 text-yellow-500"
      default:
        return "bg-primary/20 text-primary"
    }
  }

  return (
    <Sheet open={true} onOpenChange={onClose}>
      <SheetContent side="right" className="w-[500px] sm:max-w-[500px] bg-card border-border">
        <SheetHeader>
          <SheetTitle className="flex items-center gap-2 text-foreground">
            <Activity className="w-5 h-5 text-primary" />
            Security Audit Logs
          </SheetTitle>
        </SheetHeader>

        <div className="mt-4 space-y-4">
          <div className="flex items-center justify-between">
            <p className="text-sm text-muted-foreground">Showing last {logs.length} security events</p>
            <Button
              variant="outline"
              size="sm"
              onClick={fetchLogs}
              disabled={isLoading}
              className="border-border bg-transparent"
            >
              <RefreshCw className={`w-4 h-4 mr-2 ${isLoading ? "animate-spin" : ""}`} />
              Refresh
            </Button>
          </div>

          {/* Stats */}
          <div className="grid grid-cols-3 gap-2">
            <div className="p-3 rounded-lg bg-secondary/30 border border-border">
              <div className="text-2xl font-bold text-primary">{logs.filter((l) => l.severity === "info").length}</div>
              <div className="text-xs text-muted-foreground">Successful</div>
            </div>
            <div className="p-3 rounded-lg bg-secondary/30 border border-border">
              <div className="text-2xl font-bold text-destructive">
                {logs.filter((l) => l.severity === "error").length}
              </div>
              <div className="text-xs text-muted-foreground">Errors</div>
            </div>
            <div className="p-3 rounded-lg bg-secondary/30 border border-border">
              <div className="text-2xl font-bold text-yellow-500">
                {logs.filter((l) => l.event === "REPLAY_ATTACK_DETECTED").length}
              </div>
              <div className="text-xs text-muted-foreground">Replay Attacks</div>
            </div>
          </div>

          <ScrollArea className="h-[calc(100vh-280px)]">
            <div className="space-y-2">
              {logs.map((log) => {
                const config = getLogConfig(log.event ?? "UNKNOWN_EVENT")

                return (
                  <div
                    key={log.id}
                    className="p-3 rounded-lg bg-secondary/20 border border-border hover:bg-secondary/30 transition-colors"
                  >
                    <div className="flex items-start justify-between gap-2 mb-2">
                      <div className="flex items-center gap-2">
                        <span className={config.color}>{config.icon}</span>
                        <Badge className={`text-xs ${getSeverityColor(log.severity ?? "info")}`}>
                          {(log.event ?? "UNKNOWN_EVENT").replace(/_/g, " ")}
                        </Badge>

                      </div>
                      <span className="text-xs text-muted-foreground whitespace-nowrap">
                        {formatTime(log.timestamp)}
                      </span>
                    </div>
                    <p className="text-sm text-foreground/80">{log.details}</p>
                    {log.userId && (
                      <p className="text-xs text-muted-foreground mt-1 font-mono">
                        User: {log.userId.substring(0, 8)}...
                      </p>
                    )}
                  </div>
                )
              })}

              {logs.length === 0 && !isLoading && (
                <div className="text-center py-8 text-muted-foreground">
                  <Activity className="w-12 h-12 mx-auto mb-2 opacity-50" />
                  <p>No security logs yet</p>
                </div>
              )}
            </div>
          </ScrollArea>
        </div>
      </SheetContent>
    </Sheet>
  )
}
