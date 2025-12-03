"use client"
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Progress } from "@/components/ui/progress"
import { CheckCircle2, Loader2, Key, Shield, Lock, AlertCircle, ShieldCheck } from "lucide-react"

interface KeyExchangeModalProps {
  isOpen: boolean
  onClose: () => void
  currentStep: number
  error: string | null
  recipientUsername: string
}

const steps = [
  { label: "Generating ephemeral ECDH key pair", icon: Key },
  { label: "Signing public key with identity key (ECDSA)", icon: Shield },
  { label: "Sending key exchange initiation", icon: Lock },
  { label: "Waiting for recipient response", icon: Loader2 },
  { label: "Verifying recipient signature", icon: Shield },
  { label: "Deriving shared secret (ECDH)", icon: Key },
  { label: "Generating session key (HKDF)", icon: Lock },
  { label: "Key confirmation exchange", icon: ShieldCheck },
]

export function KeyExchangeModal({ isOpen, onClose, currentStep, error, recipientUsername }: KeyExchangeModalProps) {
  const progress = ((currentStep + 1) / steps.length) * 100
  const isComplete = currentStep >= steps.length - 1 && !error

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="bg-card border-border max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-foreground">
            <Key className="w-5 h-5 text-primary" />
            Secure Key Exchange
          </DialogTitle>
        </DialogHeader>

        <div className="space-y-6 py-4">
          <div className="text-center">
            <p className="text-sm text-muted-foreground">
              Establishing encrypted channel with{" "}
              <span className="text-foreground font-medium">{recipientUsername}</span>
            </p>
          </div>

          <Progress value={progress} className="h-2" />

          <div className="space-y-3">
            {steps.map((step, index) => {
              const Icon = step.icon
              const isActive = index === currentStep
              const isCompleted = index < currentStep
              const isFailed = error && index === currentStep

              return (
                <div
                  key={index}
                  className={`flex items-center gap-3 p-2 rounded-lg transition-all ${
                    isActive ? "bg-primary/10 border border-primary/30" : ""
                  } ${isFailed ? "bg-destructive/10 border border-destructive/30" : ""}`}
                >
                  <div
                    className={`w-8 h-8 rounded-full flex items-center justify-center ${
                      isCompleted
                        ? "bg-primary text-primary-foreground"
                        : isActive
                          ? "bg-primary/20 text-primary"
                          : isFailed
                            ? "bg-destructive/20 text-destructive"
                            : "bg-secondary text-muted-foreground"
                    }`}
                  >
                    {isCompleted ? (
                      <CheckCircle2 className="w-4 h-4" />
                    ) : isFailed ? (
                      <AlertCircle className="w-4 h-4" />
                    ) : isActive ? (
                      <Loader2 className="w-4 h-4 animate-spin" />
                    ) : (
                      <Icon className="w-4 h-4" />
                    )}
                  </div>
                  <span className={`text-sm ${isActive || isCompleted ? "text-foreground" : "text-muted-foreground"}`}>
                    {step.label}
                  </span>
                </div>
              )
            })}
          </div>

          {error && (
            <div className="p-3 rounded-lg bg-destructive/10 border border-destructive/30">
              <div className="flex items-center gap-2 text-destructive">
                <AlertCircle className="w-4 h-4" />
                <span className="text-sm font-medium">Key Exchange Failed</span>
              </div>
              <p className="text-xs text-destructive/80 mt-1">{error}</p>
            </div>
          )}

          {isComplete && (
            <div className="p-3 rounded-lg bg-primary/10 border border-primary/30">
              <div className="flex items-center gap-2 text-primary">
                <ShieldCheck className="w-4 h-4" />
                <span className="text-sm font-medium">Secure Channel Established</span>
              </div>
              <p className="text-xs text-primary/80 mt-1">
                Key confirmed. All messages will now be encrypted with AES-256-GCM
              </p>
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  )
}
