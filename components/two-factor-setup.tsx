"use client"

import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Shield, CheckCircle2, AlertCircle, Loader2, Copy, QrCode } from "lucide-react"
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog"

const API_URL = "http://localhost:5000"

interface TwoFactorSetupProps {
  userId: string
  username: string
  onComplete: () => void
  onCancel: () => void
}

export function TwoFactorSetup({ userId, username, onComplete, onCancel }: TwoFactorSetupProps) {
  const [password, setPassword] = useState("")
  const [step, setStep] = useState<"password" | "qr" | "verify">("password")
  const [secret, setSecret] = useState<string | null>(null)
  const [totpURI, setTotpURI] = useState<string | null>(null)
  const [verificationCode, setVerificationCode] = useState("")
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState(false)

  const handlePasswordSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsLoading(true)
    setError(null)

    try {
      const response = await fetch(`${API_URL}/api/auth/2fa/setup`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ userId, password }),
      })

      if (!response.ok) {
        const data = await response.json()
        throw new Error(data.error || "Failed to set up 2FA")
      }

      const data = await response.json()
      setSecret(data.secret)
      setTotpURI(data.totpURI)
      setStep("qr")
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to set up 2FA")
    } finally {
      setIsLoading(false)
    }
  }

  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsLoading(true)
    setError(null)

    try {
      const response = await fetch(`${API_URL}/api/auth/2fa/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ userId, totpCode: verificationCode }),
      })

      if (!response.ok) {
        const data = await response.json()
        throw new Error(data.error || "Invalid verification code")
      }

      setSuccess(true)
      setTimeout(() => {
        onComplete()
      }, 2000)
    } catch (err) {
      setError(err instanceof Error ? err.message : "Verification failed")
    } finally {
      setIsLoading(false)
    }
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
  }

  const generateQRCodeURL = (uri: string) => {
    // Use a public QR code API (or you can install qrcode library)
    return `https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=${encodeURIComponent(uri)}`
  }

  if (success) {
    return (
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <CheckCircle2 className="w-5 h-5 text-primary" />
            2FA Enabled Successfully
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-muted-foreground">Two-factor authentication has been enabled for your account.</p>
        </CardContent>
      </Card>
    )
  }

  return (
    <Card className="w-full max-w-md">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Shield className="w-5 h-5 text-primary" />
          Set Up Two-Factor Authentication
        </CardTitle>
        <CardDescription>Add an extra layer of security to your account</CardDescription>
      </CardHeader>
      <CardContent>
        {step === "password" && (
          <form onSubmit={handlePasswordSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="password">Enter your password to continue</Label>
              <Input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Your password"
                required
              />
            </div>

            {error && (
              <div className="flex items-center gap-2 text-destructive text-sm">
                <AlertCircle className="w-4 h-4" />
                {error}
              </div>
            )}

            <div className="flex gap-2">
              <Button type="submit" disabled={isLoading} className="flex-1">
                {isLoading ? (
                  <>
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                    Setting up...
                  </>
                ) : (
                  "Continue"
                )}
              </Button>
              <Button type="button" variant="outline" onClick={onCancel}>
                Cancel
              </Button>
            </div>
          </form>
        )}

        {step === "qr" && secret && totpURI && (
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>Scan this QR code with your authenticator app</Label>
              <div className="flex justify-center p-4 bg-secondary/30 rounded-lg border border-border">
                <img src={generateQRCodeURL(totpURI)} alt="QR Code" className="w-64 h-64" />
              </div>
              <p className="text-xs text-muted-foreground text-center">
                Use Google Authenticator, Microsoft Authenticator, or any TOTP-compatible app
              </p>
            </div>

            <div className="space-y-2">
              <Label>Or enter this secret manually:</Label>
              <div className="flex gap-2">
                <Input value={secret} readOnly className="font-mono text-sm" />
                <Button
                  type="button"
                  variant="outline"
                  size="icon"
                  onClick={() => copyToClipboard(secret)}
                  title="Copy secret"
                >
                  <Copy className="w-4 h-4" />
                </Button>
              </div>
            </div>

            <div className="p-3 rounded-lg bg-secondary/30 border border-border">
              <p className="text-xs text-muted-foreground">
                <AlertCircle className="w-3 h-3 inline mr-1" />
                After scanning, click "Continue" and enter the 6-digit code from your authenticator app to verify.
              </p>
            </div>

            <div className="flex gap-2">
              <Button onClick={() => setStep("verify")} className="flex-1">
                Continue
              </Button>
              <Button type="button" variant="outline" onClick={onCancel}>
                Cancel
              </Button>
            </div>
          </div>
        )}

        {step === "verify" && (
          <form onSubmit={handleVerify} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="verification-code">Enter 6-digit code from your authenticator app</Label>
              <Input
                id="verification-code"
                type="text"
                value={verificationCode}
                onChange={(e) => setVerificationCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                placeholder="000000"
                maxLength={6}
                className="text-center text-2xl font-mono tracking-widest"
                required
              />
            </div>

            {error && (
              <div className="flex items-center gap-2 text-destructive text-sm">
                <AlertCircle className="w-4 h-4" />
                {error}
              </div>
            )}

            <div className="flex gap-2">
              <Button type="submit" disabled={isLoading || verificationCode.length !== 6} className="flex-1">
                {isLoading ? (
                  <>
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                    Verifying...
                  </>
                ) : (
                  "Verify & Enable"
                )}
              </Button>
              <Button type="button" variant="outline" onClick={() => setStep("qr")}>
                Back
              </Button>
            </div>
          </form>
        )}
      </CardContent>
    </Card>
  )
}

