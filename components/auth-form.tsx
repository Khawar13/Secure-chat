"use client"

import type React from "react"

import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Shield, Key, Lock, Loader2, CheckCircle2, AlertCircle } from "lucide-react"

interface AuthFormProps {
  onRegister: (username: string, password: string) => Promise<void>
  onLogin: (username: string, password: string) => Promise<void>
  isLoading: boolean
  error: string | null
}

export function AuthForm({ onRegister, onLogin, isLoading, error }: AuthFormProps) {
  const [username, setUsername] = useState("")
  const [password, setPassword] = useState("")
  const [confirmPassword, setConfirmPassword] = useState("")
  const [activeTab, setActiveTab] = useState("login")

  const handleSubmit = async (e: React.FormEvent, type: "login" | "register") => {
    e.preventDefault()

    if (type === "register" && password !== confirmPassword) {
      return
    }

    if (type === "register") {
      await onRegister(username, password)
    } else {
      await onLogin(username, password)
    }
  }

  const passwordsMatch = password === confirmPassword || confirmPassword === ""

  return (
    <div className="min-h-screen flex items-center justify-center p-4 relative overflow-hidden">
      {/* Animated background */}
      <div className="absolute inset-0 bg-background">
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,_var(--tw-gradient-stops))] from-primary/10 via-background to-background" />
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-primary/5 rounded-full blur-3xl animate-pulse" />
        <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-accent/5 rounded-full blur-3xl animate-pulse delay-1000" />
      </div>

      <Card className="w-full max-w-md glass border-primary/20 relative z-10">
        <CardHeader className="text-center space-y-4">
          <div className="mx-auto w-16 h-16 rounded-full bg-primary/10 flex items-center justify-center border border-primary/30 animate-pulse-glow">
            <Shield className="w-8 h-8 text-primary" />
          </div>
          <div>
            <CardTitle className="text-2xl font-bold terminal-text text-primary">CipherChat</CardTitle>
            <CardDescription className="text-muted-foreground mt-2">
              Secure End-to-End Encrypted Messaging
            </CardDescription>
          </div>
        </CardHeader>

        <CardContent>
          <Tabs value={activeTab} onValueChange={setActiveTab}>
            <TabsList className="grid w-full grid-cols-2 bg-secondary/50">
              <TabsTrigger
                value="login"
                className="data-[state=active]:bg-primary data-[state=active]:text-primary-foreground"
              >
                Login
              </TabsTrigger>
              <TabsTrigger
                value="register"
                className="data-[state=active]:bg-primary data-[state=active]:text-primary-foreground"
              >
                Register
              </TabsTrigger>
            </TabsList>

            <TabsContent value="login">
              <form onSubmit={(e) => handleSubmit(e, "login")} className="space-y-4 mt-4">
                <div className="space-y-2">
                  <Label htmlFor="login-username" className="text-foreground">
                    Username
                  </Label>
                  <div className="relative">
                    <Input
                      id="login-username"
                      type="text"
                      value={username}
                      onChange={(e) => setUsername(e.target.value)}
                      placeholder="Enter username"
                      className="bg-input border-border focus:border-primary pl-10"
                      required
                    />
                    <Key className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                  </div>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="login-password" className="text-foreground">
                    Password
                  </Label>
                  <div className="relative">
                    <Input
                      id="login-password"
                      type="password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder="Enter password"
                      className="bg-input border-border focus:border-primary pl-10"
                      required
                    />
                    <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                  </div>
                </div>

                {error && (
                  <div className="flex items-center gap-2 text-destructive text-sm">
                    <AlertCircle className="w-4 h-4" />
                    {error}
                  </div>
                )}

                <Button
                  type="submit"
                  className="w-full bg-primary hover:bg-primary/90 text-primary-foreground"
                  disabled={isLoading}
                >
                  {isLoading ? (
                    <>
                      <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                      Authenticating...
                    </>
                  ) : (
                    <>
                      <Shield className="w-4 h-4 mr-2" />
                      Secure Login
                    </>
                  )}
                </Button>
              </form>
            </TabsContent>

            <TabsContent value="register">
              <form onSubmit={(e) => handleSubmit(e, "register")} className="space-y-4 mt-4">
                <div className="space-y-2">
                  <Label htmlFor="register-username" className="text-foreground">
                    Username
                  </Label>
                  <div className="relative">
                    <Input
                      id="register-username"
                      type="text"
                      value={username}
                      onChange={(e) => setUsername(e.target.value)}
                      placeholder="Choose username"
                      className="bg-input border-border focus:border-primary pl-10"
                      required
                    />
                    <Key className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                  </div>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="register-password" className="text-foreground">
                    Password
                  </Label>
                  <div className="relative">
                    <Input
                      id="register-password"
                      type="password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder="Create password"
                      className="bg-input border-border focus:border-primary pl-10"
                      required
                      minLength={8}
                    />
                    <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                  </div>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="confirm-password" className="text-foreground">
                    Confirm Password
                  </Label>
                  <div className="relative">
                    <Input
                      id="confirm-password"
                      type="password"
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                      placeholder="Confirm password"
                      className={`bg-input border-border focus:border-primary pl-10 ${
                        !passwordsMatch ? "border-destructive" : ""
                      }`}
                      required
                    />
                    {confirmPassword &&
                      (passwordsMatch ? (
                        <CheckCircle2 className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-primary" />
                      ) : (
                        <AlertCircle className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-destructive" />
                      ))}
                    <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                  </div>
                  {!passwordsMatch && <p className="text-xs text-destructive">Passwords do not match</p>}
                </div>

                {error && (
                  <div className="flex items-center gap-2 text-destructive text-sm">
                    <AlertCircle className="w-4 h-4" />
                    {error}
                  </div>
                )}

                <div className="p-3 rounded-lg bg-secondary/30 border border-border">
                  <p className="text-xs text-muted-foreground">
                    <Shield className="w-3 h-3 inline mr-1" />
                    Your password will be hashed with bcrypt. A unique ECDSA P-256 key pair will be generated for your
                    identity.
                  </p>
                </div>

                <Button
                  type="submit"
                  className="w-full bg-primary hover:bg-primary/90 text-primary-foreground"
                  disabled={isLoading || !passwordsMatch}
                >
                  {isLoading ? (
                    <>
                      <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                      Generating Keys...
                    </>
                  ) : (
                    <>
                      <Key className="w-4 h-4 mr-2" />
                      Create Secure Account
                    </>
                  )}
                </Button>
              </form>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  )
}
