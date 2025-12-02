// API Configuration - Points to Express backend
export const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:5000"

export async function apiRequest(endpoint: string, options?: RequestInit) {
  const url = `${API_BASE_URL}${endpoint}`
  const response = await fetch(url, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...options?.headers,
    },
  })
  return response
}
