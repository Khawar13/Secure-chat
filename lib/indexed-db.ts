// IndexedDB wrapper for secure client-side key storage

const DB_NAME = "CipherChatKeys"
const DB_VERSION = 1
const STORE_NAME = "keys"

export interface StoredKeys {
  id: string // 'identity' or 'session-{sessionId}'
  publicKey: string // JWK format
  privateKey: string // Exported key or JWK format
}

export function getSessionId(userId1: string, userId2: string): string {
  // Sort to ensure both users generate the same session ID
  return [userId1, userId2].sort().join("-")
}

export async function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION)

    request.onerror = () => reject(request.error)
    request.onsuccess = () => resolve(request.result)

    request.onupgradeneeded = (event) => {
      const db = (event.target as IDBOpenDBRequest).result
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: "id" })
      }
    }
  })
}

export async function storeKeys(keys: StoredKeys): Promise<void> {
  const db = await openDatabase()
  return new Promise((resolve, reject) => {
    const transaction = db.transaction([STORE_NAME], "readwrite")
    const store = transaction.objectStore(STORE_NAME)
    const request = store.put(keys)

    request.onerror = () => reject(request.error)
    request.onsuccess = () => resolve()
  })
}

export async function getKeys(id: string): Promise<StoredKeys | null> {
  const db = await openDatabase()
  return new Promise((resolve, reject) => {
    const transaction = db.transaction([STORE_NAME], "readonly")
    const store = transaction.objectStore(STORE_NAME)
    const request = store.get(id)

    request.onerror = () => reject(request.error)
    request.onsuccess = () => resolve(request.result || null)
  })
}

export async function deleteKeys(id: string): Promise<void> {
  const db = await openDatabase()
  return new Promise((resolve, reject) => {
    const transaction = db.transaction([STORE_NAME], "readwrite")
    const store = transaction.objectStore(STORE_NAME)
    const request = store.delete(id)

    request.onerror = () => reject(request.error)
    request.onsuccess = () => resolve()
  })
}

export async function clearAllKeys(): Promise<void> {
  const db = await openDatabase()
  return new Promise((resolve, reject) => {
    const transaction = db.transaction([STORE_NAME], "readwrite")
    const store = transaction.objectStore(STORE_NAME)
    const request = store.clear()

    request.onerror = () => reject(request.error)
    request.onsuccess = () => resolve()
  })
}

export async function getAllSessionKeys(): Promise<StoredKeys[]> {
  const db = await openDatabase()
  return new Promise((resolve, reject) => {
    const transaction = db.transaction([STORE_NAME], "readonly")
    const store = transaction.objectStore(STORE_NAME)
    const request = store.getAll()

    request.onerror = () => reject(request.error)
    request.onsuccess = () => {
      const results = request.result.filter((k: StoredKeys) => k.id.startsWith("session-"))
      resolve(results)
    }
  })
}
