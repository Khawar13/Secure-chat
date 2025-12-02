// Custom server for Socket.io integration
// Run with: npx ts-node --esm server.ts

import { createServer } from "http"
import { parse } from "url"
import next from "next"
import { initializeSocketServer } from "./lib/socket-server"

const dev = process.env.NODE_ENV !== "production"
const hostname = "localhost"
const port = Number.parseInt(process.env.PORT || "3000", 10)

const app = next({ dev, hostname, port })
const handle = app.getRequestHandler()

app.prepare().then(() => {
  const server = createServer((req, res) => {
    const parsedUrl = parse(req.url!, true)
    handle(req, res, parsedUrl)
  })

  // Initialize Socket.io
  initializeSocketServer(server)

  server.listen(port, () => {
    console.log(`> Ready on http://${hostname}:${port}`)
    console.log(`> Socket.io server initialized`)
  })
})
