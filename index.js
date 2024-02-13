import http from 'http'
import { getToken, init } from './certificateManager.js'

// Create a simple HTTP server
const server = http.createServer((req, res) => {
  const reqUrl = new URL(req.url, `http://${req.headers.host}`)

  console.log('REQUEST!!!');
  console.log(req.url);
  console.log(req.headers);
  // Check if the request is for the ACME challenge
  const acmeChallengeRegex = /^\/.well-known\/acme-challenge\/(.+)$/
  const match = acmeChallengeRegex.exec(reqUrl.pathname)
  if (match) {
    // If the request URL matches the ACME challenge pattern,
    // call the handleAcmeChallenge function with the token
    return getToken(req, res)
  }

  // Fallback response for other routes
  res.writeHead(200, { 'Content-Type': 'text/plain' })
  res.end('Hello, World!\n')
})

init()

// Listen on port 3000
const PORT = 3000
server.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}/`)
})
