// test/playwright-test-runner.js
import { chromium } from 'playwright'
import { createServer } from 'http-server'
import path from 'path'
import { fileURLToPath } from 'url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const PORT = 8123

// Serve static test files
const server = createServer({ root: path.join(__dirname, '..') })
server.listen(PORT, () => {
  console.log(`🚀 Serving at http://localhost:${PORT}/test-runner.html`)
})

const browser = await chromium.launch()
const page = await browser.newPage()

page.on('console', msg => {
  console[msg.type()](`[browser] ${msg.text()}`)
})

try {
  await page.goto(`http://localhost:${PORT}/test/test-runner.html`)
  await page.waitForFunction(() => window.testsFinished === true, null, { timeout: 10000 })
  console.log('✅ Tests passed in a browser.')
} catch (err) {
  console.error('❌ Tests failed or timed out:', err)
  process.exit(1)
} finally {
  await browser.close()
  server.close()
}
