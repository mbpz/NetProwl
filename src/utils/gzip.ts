/** Compress JSON data to base64 gzip string */
export async function compressSnapshot<T>(data: T): Promise<string> {
  try {
    const pako = require('pako')
    const buffer = Buffer.from(JSON.stringify(data))
    const compressed = pako.deflate(buffer)
    return Buffer.from(compressed).toString('base64')
  } catch {
    // Fallback: no compression
    return JSON.stringify(data)
  }
}

/** Decompress base64 gzip string back to JSON */
export async function decompressSnapshot<T>(base64: string): Promise<T> {
  try {
    const pako = require('pako')
    const buffer = Buffer.from(base64, 'base64')
    const decompressed = pako.inflate(buffer, { to: 'string' })
    return JSON.parse(decompressed)
  } catch {
    // Fallback: plain JSON
    return JSON.parse(base64)
  }
}