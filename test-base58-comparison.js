import { webcrypto } from '@substrate-system/one-webcrypto'
import { fromString, toString } from 'uint8arrays'
import { publicKeyToDid, didToPublicKey } from './dist/crypto.js'

// Create an Ed25519 keypair
const keys = await webcrypto.subtle.generateKey(
    { name: 'Ed25519' },
    true,
    ['sign', 'verify']
)

console.log('\n=== Base58 Encoding Comparison ===\n')

// Export the raw public key
const rawExport = await webcrypto.subtle.exportKey('raw', keys.publicKey)
const rawBytes = new Uint8Array(rawExport)

// Create DID (this adds multicodec prefix)
const did = await publicKeyToDid(keys.publicKey, 'ed25519')
console.log('DID:', did)

// Extract the base58btc part (after "did:key:z")
const didBase58Part = did.substring('did:key:z'.length)
console.log('DID base58 part:', didBase58Part)

// Encode JUST the raw public key to base58btc (WITHOUT multicodec prefix)
const rawKeyBase58 = toString(rawBytes, 'base58btc')
console.log('Raw key base58:  ', rawKeyBase58)

console.log('\nDo they match?', didBase58Part === rawKeyBase58)

// Now let's see what the DID base58 part actually contains when decoded
const didDecoded = fromString(didBase58Part, 'base58btc')
console.log('\n=== What the DID contains ===')
console.log('Decoded DID total bytes:', didDecoded.length)
console.log('First 2 bytes (multicodec prefix):', didDecoded.slice(0, 2), '← This is 0xED01')
console.log('Remaining bytes:', didDecoded.slice(2).length, 'bytes')
console.log('\nThe DID contains: multicodec prefix + raw public key')
console.log('That\'s why base58(raw key) ≠ DID base58 part')
console.log('\nThe DID encodes:', toString(didDecoded, 'base58btc'))
console.log('But the raw key alone encodes:', toString(rawBytes, 'base58btc'))
