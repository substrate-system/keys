import { webcrypto } from '@substrate-system/one-webcrypto'
import { fromString } from 'uint8arrays'
import { publicKeyToDid, didToPublicKey } from './dist/crypto.js'

// Create an Ed25519 keypair
const keys = await webcrypto.subtle.generateKey(
    { name: 'Ed25519' },
    true,
    ['sign', 'verify']
)

console.log('\n=== Ed25519 Key Analysis ===\n')

// Export in different formats
const rawExport = await webcrypto.subtle.exportKey('raw', keys.publicKey)
const spkiExport = await webcrypto.subtle.exportKey('spki', keys.publicKey)

console.log('Raw format length:', new Uint8Array(rawExport).length, 'bytes')
console.log('Raw bytes:', new Uint8Array(rawExport))

console.log('\nSPKI format length:', new Uint8Array(spkiExport).length, 'bytes')
console.log('SPKI bytes:', new Uint8Array(spkiExport))

// Create DID
const did = await publicKeyToDid(keys.publicKey, 'ed25519')
console.log('\nDID:', did)

// Decode the DID to see what's in it
const didWithoutPrefix = did.substring('did:key:z'.length)
const decoded = fromString(didWithoutPrefix, 'base58btc')

console.log('\nDecoded DID (with multicodec prefix):')
console.log('Total length:', decoded.length, 'bytes')
console.log('Full bytes:', decoded)
console.log('First 2 bytes (multicodec):', decoded.slice(0, 2))
console.log('Remaining bytes:', decoded.slice(2))
console.log('Remaining length:', decoded.slice(2).length, 'bytes')

// Now use didToPublicKey to see what we get back
const recovered = didToPublicKey(did)
console.log('\nRecovered public key:')
console.log('Type:', recovered.type)
console.log('Length:', recovered.publicKey.length, 'bytes')
console.log('Bytes:', recovered.publicKey)

// Compare
console.log('\n=== Comparison ===')
console.log('Original raw export length:', new Uint8Array(rawExport).length)
console.log('Recovered key length:', recovered.publicKey.length)
console.log('Match:', arraysEqual(new Uint8Array(rawExport), recovered.publicKey))

function arraysEqual(a, b) {
    if (a.length !== b.length) return false
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) return false
    }
    return true
}
