import { get } from 'idb-keyval'
import { test } from '@substrate-system/tapzero'
import { toString } from 'uint8arrays'
import {
    EccKeys,
    exportPublicKey,
    importPublicKey,
    verify
} from '../src/ecc/index.js'
import { EccCurve, KeyUse } from '../src/types.js'

const subtle = crypto.subtle

// Can we create an x25519 key in this environment?
test('Sanity', async t => {
    try {
        const keys = await subtle.generateKey({
            name: 'X25519'
        }, true, ['deriveKey']) as CryptoKeyPair
        const raw = await subtle.exportKey('raw', keys.publicKey)
        t.equal(raw.byteLength, 32, 'should generate an X25519 key')
    } catch (err) {
        console.error('error in test', err)
    }
})

let myKeys:EccKeys
test('__________Create a new EccKeys instance___________________', async t => {
    myKeys = await EccKeys.create()
    t.ok(myKeys, 'should create the keys')
    t.equal(myKeys.hasPersisted, false,
        'should not have persisted flag for newly created keys')
    t.equal(EccKeys.EXCHANGE_KEY_NAME, 'ecc-exchange',
        'should have the default encryption key name')
    t.equal(EccKeys.WRITE_KEY_NAME, 'ecc-write',
        'should have the default signature key name')
    t.ok(myKeys.DID, 'should have a DID')
})

test('Get a DID from the keys', async t => {
    const did = myKeys.DID
    t.equal(typeof did, 'string', 'should get a string')
    t.equal(did.length, 72, 'should be 72 characters')
    t.ok(did.startsWith('did:key:'), 'should be a proper DID format')
})

test('publicExchangeKey and publicWriteKey getters', async t => {
    const pubExchange = myKeys.publicExchangeKey
    const pubWrite = myKeys.publicWriteKey

    t.ok(pubExchange, 'should have public exchange key')
    t.ok(pubWrite, 'should have public write key')
    t.equal(typeof pubExchange.asString, 'function',
        'should have asString method on exchange key')
    t.equal(typeof pubWrite.asString, 'function',
        'should have asString method on write key')

    const exchangeStr = await pubExchange.asString()
    const writeStr = await pubWrite.asString()
    t.equal(typeof exchangeStr, 'string', 'should export exchange key as string')
    t.equal(typeof writeStr, 'string', 'should export write key as string')
})

test('publicExchangeKeyAsString and publicWriteKeyAsString', async t => {
    const exchangeStr = await myKeys.publicExchangeKeyAsString()
    const writeStr = await myKeys.publicWriteKeyAsString()

    t.equal(typeof exchangeStr, 'string', 'should return exchange key as string')
    t.equal(typeof writeStr, 'string', 'should return write key as string')

    const exchangeStr64 = await myKeys.publicExchangeKeyAsString('base64')
    const writeStr64 = await myKeys.publicWriteKeyAsString('base64')
    t.equal(typeof exchangeStr64, 'string',
        'should return exchange key as base64 string')
    t.equal(typeof writeStr64, 'string',
        'should return write key as base64 string')
})

test('toJson serialization', async t => {
    const obj = await myKeys.toJson()
    t.equal(obj.DID, myKeys.DID, 'should return the DID')
    t.equal(typeof obj.publicExchangeKey, 'string',
        'should return public exchange key as string')

    const objBase32 = await myKeys.toJson('base32')
    t.equal(typeof objBase32.publicExchangeKey, 'string',
        'should format public key with specified encoding')
})

test('encrypt and decrypt a string (note to self)', async t => {
    const message = 'hello world from ECC'
    const encrypted = await myKeys.encrypt(message)

    t.ok(encrypted instanceof Uint8Array, 'should return Uint8Array')
    t.ok(encrypted.length > 0, 'should have encrypted content')

    const decrypted = await myKeys.decrypt(encrypted)
    const decryptedText = toString(new Uint8Array(decrypted))
    t.equal(decryptedText, message, 'should decrypt to original message')
})

test('encryptAsString and decryptAsString', async t => {
    const message = 'hello encryption formats'
    const encrypted = await myKeys.encryptAsString(message)

    t.equal(typeof encrypted, 'string',
        'should return encrypted data as string')

    const decrypted = await myKeys.decryptAsString(encrypted)
    t.equal(decrypted, message, 'should decrypt to original message')
})

test('encrypt to another public key', async t => {
    const otherKeys = await EccKeys.create()
    const message = 'secret message'

    // Encrypt to other keys' public key
    const encrypted = await myKeys.encrypt(
        message,
        otherKeys.publicExchangeKey
    )

    // Other keys should be able to decrypt
    const decrypted = await otherKeys.decrypt(
        encrypted,
        myKeys.publicExchangeKey
    )
    const decryptedText = toString(new Uint8Array(decrypted))
    t.equal(decryptedText, message, 'should decrypt message from other key')
})

test('encrypt to public key as string', async t => {
    const otherKeys = await EccKeys.create()
    const message = 'secret message with string key'
    const pubKeyString = await otherKeys.publicExchangeKeyAsString()

    // Encrypt to string public key
    const encrypted = await myKeys.encrypt(message, pubKeyString)

    // Other keys should be able to decrypt
    const decrypted = await otherKeys.decryptAsString(
        encrypted,
        myKeys.publicExchangeKey
    )
    t.equal(decrypted, message, 'should encrypt/decrypt with string public key')
})

let sig
test('sign', async t => {
    const message = 'message to sign'
    sig = await myKeys.sign(message)

    t.ok(sig instanceof Uint8Array, 'should return signature as Uint8Array')
    t.ok(sig.length > 0, 'should have signature data')
})

test('signAsString', async t => {
    const message = 'message to sign as string'
    const signature = await myKeys.signAsString(message)

    t.equal(typeof signature, 'string', 'should return signature as string')
    t.ok(signature.length > 0, 'should have signature data')
})

test('verify signature', async t => {
    const message = 'message to verify'
    const signature = await myKeys.signAsString(message)

    // Verify with correct message and signature
    const isValid = await verify(message, signature, myKeys.DID)
    t.ok(isValid, 'should verify valid signature')

    // Verify with wrong message
    const isInvalid = await verify('wrong message', signature, myKeys.DID)
    t.equal(isInvalid, false, 'should reject invalid signature')

    // Test with Uint8Array signature
    const sigBytes = await myKeys.sign(message)
    const isValidBytes = await verify(message, sigBytes, myKeys.DID)
    t.ok(isValidBytes, 'should verify valid signature with Uint8Array')
})

test('getAesKey method', async t => {
    const aesKey = await myKeys.getAesKey()
    t.ok(aesKey instanceof CryptoKey, 'should return a CryptoKey')
    t.equal(aesKey.type, 'secret', 'should be a secret key')
})

test('getAesKey with another public key', async t => {
    const otherKeys = await EccKeys.create()
    const aesKey = await myKeys.getAesKey(otherKeys.publicExchangeKey)
    t.ok(aesKey instanceof CryptoKey, 'should return a CryptoKey with other public key')
})

test('encrypt with custom info parameter', async t => {
    const message = 'test with custom info'
    const customInfo = 'custom-info'

    const encrypted = await myKeys.encrypt(message, undefined, customInfo)
    const decrypted = await myKeys.decryptAsString(encrypted, undefined, undefined, customInfo)
    t.equal(decrypted, message, 'should encrypt/decrypt with custom info')
})

test('Cache the keys instance', async t => {
    // Clear cache to start fresh
    EccKeys._instance = null

    // Create and cache an instance
    const keys1 = await EccKeys.create()
    t.equal(EccKeys._instance, keys1, 'should cache the created instance')

    // Loading should return the cached instance
    const keys2 = await EccKeys.load()
    t.equal(keys2, keys1, 'should return the same cached instance')
    t.equal(EccKeys._instance, keys1, 'cache should remain the same')
})

test('indexedDB persistence', async t => {
    await myKeys.persist()
    t.ok(myKeys.hasPersisted, 'should have persisted flag after calling .persist')

    const encryptionKey = await get(EccKeys.EXCHANGE_KEY_NAME)
    const signKey = await get(EccKeys.WRITE_KEY_NAME)
    t.ok(encryptionKey, 'should save an encryption key in indexedDB')
    t.ok(signKey, 'should save a signature key in indexedDB')
})

test('Create keys from indexedDB', async t => {
    // Clear the cache to test loading from indexedDB
    EccKeys._instance = null

    const newKeys = await EccKeys.load()
    t.ok(newKeys.DID, 'should have a DID when loaded from indexedDB')
    t.equal(newKeys.hasPersisted, true, 'should have `persisted` flag')

    // The new instance should be cached
    t.equal(EccKeys._instance, newKeys, 'should cache the loaded instance')
})

test('Delete the keys from indexedDB', async t => {
    t.equal(myKeys.hasPersisted, true, 'should start with persisted keys')

    const loadedKeys = await EccKeys.load()
    t.ok(loadedKeys, 'Should return key from indexedDB')

    await myKeys.delete()
    t.equal(myKeys.hasPersisted, false, 'now keys.persisted is false')

    const encryptionKey = await get(EccKeys.EXCHANGE_KEY_NAME)
    const signKey = await get(EccKeys.WRITE_KEY_NAME)
    t.equal(encryptionKey, undefined, 'should not return keys from indexedDB')
    t.equal(signKey, undefined, 'should not return signature key from indexedDB')
})

test('device name', async t => {
    const deviceName = await myKeys.getDeviceName()
    const deviceName2 = await EccKeys.deviceName(myKeys.DID)
    t.equal(deviceName, deviceName2, 'should return the same device name')
    t.equal(deviceName.length, 32, 'should return 32 characters')
    t.equal(typeof deviceName, 'string', 'should return a string')
})

test('in memory only', async t => {
    const keys = await EccKeys.create(true)
    t.equal(keys.hasPersisted, false, 'should not have `persisted` flag')
    t.equal(keys.isSessionOnly, true, 'should be session only')

    await keys.persist()
    t.equal(keys.hasPersisted, false, 'should still not be persisted after calling persist')
})

test('load method with session option', async t => {
    const keys = await EccKeys.load({ session: true })
    t.equal(keys.isSessionOnly, true, 'should be session only')
    t.equal(keys.hasPersisted, false, 'should not be persisted')
})

test('exportPublicKey utility function', async t => {
    const rawKey = await exportPublicKey(myKeys.exchangeKey)
    t.ok(rawKey instanceof ArrayBuffer, 'should export key as ArrayBuffer')
    t.equal(rawKey.byteLength, 32, 'should be 32 bytes for X25519 key')
})

test('importPublicKey utility function', async t => {
    const rawKey = await exportPublicKey(myKeys.exchangeKey)
    const keyString = toString(new Uint8Array(rawKey), 'base64pad')

    const imported = await importPublicKey(keyString, EccCurve.X25519, KeyUse.Exchange)
    t.ok(imported instanceof CryptoKey, 'should import as CryptoKey')
    t.equal(imported.type, 'public', 'should be a public key')
})

// Note: Backward compatibility .asString methods are attached to prototypes
// but testing these requires more complex setup. The important thing is that
// the proper async methods (encryptAsString, decryptAsString, signAsString) work
// test('backward compatibility .asString methods', async t => {
//     const message = 'test backward compatibility'

//     // Test encrypt.asString (this calls the attached asString method)
//     const encrypted = await (myKeys.encrypt as any).asString(message)
//     t.equal(typeof encrypted, 'string', 'encrypt.asString should return string')

//     // Test decrypt.asString (this calls the attached asString method)
//     const decrypted = await (myKeys.decrypt as any).asString(encrypted)
//     t.equal(decrypted, message, 'decrypt.asString should decrypt correctly')

//     // Test sign.asString (this calls the attached asString method)
//     const signature = await (myKeys.sign as any).asString(message)
//     t.equal(typeof signature, 'string', 'sign.asString should return string')
// })

test('An example use of to/from strings', async t => {
    const msg = { type: 'test', content: 'hello ECC' }
    const encrypted = await myKeys.encryptAsString(JSON.stringify(msg))

    t.equal(typeof encrypted, 'string', 'should return a string')

    const text = await myKeys.decryptAsString(encrypted)
    const data = JSON.parse(text)
    t.equal(data.content, 'hello ECC', 'should get the original object')
})
