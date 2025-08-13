import { test } from '@substrate-system/tapzero'
import { toString, fromString, equals } from 'uint8arrays'
import { AES, importAesKey } from '../src/aes/index.js'
import { SymmKeyLength } from '../src/types.js'

test('________________create an AES key__________________', async t => {
    const key = await AES.create()
    t.ok(key instanceof CryptoKey, 'should return a new CryptoKey')
    t.equal(key.type, 'secret', 'should be a secret key')
    t.equal(key.algorithm.name, 'AES-GCM', 'should be AES-GCM algorithm')
    t.equal((key.algorithm as any).length, 256, 'should be 256-bit key by default')
})

test('create AES key with custom options', async t => {
    const key128 = await AES.create({ length: 128 })
    t.equal((key128.algorithm as any).length, 128, 'should create 128-bit key')

    const key256 = await AES.create({ length: SymmKeyLength.B256 })
    t.equal((key256.algorithm as any).length, 256,
        'should create 256-bit key with enum')
})

test('export an AES key', async t => {
    const key = await AES.create()
    const exported = await AES.export(key)
    t.ok(exported instanceof Uint8Array, 'should return a Uint8Array')
    t.equal(exported.length, 32, 'should be 32 bytes for 256-bit key')
})

test('export an AES key as string', async t => {
    const key = await AES.create()
    const exported = await AES.export.asString(key)
    t.equal(typeof exported, 'string', 'should return a string')
    t.ok(exported.length > 0, 'should have content')

    // Test with different formats
    const base32 = await AES.export.asString(key, 'base32')
    t.equal(typeof base32, 'string', 'should export as base32 string')
    t.notEqual(base32, exported, 'should be different format')
})

test('exportAsString method', async t => {
    const key = await AES.create()
    const exported = await AES.exportAsString(key)
    t.equal(typeof exported, 'string', 'should return a string version')

    // Should match the export.asString method
    const exported2 = await AES.export.asString(key)
    t.equal(exported, exported2, 'should match export.asString result')
})

test('import an AES key from Uint8Array', async t => {
    const originalKey = await AES.create()
    const exported = await AES.export(originalKey)
    const imported = await AES.import(exported)

    t.ok(imported instanceof CryptoKey, 'should return a CryptoKey')
    t.equal(imported.type, 'secret', 'should be a secret key')
    t.equal(imported.algorithm.name, 'AES-GCM', 'should be AES-GCM algorithm')
})

test('import an AES key from string', async t => {
    const originalKey = await AES.create()
    const exported = await AES.exportAsString(originalKey)
    const imported = await AES.import(exported)

    t.ok(imported instanceof CryptoKey, 'should return a CryptoKey from string')
    t.equal(imported.type, 'secret', 'should be a secret key')
})

test('importAesKey utility function', async t => {
    const originalKey = await AES.create()
    const exported = await AES.export(originalKey)
    const imported = await importAesKey(exported)

    t.ok(imported instanceof CryptoKey, 'should import as CryptoKey')
    t.equal(imported.type, 'secret', 'should be a secret key')
})

test('importAesKey with custom length', async t => {
    const key128 = await AES.create({ length: 128 })
    const exported = await AES.export(key128)
    const imported = await importAesKey(exported, 128)

    t.equal((imported.algorithm as any).length, 128,
        'should import with correct length')
})

test('AES encrypt and decrypt', async t => {
    const key = await AES.create()
    const message = 'Hello AES encryption!'
    const data = fromString(message)

    const encrypted = await AES.encrypt(data, key)
    t.ok(encrypted instanceof Uint8Array, 'should return encrypted Uint8Array')
    t.ok(encrypted.length > data.length,
        'encrypted should be larger (includes IV)')

    const decrypted = await AES.decrypt(encrypted, key)
    t.ok(decrypted instanceof Uint8Array, 'should return decrypted Uint8Array')

    const decryptedText = toString(decrypted)
    t.equal(decryptedText, message, 'should decrypt to original message')
})

test('AES encrypt with format options', async t => {
    const key = await AES.create()
    const data = fromString('test data')

    const encryptedUint8 = await AES.encrypt(data, key, 'uint8array')
    t.ok(encryptedUint8 instanceof Uint8Array, 'should return Uint8Array format')

    const encryptedBuffer = await AES.encrypt(data, key, 'arraybuffer')
    t.ok(encryptedBuffer instanceof ArrayBuffer, 'should return ArrayBuffer format')

    // Both should decrypt to same result
    const decrypted1 = await AES.decrypt(encryptedUint8, key)
    const decrypted2 = await AES.decrypt(encryptedBuffer, key)
    t.ok(equals(decrypted1, decrypted2),
        'should decrypt to same result regardless of format')
})

test('AES encrypt with custom IV', async t => {
    const key = await AES.create()
    const data = fromString('test with custom IV')
    const iv = crypto.getRandomValues(new Uint8Array(12)) // AES-GCM uses 12-byte IV

    const encrypted = await AES.encrypt(data, key, undefined, iv)
    const decrypted = await AES.decrypt(encrypted, key, iv)

    const decryptedText = toString(decrypted)
    t.equal(decryptedText, 'test with custom IV', 'should work with custom IV')
})

test('AES encrypt/decrypt with Uint8Array key', async t => {
    const originalKey = await AES.create()
    const keyBytes = await AES.export(originalKey)
    const message = 'test with raw key'
    const data = fromString(message)

    const encrypted = await AES.encrypt(data, keyBytes)
    const decrypted = await AES.decrypt(encrypted, keyBytes)

    const decryptedText = toString(decrypted)
    t.equal(decryptedText, message, 'should work with Uint8Array key')
})

test('AES decrypt with string input', async t => {
    const key = await AES.create()
    const message = 'test string input'
    const data = fromString(message)

    const encrypted = await AES.encrypt(data, key)
    const encryptedString = toString(encrypted, 'base64')

    const decrypted = await AES.decrypt(encryptedString, key)
    const decryptedText = toString(decrypted)
    t.equal(decryptedText, message, 'should decrypt from string input')
})

test('AES decrypt with ArrayBuffer input', async t => {
    const key = await AES.create()
    const message = 'test ArrayBuffer input'
    const data = fromString(message)

    const encrypted = await AES.encrypt(data, key, 'arraybuffer')
    const decrypted = await AES.decrypt(encrypted, key)

    const decryptedText = toString(decrypted)
    t.equal(decryptedText, message, 'should decrypt from ArrayBuffer input')
})

test('Round trip: export and import key maintains functionality', async t => {
    const originalKey = await AES.create()
    const message = 'roundtrip test'
    const data = fromString(message)

    // Export and reimport the key
    const exported = await AES.export(originalKey)
    const reimported = await AES.import(exported)

    // Encrypt with original, decrypt with reimported
    const encrypted = await AES.encrypt(data, originalKey)
    const decrypted = await AES.decrypt(encrypted, reimported)

    const decryptedText = toString(decrypted)
    t.equal(decryptedText, message, 'should work with reimported key')
})

test('Round trip: string export/import', async t => {
    const originalKey = await AES.create()
    const message = 'string roundtrip test'
    const data = fromString(message)

    // Export as string and reimport
    const exportedString = await AES.exportAsString(originalKey)
    const reimported = await AES.import(exportedString)

    // Test encryption/decryption
    const encrypted = await AES.encrypt(data, originalKey)
    const decrypted = await AES.decrypt(encrypted, reimported)

    const decryptedText = toString(decrypted)
    t.equal(decryptedText, message, 'should work with string export/import')
})

test('Different key sizes', async t => {
    const sizes = [128, 256]
    const expectedBytes = [16, 32]

    for (let i = 0; i < sizes.length; i++) {
        const key = await AES.create({ length: sizes[i] })
        const exported = await AES.export(key)
        t.equal(exported.length, expectedBytes[i],
            `should export ${expectedBytes[i]} bytes for ${sizes[i]}-bit key`)

        // Test encryption/decryption works
        const data = fromString(`test ${sizes[i]}-bit key`)
        const encrypted = await AES.encrypt(data, key)
        const decrypted = await AES.decrypt(encrypted, key)
        const decryptedText = toString(decrypted)
        t.equal(decryptedText, `test ${sizes[i]}-bit key`,
            `should work with ${sizes[i]}-bit key`)
    }
})

test('Error handling: decrypt with wrong key', async t => {
    const key1 = await AES.create()
    const key2 = await AES.create()
    const data = fromString('test error handling')

    const encrypted = await AES.encrypt(data, key1)

    try {
        await AES.decrypt(encrypted, key2)
        t.fail('should throw error when decrypting with wrong key')
    } catch (err) {
        t.ok(err, 'should throw error when decrypting with wrong key')
    }
})

test('Large data encryption/decryption', async t => {
    const key = await AES.create()
    const largeMessage = 'x'.repeat(10000) // 10KB of data
    const data = fromString(largeMessage)

    const encrypted = await AES.encrypt(data, key)
    const decrypted = await AES.decrypt(encrypted, key)
    const decryptedText = toString(decrypted)

    t.equal(decryptedText, largeMessage, 'should handle large data')
    t.equal(decryptedText.length, 10000, 'should maintain data length')
})

test('Binary data encryption/decryption', async t => {
    const key = await AES.create()
    const binaryData = new Uint8Array([0, 1, 2, 3, 255, 254, 253, 128, 127])

    const encrypted = await AES.encrypt(binaryData, key)
    const decrypted = await AES.decrypt(encrypted, key)

    t.ok(equals(binaryData, decrypted), 'should handle binary data correctly')
})
