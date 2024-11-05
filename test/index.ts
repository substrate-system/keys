import { get } from 'idb-keyval'
import { test } from '@bicycle-codes/tapzero'
import { fromString, toString } from 'uint8arrays'
import {
    Keys,
    verifyFromString,
    encryptKeyTo,
    encryptTo,
    AES
} from '../src/index.js'
import type { EncryptedMessage } from '../src/types.js'

let keys:Keys
test('create a new Keys', async t => {
    keys = await Keys.create()
    t.ok(keys, 'should return something')

    t.equal(keys.ENCRYPTION_KEY_NAME, 'encryption-key',
        'should have the default encryption key name')
    t.equal(keys.SIGNING_KEY_NAME, 'signing-key',
        'should have the default signature key name')
})

test('indexedDB', async t => {
    const encryptionKey = await get(keys.ENCRYPTION_KEY_NAME)
    const signKey = await get(keys.SIGNING_KEY_NAME)
    t.ok(encryptionKey, 'should save an encryption key in indexedDB')
    t.ok(signKey, 'should save a signature key in indexedDB')
})

test('sign something', async t => {
    const sig = await keys.sign('hello signatures')
    t.ok(sig instanceof Uint8Array, 'should return a Uint8Array by default')
})

let sig:string
test('.signAsString', async t => {
    sig = await keys.signAsString('hello string')
    t.equal(typeof sig, 'string', 'should return the signature as a string')
})

test('verify a valid signature', async t => {
    const isOk = await verifyFromString('hello string', sig, keys.DID)
    t.ok(isOk, 'should verify a valid signature')
})

test('verify an invalid signature', async t => {
    const isOk = await verifyFromString('hello string123', sig, keys.DID)
    t.ok(!isOk, 'should not verify an invalid signature')
})

let encrypted:Uint8Array
test('encrypt something to a keys instance', async t => {
    encrypted = await encryptKeyTo({
        content: 'hello',
        publicKey: keys.publicEncryptKey
    })

    t.ok(encrypted instanceof Uint8Array, 'should return a Uint8Array')
})

test('decrypt a message', async t => {
    const decrypted = await keys.decryptKey(encrypted)
    t.equal(toString(decrypted), 'hello', 'should decrypt the text')
})

test('decrypt a message with the wrong keys', async t => {
    const newKeys = await Keys.create()
    try {
        const decrypted = await newKeys.decryptKey(encrypted)
        t.ok(toString(decrypted) !== 'hello',
            'should not decrypt with the wrong keys')
    } catch (err) {
        t.ok(err, 'should throw if decrypting with the wrong keys')
    }
})

test('decrypt as string', async t => {
    const decrypted = await keys.decryptKeyAsString(encrypted)
    t.equal(decrypted, 'hello', 'should decrypt and return a string')
})

let aesKey:CryptoKey
test('create an AES key', async t => {
    aesKey = await AES.create()
    t.ok(aesKey instanceof CryptoKey, 'should return a new CryptoKey')
})

test('export an AES key', async t => {
    const exported = await AES.export(aesKey)
    t.ok(exported instanceof Uint8Array, 'should return a Uint8Array')
})

test('export an AES key as a string', async t => {
    const exported = await AES.exportAsString(aesKey)
    t.equal(typeof exported, 'string', 'should return a string version')
})

let encryptedText:Uint8Array
test('AES encrypt', async t => {
    encryptedText = await AES.encrypt(fromString('hello AES'), aesKey)
    t.ok(encrypted instanceof Uint8Array, 'should return a new Uint8Array')
})

test('AES decrypt', async t => {
    const decryptedText = await AES.decrypt(encryptedText, aesKey)
    t.ok(decryptedText instanceof Uint8Array, 'should return a Uint8Array')
    t.equal(toString(decryptedText), 'hello AES',
        'should decrypt to the right value')
})

let bob:Keys
let encryptedMsg:EncryptedMessage
test('encrypt content to a public key', async t => {
    bob = await Keys.create()

    const message = 'Hello bob'

    encryptedMsg = await encryptTo({
        content: message,
        publicKey: bob.publicEncryptKey
    })

    t.ok(encryptedMsg.content instanceof Uint8Array,
        'should return the content as a Uint8Array')
    t.ok(encryptedMsg.key instanceof Uint8Array,
        'should return the key as a Uint8Array')
})

test('Bob can decrypt the message addressed to Bob', async t => {
    const decrypted = await bob.decrypt(encryptedMsg)
    t.equal(toString(decrypted), 'Hello bob', 'should decrypt the message')
})

test('keys.decryptToString', async t => {
    const decrypted = await bob.decryptToString(encryptedMsg)
    t.equal(decrypted, 'Hello bob', 'should decrypt the message to a string')
})
