import { get } from 'idb-keyval'
import { test } from '@substrate-system/tapzero'
import { fromString, toString, equals } from 'uint8arrays'
import {
    Keys,
    encryptKeyTo,
    encryptTo,
    AES,
    verify,
    publicKeyToDid,
    getPublicKeyAsUint8Array
} from '../src/index.js'

let keys:Keys
test('create a new Keys', async t => {
    keys = await Keys.create()
    t.ok(keys, 'should return something')

    t.equal(keys.persisted, false,
        'should not have persisted flag for newly created keys')
    t.equal(keys.ENCRYPTION_KEY_NAME, 'encryption-key',
        'should have the default encryption key name')
    t.equal(keys.SIGNING_KEY_NAME, 'signing-key',
        'should have the default signature key name')
    t.ok(keys.DID, 'should have a DID')
})

test('encrypt and decrypt a string', async t => {
    const pubKey = keys.publicEncryptKey
    const message = 'hello world'
    const cipherText = await encryptTo.asString({
        content: message,
        publicKey: pubKey
    })

    const decrypted = await keys.decrypt.asString(cipherText)
    t.equal(decrypted, 'hello world', 'should decrypt the text')
})

test('`encryptTo.asString` and `keys.decrypt`', async t => {
    const pubKey = keys.publicEncryptKey
    const message = 'hello encryption formats'
    const cipherText = await encryptTo.asString({
        content: message,
        publicKey: pubKey
    })

    t.equal(typeof cipherText, 'string', 'should return a string')
    const plainTextBuf = await keys.decrypt(cipherText)
    const plainText = toString(plainTextBuf)
    t.equal(plainText, message, 'should decrypt the message to the original')
})

test('An example use of to/from strings', async t => {
    const pubKey = await keys.getPublicEncryptKey()
    const msg = { type: 'test', content: 'hello' }
    const cipherText = await encryptTo.asString({
        content: JSON.stringify(msg),
        // pass in a string public key
        publicKey: pubKey
    })

    t.equal(typeof cipherText, 'string', 'should return a string')

    const text = await keys.decrypt.asString(cipherText)
    const data = JSON.parse(text)
    t.equal(data.content, 'hello', 'should get the original object')
})

test('cache the keys instance', async t => {
    const newKeys = await Keys.load()
    t.equal(newKeys, keys, 'should return the same isntance of Keys')
})

test('getPublicKeyAsUint8Array', async t => {
    const arr = await getPublicKeyAsUint8Array(keys.publicEncryptKey)
    t.ok(arr instanceof Uint8Array,
        'should expose the util function `getPublicKeyAsUint8Array`')
})

test('publicKeyToDid method', async t => {
    const did = await publicKeyToDid(keys.publicSignKey)
    t.equal(did, keys.DID, 'should return the DID')
})

test('indexedDB', async t => {
    await keys.persist()
    t.ok(keys.persisted, 'should have persisted flag after calling .persist')
    const encryptionKey = await get(keys.ENCRYPTION_KEY_NAME)
    const signKey = await get(keys.SIGNING_KEY_NAME)
    t.ok(encryptionKey, 'should save an encryption key in indexedDB')
    t.ok(signKey, 'should save a signature key in indexedDB')
})

test('Create keys from indexedDB', async t => {
    const newKeys = await Keys.load()
    t.equal(newKeys.DID, keys.DID,
        'should create a new instance with the same keys')
    t.equal(newKeys.persisted, true, 'should have `persisted` flag')
})

test('Delete the keys from indexedDB', async t => {
    t.ok(keys.persisted, 'should start with persisted keys')
    t.ok(await get(keys.ENCRYPTION_KEY_NAME), 'Should return key from indexedDB')
    await keys.delete()
    t.ok(!keys.persisted, 'now keys.persisted is false')
    const res = await get(keys.ENCRYPTION_KEY_NAME)
    t.ok(!res, 'should not return keys from indexedDB')
})

test('device name', async t => {
    const name = await Keys.deviceName(keys.DID)
    const name2 = await keys.getDeviceName()
    t.equal(name, name2, 'should return the same device name')
    t.equal(name.length, 32, 'should return 32 chracters')
})

let sigArr:Uint8Array
test('sign something', async t => {
    sigArr = await keys.sign('hello signatures')
    t.ok(sigArr instanceof Uint8Array, 'should return a Uint8Array by default')
})

test('verify the signature as a buffer', async t => {
    const isOk = await verify('hello signatures', sigArr, keys.DID)
    t.ok(isOk, 'should verify a valid signature')
})

let sig:string
test('.sign.asString', async t => {
    sig = await keys.sign.asString('hello string')
    t.equal(typeof sig, 'string', 'should return the signature as a string')
})

test('verify a valid string signature', async t => {
    const isOk = await verify('hello string', sig, keys.DID)
    t.ok(isOk, 'should verify a valid signature')
})

test('verify an invalid signature', async t => {
    const isOk = await verify('hello string123', sig, keys.DID)
    t.ok(!isOk, 'should not verify an invalid signature')
})

let encrypted:Uint8Array
test('encrypt a key to a keys instance', async t => {
    encrypted = await encryptKeyTo({
        key: 'hello',
        publicKey: keys.publicEncryptKey
    })

    t.ok(encrypted instanceof Uint8Array, 'should return a Uint8Array')

    const otherKey = await AES.create()
    const otherArr = await AES.export(otherKey)
    const otherEncrypted = await encryptKeyTo({
        key: otherKey,
        publicKey: keys.publicEncryptKey
    })

    const otherDecrypted = await keys.decryptKey(otherEncrypted)
    t.ok(equals(otherArr, otherDecrypted), 'should decrypt to the same value')
})

test('get a serializable object from keys', async t => {
    t.plan(2)
    const keys = await Keys.create()
    const obj = await keys.toJson()
    t.equal(obj.DID, keys.DID, 'should return the DID')
    t.equal(obj.publicEncryptKey, await keys.getPublicEncryptKey(),
        'should return a string of the public encyrption key')
})

test('encrypt a key to a keypair, return a string', async t => {
    const aes = await AES.create()
    const encrypted = await encryptKeyTo.asString({
        key: aes,
        publicKey: keys.publicEncryptKey
    })

    t.equal(typeof encrypted, 'string', 'should return the AES key as a string')

    const encryptedTwo = await encryptKeyTo.asString({
        key: aes,
        publicKey: keys.publicEncryptKey
    }, 'base32')

    t.equal(typeof encryptedTwo, 'string', 'should retunr a string')
    t.equal(encryptedTwo, encryptedTwo.toLocaleLowerCase(),
        'should base32 encode the key')
})

test('encrypt a key to a public key, return a string', async t => {
    const aes = await AES.create()
    const enc = await encryptKeyTo.asString({
        key: aes,
        publicKey: await keys.getPublicEncryptKey()
    })

    t.equal(typeof enc, 'string', 'should encrypt the key and return a string')
})

test('`getPublicEncryptKey', async t => {
    const key = await keys.getPublicEncryptKey()
    t.equal(typeof key, 'string', 'should return a string')
})

test('`getPublicEncryptKey.uint8Array`', async t => {
    const arr = await keys.getPublicEncryptKey.uint8Array()
    t.ok(arr instanceof Uint8Array, 'should return a Uint8Array')
})

test('Can pass a format to `getPublicEncryptKey`', async t => {
    const key = await keys.getPublicEncryptKey('base32')
    t.equal(typeof key, 'string', 'should return a string')
    t.equal(key, key.toLowerCase(), 'should be base32 encoded')
})

test('encrypt some content to a public key', async t => {
    const encrypted = await encryptTo({
        content: 'hello public key',
        publicKey: await keys.getPublicEncryptKey()
    })

    t.ok(encrypted instanceof ArrayBuffer, 'should return an array buffer')
})

test('encrypt some content to a public key, as string', async t => {
    const encrypted = await encryptTo.asString({
        content: 'hello public key',
        publicKey: await keys.getPublicEncryptKey()
    })

    t.equal(typeof encrypted, 'string', 'returns a string')
})

test('decrypt a key', async t => {
    const decrypted = await keys.decryptKey(encrypted)
    t.equal(toString(decrypted), 'hello', 'should decrypt the text')
})

test('decrypt a key with the wrong keys', async t => {
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
    const decrypted = await keys.decryptKey.asString(encrypted)
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

    const again = await AES.export.asString(aesKey)
    t.equal(again, exported, 'should export the same key')
})

let encryptedText:Uint8Array
test('AES encrypt', async t => {
    encryptedText = await AES.encrypt(fromString('hello AES'), aesKey)
    t.ok(encryptedText instanceof Uint8Array, 'should return a new Uint8Array')
})

test('AES encrypt with format', async t => {
    const encrypted = await AES.encrypt(fromString('hello AES'), aesKey, 'arraybuffer')
    t.ok(encrypted instanceof ArrayBuffer, 'should return an array buffer')
})

test('AES decrypt', async t => {
    const decryptedText = await AES.decrypt(encryptedText, aesKey)
    t.ok(decryptedText instanceof Uint8Array, 'should return a Uint8Array')
    t.equal(toString(decryptedText), 'hello AES',
        'should decrypt to the right value')
})

test('getPublicEncryptKey', async t => {
    const pubKey = await keys.getPublicEncryptKey()
    t.ok(pubKey, 'should return something')
    t.equal(typeof pubKey, 'string', 'should return a string')
})

let bob:Keys
let encryptedMsg:ArrayBuffer
test('encrypt content to a public key', async t => {
    bob = await Keys.create()

    const message = 'Hello bob'

    encryptedMsg = await encryptTo({
        content: message,
        publicKey: bob.publicEncryptKey
    })

    t.ok(encryptedMsg instanceof ArrayBuffer, 'should return an array buffer')
})

let encryptedString:string
test('encrypt and return a string', async t => {
    const msg = 'hello strings'

    encryptedString = await encryptTo.asString({
        content: msg,
        publicKey: bob.publicEncryptKey
    })

    t.equal(typeof encryptedString, 'string', 'should return an encrypted string')
    t.ok(encryptedString !== msg)
})

test('Bob can decrypt the message addressed to Bob', async t => {
    const decrypted = await bob.decrypt(encryptedMsg)
    t.equal(toString(decrypted), 'Hello bob', 'should decrypt the message')
})

test('keys.decrypt.asString', async t => {
    const decrypted = await bob.decrypt.asString(encryptedString)
    t.equal(decrypted, 'hello strings', 'should decrypt the message to a string')
})

test('AES.export with format argument', async t => {
    const key = await AES.create()
    const defaultExport = await AES.export.asString(key)
    const exported = await AES.export.asString(key, 'base64url')
    t.ok(defaultExport !== exported, 'should use the `format` argument')
})

test('in memory only', async t => {
    const keys = await Keys.create({ session: true })
    await keys.persist()
    delete Keys._instance  // rm the cached copy
    t.equal(keys.persisted, false, 'should not have `persisted` flag')
    const keysTwo = await Keys.load()
    t.ok(keysTwo.DID !== keys.DID,
        'should not load the same keypair from indexedDB')
})
