import { get } from 'idb-keyval'
import { test } from '@bicycle-codes/tapzero'
import { Keys, verifyFromString } from '../src/index.js'

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
