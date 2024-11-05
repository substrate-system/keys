import { get } from 'idb-keyval'
import { test } from '@bicycle-codes/tapzero'
import { Keys } from '../src/index.js'

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
