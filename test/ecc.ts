import { test } from '@substrate-system/tapzero'
import { EccKeys } from '../src/ecc/index.js'
import { publicKeyToDid } from '../src/util.js'

const subtle = crypto.subtle

// Can we create an x25519 key in this environment?
test('Sanity', async t => {
    try {
        const keys = await subtle.generateKey({
            name: 'X25519'
        }, true, ['deriveKey']) as CryptoKeyPair
        const raw = await subtle.exportKey('raw', keys.publicKey)
        t.equal(raw.byteLength, 32, 'should generate an X25519 key')

        // @ts-expect-error dev
        window.testsFinished = true
    } catch (err) {
        // @ts-expect-error dev
        window.testsFinished = true
        console.error('error in test', err)
    }
})

let myKeys:EccKeys
test('Create a new Keys instance', async t => {
    myKeys = await EccKeys.create()
    t.ok(myKeys, 'should create the keys')
})

test('Get a DID from the keys', async t => {
    const did = myKeys.DID
    t.equal(typeof did, 'string', 'should get a string')
    t.equal(did.length, 72, 'should be 72 characters')
    const did2 = await publicKeyToDid(myKeys.publicWriteKey, 'ed25519')
    t.equal(did2, myKeys.DID, 'should return the right string')
})

test('done', () => {
    // @ts-expect-error dev
    window.testsFinished = true
})
