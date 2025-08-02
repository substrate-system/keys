import { test } from '@substrate-system/tapzero'
import { EccKeys } from '../src/ecc/index.js'

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

test('Create a new Keys instance', async t => {
    const myKeys = await EccKeys.create()
    t.ok(myKeys, 'should create the keys')
})

test('done', () => {
    // @ts-expect-error dev
    window.testsFinished = true
})
