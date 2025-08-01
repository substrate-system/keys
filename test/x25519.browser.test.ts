import { test } from '@substrate-system/tapzero'

// @ts-expect-error dev
window.runTests = async function runTests () {
    const subtle = crypto.subtle

    // Use a Promise to wait for test completion
    return new Promise<void>((resolve, reject) => {
        test('X25519 keypair generates 32-byte raw public key', async t => {
            try {
                const keys = await subtle.generateKey({
                    name: 'X25519'
                }, true, ['deriveKey']) as CryptoKeyPair
                const raw = await subtle.exportKey('raw', keys.publicKey)
                t.equal(raw.byteLength, 32, 'should be 32 bytes')

                // @ts-expect-error dev
                window.testsFinished = true
                resolve()
            } catch (err) {
                // @ts-expect-error dev
                window.testsFinished = true
                reject(err)
            }
        })
    })
}
