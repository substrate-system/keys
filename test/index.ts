import { test } from '@substrate-system/tapzero'
import { verify as ed25519Verify, EccKeys } from '../src/ecc/index.js'
import { verify as rsaVerify, RsaKeys } from '../src/rsa/index.js'
import { verify } from '../src/crypto.js'
import './aes.js'
import './rsa.js'
import './ecc.js'

test('Verify all signature types', async t => {
    const ecc = await EccKeys.create(true)
    const rsa = await RsaKeys.create(true)
    const message = 'message to sign as string'

    const signature = await ecc.signAsString(message)
    t.equal(typeof signature, 'string', 'Can sign with Ed25519')

    const rsaSig = await rsa.signAsString(message)
    t.equal(typeof rsaSig, 'string', 'Can sign with RSA')

    t.ok(await rsaVerify(
        message,
        rsaSig,
        rsa.DID,
    ), 'rsa signature is ok')

    t.ok(await ed25519Verify(
        message,
        signature,
        ecc.DID,
    ), 'ecc is ok')

    console.log('**ECC DID**', ecc.DID)
    console.log('**RSA DID**', rsa.DID)

    // this should work with either type of signature
    t.ok(await verify({ message, publicKey: ecc.DID, signature }),
        'Generic verify ECC keys')
    t.ok(await verify({ message, publicKey: rsa.DID, signature: rsaSig }),
        'Can verify RSA with generic function')

    t.ok(!(await verify({
        message,
        publicKey: ecc.DID,
        signature: 'A' + signature.slice(1)
    })), 'Should not verify an invalid Ed25519 signature')

    t.ok(!(await verify({
        message,
        publicKey: rsa.DID,
        signature: 'A' + rsaSig.slice(1)
    })), 'Should not verify an invalid RSA signature')
})
