import { webcrypto } from '@substrate-system/one-webcrypto'
import { base64ToArrBuf } from '../util.js'
import { ECC_EXCHANGE_ALG, ECC_WRITE_ALG } from '../constants.js'
import { KeyUse, EccCurve, type PublicKey, DID } from '../types.js'
import { checkValidKeyUse } from '../errors.js'

// // Step 1: Bob generates ECDH key pair (this could be long-term)
// async function generateUserKeyPair () {
//     return crypto.subtle.generateKey(
//         { name: 'ECDH', namedCurve: 'X25519' },
//         true,
//         ['deriveKey']
//     )
// }

export class Keys {
    DID:DID

    constructor (opts:{
        keys:{ encrypt:CryptoKeyPair, sign:CryptoKeyPair };
        did:DID;
        persisted:boolean;
        session:boolean;  // in memory only?
    }) {
        this.DID = opts.did
    }

    get signKeypair ():CryptoKeyPair {
        return {
            privateKey: this.privateSignKey,
            publicKey: this.publicSignKey
        }
    }
}

/**
 * Create a new ECC keypair.
 * Default type is X25519 key, and encryption uses.
 *
 * @param {EccCurve} curve Curve, e.g. X25519
 * @param {KeyUse} use Signing, encryption, etc
 * @returns {Promise<CryptoKeyPair>} New keypair
 */
export async function create (
    curve:EccCurve = EccCurve.X25519,
    use:KeyUse = KeyUse.Exchange
):Promise<CryptoKeyPair> {
    checkValidKeyUse(use)
    const alg = (use === KeyUse.Exchange ? ECC_EXCHANGE_ALG : ECC_WRITE_ALG)
    const uses:KeyUsage[] = (use === KeyUse.Exchange ?
        ['deriveKey', 'deriveBits'] :
        ['sign', 'verify'])

    return await webcrypto.subtle.generateKey(
        {
            name: alg,  // 'ECDH' or 'ECDSA' -- encryption or signatures
            namedCurve: curve  // 'X25519' or 'P-256',
        },
        false,  // extractable
        uses  // derive or sign
    )
}

/**
 * Get the public key from a given keypair.
 *
 * @param {CryptoKeyPair} keypair The keypair to get the public side from.
 * @returns {Promise<ArrayBuffer>} ArrayBuffer of public key material
 */
export async function exportPublicKey (
    keypair:CryptoKeyPair
):Promise<ArrayBuffer> {
    const raw = await webcrypto.subtle.exportKey('raw', keypair.publicKey)
    return raw
}

export async function importPublicKey (
    base64Key:string,
    curve:EccCurve,
    use:KeyUse
):Promise<PublicKey> {
    checkValidKeyUse(use)
    const alg = use === KeyUse.Exchange ? ECC_EXCHANGE_ALG : ECC_WRITE_ALG
    const uses:KeyUsage[] = use === KeyUse.Exchange ? [] : ['verify']
    const buf = base64ToArrBuf(base64Key)
    return webcrypto.subtle.importKey(
        'raw',
        buf,
        { name: alg, namedCurve: curve },
        true,
        uses
    )
}

export default {
    create,
    importPublicKey
}

