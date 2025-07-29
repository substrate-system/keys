import { webcrypto } from '@substrate-system/one-webcrypto'
import {
    getPublicKeyAsArrayBuffer,
    publicKeyToDid,
    base64ToArrBuf,
    makeEccKeypair
} from '../util.js'
import { ECC_EXCHANGE_ALG, ECC_WRITE_ALG } from '../constants.js'
import { KeyUse, type EccCurve, type PublicKey, type DID } from '../types.js'
import { checkValidKeyUse } from '../errors.js'

/**
 * Class for ECC keys
 */
export class Keys {
    DID:DID
    exchangeKey:CryptoKeyPair
    writeKey:CryptoKeyPair
    isPersisted:boolean
    isSessionOnly:boolean

    /**
     * Use `.create`, not the constructor.
     */
    constructor (opts:{
        keys:{ exchange:CryptoKeyPair, write:CryptoKeyPair };
        did:DID;
        isPersisted:boolean;
        isSessionOnly:boolean;  // in memory only?
    }) {
        this.DID = opts.did
        this.exchangeKey = opts.keys.exchange
        this.writeKey = opts.keys.write
        this.isPersisted = opts.isPersisted
        this.isSessionOnly = opts.isSessionOnly
    }

    get publicExchangeKey ():CryptoKey {
        return this.exchangeKey.publicKey
    }

    get publicWriteKey ():CryptoKey {
        return this.writeKey.publicKey
    }

    /**
     * Factory function because async.
     * Create new ECC keypairs for signing and encrypting.
     *
     * @param {boolean} session In memory only, not persisted?
     */
    static async create (session?:boolean):Promise<Keys> {
        // encryption
        const exchange = await makeEccKeypair(ECC_EXCHANGE_ALG, 'encyrpt')

        // signatures
        const sign = await makeEccKeypair(ECC_WRITE_ALG, 'sign')

        const publicSigningKey = await getPublicKeyAsArrayBuffer(sign)
        const did = await publicKeyToDid(
            new Uint8Array(publicSigningKey),
            'ed25519'
        )

        const keys = new Keys({
            keys: { exchange, write: sign },
            did,
            isPersisted: false,
            isSessionOnly: !!session
        })

        return keys
    }
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
    Keys,
    importPublicKey
}

