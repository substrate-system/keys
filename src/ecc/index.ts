import { webcrypto } from '@substrate-system/one-webcrypto'
import { DEFAULT_ECC_EXCHANGE, DEFAULT_ECC_WRITE, ECC_EXCHANGE_ALG, ECC_WRITE_ALG } from '../constants.js'
import { KeyUse, type EccCurve, type PublicKey } from '../types.js'
import { base64ToArrBuf, } from '../util.js'
import { checkValidKeyUse } from '../errors.js'
import { AbstractKeys, type KeyArgs } from '../_base.js'

/**
 * Class for ECC keys
 */
export class EccKeys extends AbstractKeys {
    constructor (opts:KeyArgs) {
        super(opts)
        EccKeys.EXCHANGE_KEY_NAME = opts.exchangeKeyName || DEFAULT_ECC_EXCHANGE
        EccKeys.WRITE_KEY_NAME = opts.writeKeyName || DEFAULT_ECC_WRITE
    }

    get publicExchangeKey ():CryptoKey {
        return this.exchangeKey.publicKey
    }

    get publicWriteKey ():CryptoKey {
        return this.writeKey.publicKey
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
    EccKeys,
    importPublicKey
}

