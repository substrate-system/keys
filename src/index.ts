import { webcrypto } from '@bicycle-codes/one-webcrypto'
import {
    RSA_ALGORITHM,
    DEFAULT_RSA_SIZE,
    DEFAULT_HASH_ALGORITHM,
    RSA_SIGN_ALGORITHM
} from './constants'
import {
    KeyUse,
    type RsaSize,
    type HashAlg,
    type DID
} from './types'
import Debug from '@bicycle-codes/debug'
const debug = Debug()

/**
 * Expose RSA keys only for now, because we are
 * waiting for more browsers to support ECC.
 */
export class Keys {
    encrypt:CryptoKeyPair
    sign:CryptoKeyPair

    constructor (keys:{ encrypt:CryptoKeyPair, sign:CryptoKeyPair }) {
        this.encrypt = keys.encrypt
        this.sign = keys.sign
    }

    static async create ():Promise<Keys> {
        const encryptionKeypair = await makeRSAKeypair(
            DEFAULT_RSA_SIZE,
            DEFAULT_HASH_ALGORITHM,
            KeyUse.Encrypt
        )
        const signingKeypair = await makeRSAKeypair(
            DEFAULT_RSA_SIZE,
            DEFAULT_HASH_ALGORITHM,
            KeyUse.Sign
        )

        const keys = new Keys({
            encrypt: encryptionKeypair,
            sign: signingKeypair
        })

        const rootDID = await writeKeyToDid(signingKeypair)

        debug('create new keys', keys)

        return keys
    }
}

async function makeRSAKeypair (
    size:RsaSize,
    hashAlg:HashAlg,
    use:KeyUse
):Promise<CryptoKeyPair> {
    if (!(Object.values(KeyUse).includes(use))) {
        throw new Error('invalid key use')
    }
    const alg = use === KeyUse.Encrypt ? RSA_ALGORITHM : RSA_SIGN_ALGORITHM
    const uses:KeyUsage[] = (use === KeyUse.Encrypt ?
        ['encrypt', 'decrypt'] :
        ['sign', 'verify'])

    return webcrypto.subtle.generateKey({
        name: alg,
        modulusLength: size,
        publicExponent: publicExponent(),
        hash: { name: hashAlg }
    }, false, uses)
}

function publicExponent ():Uint8Array {
    return new Uint8Array([0x01, 0x00, 0x01])
}

/**
 * "write" key is for signing things
 *
 * @param {CryptoKeyPair} publicWriteKey This device's write key.
 * @returns {Promise<DID>}
 */
export async function writeKeyToDid (
    publicWriteKey:CryptoKeyPair
):Promise<DID> {
    const arr = await getPublicKeyAsArrayBuffer(publicWriteKey)
    const ksAlg = 'rsa'

    return publicKeyToDid(new Uint8Array(arr), ksAlg)
}
