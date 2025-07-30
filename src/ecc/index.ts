import { webcrypto } from '@substrate-system/one-webcrypto'
import {
    DEFAULT_ECC_EXCHANGE,
    DEFAULT_ECC_WRITE,
    ECC_EXCHANGE_ALG,
    ECC_WRITE_ALG,
    DEFAULT_SYMM_LENGTH,
    DEFAULT_SYMM_ALGORITHM
} from '../constants.js'
import {
    KeyUse,
    type EccCurve,
    type PublicKey,
    type SymmKeyLength
} from '../types.js'
import {
    base64ToArrBuf,
    normalizeToBuf
} from '../util.js'
import { checkValidKeyUse } from '../errors.js'
import { AbstractKeys, Encryptor, type KeyArgs } from '../_base.js'
import { toString } from 'uint8arrays'

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

    encrypt = Object.assign(
        async (
            content:string|Uint8Array,
            recipient?:CryptoKey|string,
            aesKey?:SymmKey|Uint8Array|string,
            keysize?:SymmKeyLength
        ) => {
            const ciphertext = await crypto.subtle.encrypt(
                { name: DEFAULT_SYMM_ALGORITHM, iv },
                key,
                encoder.encode(message)
            )
        },

        {
            asString: () => {

            }
        }
    )

    decrypt = Object.assign(
        /**
         * Expect the given cipher content to be the format returned by
         * encryptTo`. That is, encrypted AES key + `iv` + encrypted content.
         */
        async (
            msg:string|Uint8Array|ArrayBuffer,
            keysize?:SymmKeyLength
        ):Promise<Uint8Array> => {
            // const length = keysize || DEFAULT_SYMM_LENGTH
            // const cipherText = normalizeToBuf(msg, base64ToArrBuf)
            // const key = cipherText.slice(0, length)
            // const data = cipherText.slice(length)
            // const decryptedKey = await this.decryptKey(key)
            // const decryptedContent = await AES.decrypt(data, decryptedKey)
            // return decryptedContent

            // first get the symmetric key from the cipher text
            const length = keysize || DEFAULT_SYMM_LENGTH
            const encrypted = normalizeToBuf(msg, base64ToArrBuf)
            const salt = encrypted.slice(0, 16)
            const iv = encrypted.slice(16, 28)
            const ciphertext = encrypted.slice(28)
            const key = await deriveKey(privateKey, publicKey, salt)
        },

        {
            asString: async (msg:string, keysize?:SymmKeyLength):Promise<string> => {
                const dec = await this.decrypt(msg, keysize)
                return toString(dec)
            }
        }
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
    EccKeys,
    importPublicKey
}

/**
 * Derive AES key from X25519 keypair via ECDH + HKDF
 */
async function deriveKey (
    privateKey:CryptoKey,
    publicKey:CryptoKey,
    salt:Uint8Array,
    info:string
): Promise<CryptoKey> {
    const sharedSecret = await crypto.subtle.deriveBits(
        { name: 'ECDH', public: publicKey },
        privateKey,
        256
    )

    const hkdfBaseKey = await crypto.subtle.importKey(
        'raw',
        sharedSecret,
        'HKDF',
        false,
        ['deriveKey']
    )

    return crypto.subtle.deriveKey(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt,
            info: encoder.encode(info)
        },
        hkdfBaseKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    )
}

/**
 * Derive a symmetric key via HKDF.
 */
async function deriveSymmetricKey (
    sharedSecret:CryptoKey,
    salt:Uint8Array,
    length = DEFAULT_SYMM_LENGTH
):Promise<CryptoKey> {
    return crypto.subtle.deriveKey(
        {
            name: 'HKDF',
            salt,
            info: new Uint8Array([]),
            hash: 'SHA-256',
        },
        sharedSecret,
        { name: DEFAULT_SYMM_ALGORITHM, length },
        false,
        ['encrypt', 'decrypt']
    )
}
