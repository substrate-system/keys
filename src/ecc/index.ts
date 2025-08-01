import { webcrypto } from '@substrate-system/one-webcrypto'
import {
    DEFAULT_ECC_EXCHANGE,
    DEFAULT_ECC_WRITE,
    ECC_EXCHANGE_ALG,
    ECC_WRITE_ALG,
    DEFAULT_SYMM_ALGORITHM,
    SALT_LENGTH,
    IV_LENGTH,
    DEFAULT_SYMM_LENGTH,
} from '../constants.js'
import {
    EccCurve,
    KeyUse,
    type PublicKey,
    type SymmKeyLength,
    type SymmKey
} from '../types.js'
import {
    base64ToArrBuf,
    normalizeToBuf
} from '../util.js'
import { checkValidKeyUse } from '../errors.js'
import { AbstractKeys, type EccEncryptor, type KeyArgs } from '../_base.js'
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

    static INFO = 'example'

    /**
     * If no recipient is passed in, then this will encrypt to itself
     * (a note to self).
     */
    encrypt:EccEncryptor = Object.assign(
        /**
         * Encrypt the given content to the given public key, or encrypt to
         * our public key if it is not passedd in.
         *
         * @param content Content to encrypt
         * @param info info tag for HKDF
         * @param recipient Their public key. Optional b/c we will use our own
         *                  public key if not passed in.
         * @param aesKey The AES key to use for encryption. This is not relevant
         *               for most use cases.
         * @returns {Promise<ArrayBuffer>} Buffer of encrypted content.
         */
        async (
            content:string|Uint8Array,
            recipient?:CryptoKey|string,  // their public key
            info?:string,
            aesKey?:SymmKey|Uint8Array|string,
            keysize?:SymmKeyLength
        ):Promise<ArrayBuffer> => {
            const encoder = new TextEncoder()
            const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH))

            // publicKey is either passed in or we use our own for note to self
            const _publicKey = (recipient || this.exchangeKey.publicKey)
            let publicKey:CryptoKey
            if (typeof _publicKey === 'string') {
                publicKey = await importPublicKey(
                    _publicKey,
                    EccCurve.X25519,
                    KeyUse.Exchange
                )
            } else {
                publicKey = _publicKey
            }

            // key is passed in or derived
            let key = aesKey || (await deriveKey(
                this.exchangeKey.privateKey,
                publicKey,
                salt,
                info || EccKeys.INFO,
                keysize
            ))

            // if a key was passed in, but it is not a CryptoKey instance
            if (!(key instanceof CryptoKey)) {
                key = await deriveKey(
                    this.exchangeKey.privateKey,
                    publicKey,
                    salt,
                    info || EccKeys.INFO
                )
            }
            const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH))
            const plaintext:Uint8Array = (typeof content === 'string' ?
                encoder.encode(content) :
                content)

            const ciphertext = await crypto.subtle.encrypt(
                { name: DEFAULT_SYMM_ALGORITHM, iv },
                key,
                plaintext
            )

            return ciphertext
        },

        {
            asString: async (
                msg:string|Uint8Array,
                recipient?:CryptoKey|string,  // their public key
                info?:string,
                aesKey?:SymmKey|Uint8Array|string,
                keysize?:SymmKeyLength,
            ):Promise<string> => {
                const encrypted = await this.encrypt(
                    msg,
                    recipient,
                    info || EccKeys.INFO,
                    aesKey,
                    keysize
                )

                return toString(new Uint8Array(encrypted), 'base64pad')
            }
        }
    )

    decrypt = Object.assign(
        /**
         * The given message should have salt + iv + cipher text.
         */
        async (
            msg:string|Uint8Array|ArrayBuffer,
            publicKey?:CryptoKey|string,
            aesAlgorithm?:string,
        ):Promise<ArrayBuffer> => {
            let pub = (typeof publicKey === 'string' ?
                await importPublicKey(publicKey, EccCurve.X25519, KeyUse.Write) :
                publicKey)

            if (!pub) pub = this.publicExchangeKey

            // first get the salt & iv from the cipher text
            const encrypted = normalizeToBuf(msg, base64ToArrBuf)
            const salt = encrypted.slice(0, SALT_LENGTH)
            const iv = encrypted.slice(SALT_LENGTH, SALT_LENGTH + IV_LENGTH)
            const ciphertext = encrypted.slice(SALT_LENGTH + IV_LENGTH)
            const { privateKey } = this.exchangeKey
            const key = await deriveKey(
                privateKey,
                pub,
                salt,
                EccKeys.INFO
            )

            // we have the key, now decrypt the message
            const decrypted = await crypto.subtle.decrypt(
                {
                    name: aesAlgorithm || DEFAULT_SYMM_ALGORITHM,
                    iv,
                },
                key,
                ciphertext
            )

            return decrypted
        },

        {
            asString: async (
                msg:string|Uint8Array|ArrayBuffer,
                publicKey?:CryptoKey|string,
                aesAlgorithm?:string,
            ):Promise<string> => {
                const dec = await this.decrypt(msg, publicKey, aesAlgorithm)
                return toString(new Uint8Array(dec))
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
 * Derive an AES key from X25519 keypair via ECDH + HKDF
 */
async function deriveKey (
    privateKey:CryptoKey,
    publicKey:CryptoKey,
    salt:Uint8Array|ArrayBuffer,
    info:string,
    keysize?:number
):Promise<CryptoKey> {
    const encoder = new TextEncoder()
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
        { name: 'AES-GCM', length: keysize || DEFAULT_SYMM_LENGTH },
        false,
        ['encrypt', 'decrypt']
    )
}

// /**
//  * Derive a symmetric key via HKDF.
//  */
// async function deriveSymmetricKey (
//     sharedSecret:CryptoKey,
//     salt:Uint8Array,
//     length = DEFAULT_SYMM_LENGTH
// ):Promise<CryptoKey> {
//     return crypto.subtle.deriveKey(
//         {
//             name: 'HKDF',
//             salt,
//             info: new Uint8Array([]),
//             hash: 'SHA-256',
//         },
//         sharedSecret,
//         { name: DEFAULT_SYMM_ALGORITHM, length },
//         false,
//         ['encrypt', 'decrypt']
//     )
// }
