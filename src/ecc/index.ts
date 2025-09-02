import { webcrypto } from '@substrate-system/one-webcrypto'
import { type SupportedEncodings, toString } from 'uint8arrays'
import {
    DEFAULT_ECC_EXCHANGE,
    DEFAULT_ECC_WRITE,
    ECC_EXCHANGE_ALG,
    ECC_WRITE_ALG,
    DEFAULT_SYMM_ALGORITHM,
    SALT_LENGTH,
    IV_LENGTH,
    DEFAULT_SYMM_LENGTH,
    ECC_WRITE_NAME,
    ECC_EXCHANGE_NAME
} from '../constants.js'
import {
    EccCurve,
    KeyUse,
    type PublicKey,
    type SymmKeyLength,
    type SymmKey,
    type Msg,
    type CharSize,
    type DID,
} from '../types.js'
import {
    base64ToArrBuf,
    normalizeToBuf,
    toBase64,
    didToPublicKey
} from '../util.js'
import { checkValidKeyUse } from '../errors.js'
import {
    AbstractKeys,
    type KeyArgs
} from '../_base.js'

// Helper function to ensure proper ArrayBuffer type
function toArrayBuffer (data: Uint8Array): ArrayBuffer {
    return new Uint8Array(data).buffer
}

/**
 * Class for ECC keys
 */
export class EccKeys extends AbstractKeys {
    static TYPE:'ecc'|'rsa' = 'ecc' as const
    static EXCHANGE_KEY_NAME:string = DEFAULT_ECC_EXCHANGE
    static WRITE_KEY_NAME:string = DEFAULT_ECC_WRITE
    static INFO = 'keys'

    constructor (opts:KeyArgs) {
        super(opts)
        EccKeys.EXCHANGE_KEY_NAME = opts.exchangeKeyName || DEFAULT_ECC_EXCHANGE
        EccKeys.WRITE_KEY_NAME = opts.writeKeyName || DEFAULT_ECC_WRITE
    }

    get publicExchangeKey () {
        const publicKey = this.exchangeKey.publicKey
        return Object.assign(publicKey, {
            asString: async (format?: SupportedEncodings): Promise<string> => {
                const arrayBuffer = await exportPublicKey(this.exchangeKey)
                const uint8Array = new Uint8Array(arrayBuffer)
                return format ? toString(uint8Array, format) : toBase64(arrayBuffer)
            }
        })
    }

    get publicWriteKey () {
        const publicKey = this.writeKey.publicKey
        return Object.assign(publicKey, {
            asString: async (format?: SupportedEncodings): Promise<string> => {
                const arrayBuffer = await exportPublicKey(this.writeKey)
                const uint8Array = new Uint8Array(arrayBuffer)
                return format ? toString(uint8Array, format) : toBase64(arrayBuffer)
            }
        })
    }

    static async _createExchangeKeys ():Promise<CryptoKeyPair> {
        /**
         * don’t use `{ name: ECDH, namedCurve: 'X25519' }`, use
         * `{ name: 'X25519' }`.
         *
         * X25519/Ed25519 don't use `namedCurve`.
         */
        return await webcrypto.subtle.generateKey(
            {
                name: ECC_EXCHANGE_NAME
                // namedCurve: EccCurve.X25519
            },
            false,  // not extractable
            ['deriveKey', 'deriveBits']
        ) as CryptoKeyPair
    }

    static async _createWriteKeys ():Promise<CryptoKeyPair> {
        return await webcrypto.subtle.generateKey(
            {
                name: ECC_WRITE_NAME
            },
            false, // not extractable
            ['sign', 'verify']
        )
    }

    /**
     * Restore some keys from indexedDB, or create a new keypair if it doesn't
     * exist yet. Overrides base class to use ECC-specific key names.
     */
    static async load<T extends EccKeys = EccKeys> (
        this:typeof EccKeys,
        opts:Partial<{
            encryptionKeyName:string,
            signingKeyName:string,
            session:boolean,
        }> = {
            session: false,
        }
    ):Promise<T> {
        if (this._instance) return this._instance as T  // cache

        // Use ECC-specific key names as defaults
        const exchangeKeyName = opts.encryptionKeyName || DEFAULT_ECC_EXCHANGE
        const writeKeyName = opts.signingKeyName || DEFAULT_ECC_WRITE

        return super.load({
            ...opts,
            encryptionKeyName: exchangeKeyName,
            signingKeyName: writeKeyName
        }) as Promise<T>
    }

    /**
     * Serialize this keys instance. Will return an object of
     * { DID, publicExchangeKey }, where DID is the public write key,
     * and `publicExchangeKey` is the encryption key, `base64` encoded.
     * @returns {Promise<{ DID:DID, publicEncryptKey:string }>}
     */
    async toJson (
        format?:SupportedEncodings
    ):Promise<{ DID:DID; publicExchangeKey:string; }> {
        const did = this.DID

        const rawKey = await exportPublicKey(this.exchangeKey)

        const keyString = (format ?
            toString(new Uint8Array(rawKey), format) :
            toBase64(rawKey))

        return {
            publicExchangeKey: keyString,
            DID: did
        }
    }

    /**
     * Encrypt the given content to the given public key, or encrypt to
     * our public key if it is not passed in.
     *
     * @param {string|Uint8Array} content Content to encrypt
     * @param {CryptoKey|string} [recipient] Their public key. Optional b/c we
     *        will use our own public key if not passed in.
     * @param {string} [info] info tag for HKDF. Default is the class property.
     * @param {SymmKey|Uint8Array|string} aesKey This is not relevant for most
     *        use cases.
     * @param {SymmKeyLength} [keysize] Default is 256
     * @returns {Promise<ArrayBuffer>} Buffer of salt + iv + cipher text
     */
    async encrypt (
        content:string|Uint8Array,
        recipient?:CryptoKey|string,  // their public key
        info?:string,
        aesKey?:SymmKey|Uint8Array|string,
        keysize?:SymmKeyLength
    ):Promise<Uint8Array> {
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
            toArrayBuffer(plaintext)
        )

        // Prepend salt and IV to the ciphertext for decryption
        const saltBuffer = new Uint8Array(salt)
        const ivBuffer = new Uint8Array(iv)
        const cipherBuf = new Uint8Array(ciphertext)
        const size = saltBuffer.length + ivBuffer.length + cipherBuf.length
        const result = new Uint8Array(size)
        result.set(saltBuffer, 0)
        result.set(ivBuffer, saltBuffer.length)
        result.set(cipherBuf, saltBuffer.length + ivBuffer.length)

        return result
    }

    /**
     * Encrypt and return as base64 string.
     */
    async encryptAsString (
        content:string|Uint8Array,
        recipient?:CryptoKey|string,  // their public key
        info?:string,
        aesKey?:SymmKey|Uint8Array|string,
        keysize?:SymmKeyLength,
    ):Promise<string> {
        const encrypted = await this.encrypt(
            content,
            recipient,
            info || EccKeys.INFO,
            aesKey,
            keysize
        )

        return toString(new Uint8Array(encrypted), 'base64pad')
    }

    /**
     * Decrypt the given message. The encrypted message should be
     * salt + iv + cipher text.
     * @param msg The encrypted content
     * @param {CryptoKey|string} [publicKey] The public key used to generate
     * the AES key used on this message. If omitted, decrypt with our own
     * public key.
     * @param {string} aesAlgorithm The algorithm. Default is AES-GCM.
     * @param {string} info Custom "info" parameter
     * @returns {Promise<ArrayBuffer>} The decrypted content.
     */
    async decrypt (
        msg:string|Uint8Array|ArrayBuffer,
        publicKey?:CryptoKey|string,
        aesAlgorithm?:string,
        info?:string,
    ):Promise<ArrayBuffer|Uint8Array> {
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
            info || EccKeys.INFO
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
    }

    /**
     * Decrypt and return as string.
     * The encrypted message should be salt + iv + cipher text.
     *
     * @param msg The encrypted content
     * @param {CryptoKey|string} [publicKey] The public key used to generate
     * the AES key used on this message. If omitted, decrypt with our own
     * public key.
     * @param {string} aesAlgorithm The algorithm. Default is AES-GCM.
     * @param {string} info Custom "info" parameter
     * @returns {Promise<ArrayBuffer>} The decrypted content.
     */
    async decryptAsString (
        msg:string|Uint8Array|ArrayBuffer,
        publicKey?:CryptoKey|string,
        aesAlgorithm?:string,
        info?:string,
    ):Promise<string> {
        const dec = await this.decrypt(msg, publicKey, aesAlgorithm, info)
        return toString(new Uint8Array(dec))
    }

    /**
     * Do DHKE, create a new AES-GCM key.
     *
     * @param {CryptoKey|string|null} [publicKey] Public key to use in DHKE.
     *        Will use our public key if it is not passed in.
     * @param {string} info The info parameter for DHKE. Will use the class
     *        property `INFO` if it is not passed in.
     * @returns {CryptoKey} New AES key
     */
    async getAesKey (
        publicKey?:CryptoKey|string|null,
        info?:string|null,
    ):Promise<CryptoKey> {
        if (!publicKey) {
            publicKey = this.publicExchangeKey
        }

        let pub:CryptoKey
        if (typeof publicKey === 'string') {
            pub = await importPublicKey(
                publicKey,
                EccCurve.X25519,
                KeyUse.Exchange
            )
        } else {
            pub = publicKey
        }

        // Generate a random salt for HKDF
        const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH))

        // Derive AES key using ECDH + HKDF
        const aesKey = await deriveKey(
            this.exchangeKey.privateKey,
            pub,
            salt,
            info || EccKeys.INFO
        )

        return aesKey
    }

    /**
     * Sign the given content using our private write key.
     */
    async sign (msg:Msg, _charsize?:CharSize):Promise<Uint8Array> {
        const encoder = new TextEncoder()
        let data:Uint8Array

        if (typeof msg === 'string') {
            data = encoder.encode(msg)
        } else if (msg instanceof ArrayBuffer) {
            data = new Uint8Array(msg)
        } else {
            data = msg
        }

        const signature = await webcrypto.subtle.sign(
            { name: ECC_WRITE_ALG },
            this.writeKey.privateKey,
            toArrayBuffer(data)
        )

        return new Uint8Array(signature)
    }

    /**
     * Sign the given content and return as base64 string.
     */
    async signAsString (msg:string, _charsize?:CharSize):Promise<string> {
        const signature = await this.sign(msg, _charsize)
        return toString(signature, 'base64pad')
    }
}

// Attach asString to the prototype method for backward compatibility
Object.assign(EccKeys.prototype.sign, {
    asString: async function (
        this:EccKeys,
        msg:string,
        _charsize?:CharSize
    ):Promise<string> {
        const signature = await this.sign(msg, _charsize)
        return toString(signature, 'base64pad')
    }
})

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

    // X25519 doesn't use namedCurve in the algorithm parameter
    const algorithm = (curve === EccCurve.X25519) ?
        { name: alg } :
        { name: alg, namedCurve: curve }

    return webcrypto.subtle.importKey(
        'raw',
        buf,
        algorithm,
        true,
        uses
    )
}

export default {
    EccKeys,
    importPublicKey
}

// Add backward compatibility by attaching asString methods to prototypes
Object.assign(EccKeys.prototype.encrypt, {
    asString: async function (
        this: EccKeys,
        content: string | Uint8Array,
        recipient?: CryptoKey | string,
        info?: string,
        aesKey?: SymmKey | Uint8Array | string,
        keysize?: SymmKeyLength
    ): Promise<string> {
        return this.encryptAsString(content, recipient, info, aesKey, keysize)
    }
})

Object.assign(EccKeys.prototype.decrypt, {
    asString: async function (
        this: EccKeys,
        msg: string | Uint8Array | ArrayBuffer,
        publicKey?: CryptoKey | string,
        aesAlgorithm?: string
    ): Promise<string> {
        return this.decryptAsString(msg, publicKey, aesAlgorithm)
    }
})

Object.assign(EccKeys.prototype.sign, {
    asString: async function (
        this: EccKeys,
        msg: string,
        _charsize?: CharSize
    ): Promise<string> {
        return this.signAsString(msg, _charsize)
    }
})

/**
 * Check that the given signature is valid with the given message.
 * This uses Ed25519 verification.
 */
export async function verify (
    msg:string|Uint8Array,
    sig:string|Uint8Array,
    signingDid:DID
):Promise<boolean> {
    try {
        const _key = didToPublicKey(signingDid)

        // Verify it's an Ed25519 key
        if (_key.type !== 'ed25519') {
            throw new Error(`Expected Ed25519 key for ECC verification, got ${_key.type}`)
        }

        // Extract raw Ed25519 key from DER encoding
        // DER format has 12-byte header, then 32-byte raw key
        const rawKeyBytes = _key.publicKey.slice(-32)

        // Import the public key for verification
        const publicKey = await webcrypto.subtle.importKey(
            'raw',
            rawKeyBytes,
            { name: ECC_WRITE_ALG },
            true,
            ['verify']
        )

        // Prepare the message using the same encoding as the sign function
        const encoder = new TextEncoder()
        let data:Uint8Array

        if (typeof msg === 'string') {
            data = encoder.encode(msg)
        } else if (msg instanceof ArrayBuffer) {
            data = new Uint8Array(msg)
        } else {
            data = msg
        }

        // Prepare the signature - handle both string and Uint8Array
        let signature:Uint8Array
        if (typeof sig === 'string') {
            signature = new Uint8Array(base64ToArrBuf(sig))
        } else {
            signature = sig
        }

        // Verify the signature
        const isValid = await webcrypto.subtle.verify(
            { name: ECC_WRITE_ALG },
            publicKey,
            toArrayBuffer(signature),
            toArrayBuffer(data)
        )

        return isValid
    } catch (_err) {
        return false
    }
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
        { name: 'X25519', public: publicKey },
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
            salt: salt instanceof Uint8Array ? toArrayBuffer(salt) : salt,
            info: encoder.encode(info)
        },
        hkdfBaseKey,
        { name: 'AES-GCM', length: keysize || DEFAULT_SYMM_LENGTH },
        false,
        ['encrypt', 'decrypt']
    )
}
