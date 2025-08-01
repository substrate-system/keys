import { AbstractKeys } from '../_base.js'
import { webcrypto } from '@substrate-system/one-webcrypto'
import { fromString, toString, type SupportedEncodings } from 'uint8arrays'
import { AES, importAesKey } from '../aes/index.js'
import {
    DEFAULT_CHAR_SIZE,
    DEFAULT_SYMM_LENGTH,
    AES_GCM,
    IV_LENGTH,
} from '../constants.js'
import type {
    DID,
    Msg,
    SymmKeyLength,
    SymmKey,
    CharSize
} from '../types.js'
import {
    publicKeyToDid,
    getPublicKeyAsArrayBuffer,
    isCryptoKey,
    normalizeUnicodeToBuf,
    importKey,
    randomBuf,
    joinBufs,
    normalizeToBuf,
    rsaOperations,
    base64ToArrBuf,
    toBase64
} from '../util.js'

export { publicKeyToDid, getPublicKeyAsArrayBuffer }
export * from '../constants.js'
export type { DID }
export { getPublicKeyAsUint8Array } from '../util.js'
export type SerializedKeys = {
    DID:DID;
    publicEncryptKey:string;
}

export class RsaKeys extends AbstractKeys {
    get publicExchangeKey ():CryptoKey {
        return this.exchangeKey.publicKey
    }

    get publicWriteKey ():CryptoKey {
        return this.writeKey.publicKey
    }

    /**
     * Sign the message, and return the signature as a `Uint8Array`.
     */
    async sign (
        msg:Msg,
        charsize:CharSize = DEFAULT_CHAR_SIZE
    ):Promise<Uint8Array> {
        const key = this.writeKey
        const sig = await rsaOperations.sign(
            msg,
            key.privateKey,
            charsize
        )

        return new Uint8Array(sig)
    }

    /**
     * Sign a message, return the signature as a base64 encoded string.
     */
    async signAsString (msg:Msg, charsize?:CharSize):Promise<string> {
        const sig = await this.sign(msg, charsize)
        return toBase64(sig)
    }

    /**
     * Encrypt content using hybrid encryption (RSA + AES).
     */
    async encrypt (
        content:string|Uint8Array,
        recipient?:CryptoKey|string,
        _info?:string,  // RSA doesn't use info, but kept for interface compatibility
        aesKey?:SymmKey|Uint8Array|string,
        keysize?:SymmKeyLength
    ):Promise<Uint8Array> {
        const publicKey = recipient || this.exchangeKey.publicKey
        const key = aesKey || await AES.create({ length: keysize })
        const encryptedContent = await AES.encrypt(
            typeof content === 'string' ? fromString(content) : content,
            typeof key === 'string' ? await AES.import(key) : key,
        )
        const encryptedKey = await encryptKeyTo({ key, publicKey })

        const result = joinBufs(encryptedKey, encryptedContent)
        return new Uint8Array(result)
    }

    /**
     * Encrypt and return as base64 string.
     */
    async encryptAsString (
        content:string|Uint8Array,
        recipient?:CryptoKey|string,
        _info?:string,  // RSA doesn't use info, but kept for interface compatibility
        aesKey?:SymmKey|Uint8Array|string,
        keysize?:SymmKeyLength
    ):Promise<string> {
        const encrypted = await this.encrypt(content, recipient, _info, aesKey, keysize)
        return toString(encrypted, 'base64pad')
    }

    /**
     * Decrypt the given message. Expects encrypted AES key + encrypted content.
     */
    async decrypt (
        msg:string|Uint8Array|ArrayBuffer,
        keysize?:CryptoKey|string|SymmKeyLength,
        _aesAlgorithm?:string,
    ):Promise<Uint8Array> {
        // For RSA, the second parameter is keysize, not publicKey
        const keysizeValue = (typeof keysize === 'number' ? keysize : undefined) || DEFAULT_SYMM_LENGTH
        const cipherText = normalizeToBuf(msg, base64ToArrBuf)
        const key = cipherText.slice(0, keysizeValue)
        const data = cipherText.slice(keysizeValue)
        const decryptedKey = await this.decryptKey(key)
        const decryptedContent = await AES.decrypt(data, decryptedKey)
        return decryptedContent
    }

    /**
     * Decrypt and return as string.
     */
    async decryptAsString (
        msg:string|Uint8Array|ArrayBuffer,
        keysize?:CryptoKey|string|SymmKeyLength,
        _aesAlgorithm?:string,
    ):Promise<string> {
        const dec = await this.decrypt(msg, keysize, _aesAlgorithm)
        return toString(dec)
    }

    /**
     * Decrypt the given encrypted AES key.
     * Return the key as `Uint8Array`.
     */
    async decryptKey (key:string|Uint8Array|ArrayBuffer):Promise<Uint8Array> {
        const decrypted = await rsaOperations.decrypt(
            key,
            this.exchangeKey.privateKey
        )
        return decrypted
    }

    /**
     * Decrypt the given AES key, return the result as a string.
     */
    async decryptKeyAsString (
        msg:string|Uint8Array,
        format?:SupportedEncodings
    ):Promise<string> {
        const decrypted = await rsaOperations.decrypt(
            msg,
            this.exchangeKey.privateKey
        )

        return toString(decrypted, format)
    }

    /**
     * Get the relevant AES key for RSA - decrypt the given encrypted key.
     */
    async getAesKey (
        encryptedKey?:CryptoKey|string|null,
        _info?:string|null
    ):Promise<CryptoKey> {
        if (!encryptedKey) {
            // For RSA, we need an encrypted key to decrypt
            throw new Error('RSA requires an encrypted AES key to decrypt')
        }

        if (typeof encryptedKey === 'string') {
            const decryptedKeyData = await this.decryptKey(encryptedKey)
            return await AES.import(decryptedKeyData)
        } else {
            // If it's already a CryptoKey, return it
            return encryptedKey
        }
    }
}

// Add backward compatibility by attaching asString methods to prototypes
Object.assign(RsaKeys.prototype.sign, {
    asString: async function (
        this: RsaKeys,
        msg: Msg,
        charsize?: CharSize
    ): Promise<string> {
        return this.signAsString(msg, charsize)
    }
})

Object.assign(RsaKeys.prototype.encrypt, {
    asString: async function (
        this: RsaKeys,
        content: string | Uint8Array,
        recipient?: CryptoKey | string,
        aesKey?: SymmKey | Uint8Array | string,
        keysize?: SymmKeyLength
    ): Promise<string> {
        // RSA doesn't use info parameter, so we pass undefined
        return this.encryptAsString(content, recipient, undefined, aesKey, keysize)
    }
})

Object.assign(RsaKeys.prototype.decrypt, {
    asString: async function (
        this: RsaKeys,
        msg: string | Uint8Array | ArrayBuffer,
        keysize?: SymmKeyLength
    ): Promise<string> {
        return this.decryptAsString(msg, keysize)
    }
})

Object.assign(RsaKeys.prototype.decryptKey, {
    asString: async function (
        this: RsaKeys,
        msg: string | Uint8Array,
        format?: SupportedEncodings
    ): Promise<string> {
        return this.decryptKeyAsString(msg, format)
    }
})

/**
 * Encrypt the given message to the given public key. If an AES key is not
 * provided, one will be created. Use an AES key to encrypt the given
 * content, then we encrypt the AES key to the given public key.
 *
 * @param {{ content, publicKey }} opts The content to encrypt and
 * public key to encrypt to
 * @param {SymmKey|Uint8Array|string} [aesKey] An optional AES key to encrypt
 * to the given public key
 * @returns {Promise<ArrayBuffer>} The encrypted AES key, concattenated with
 *   the encrypted content.
 */
export async function encryptTo (
    opts:{
        content:string|Uint8Array;
        publicKey:CryptoKey|string;
    },
    aesKey?:SymmKey|Uint8Array|string,
):Promise<ArrayBuffer> {
    const { content, publicKey } = opts
    const key = aesKey || await AES.create()
    const encryptedContent = await AES.encrypt(
        typeof content === 'string' ? fromString(content) : content,
        typeof key === 'string' ? await AES.import(key) : key,
    )
    const encryptedKey = await encryptKeyTo({ key, publicKey })

    return joinBufs(encryptedKey, encryptedContent)
}

/**
 * Encrypt the given AES key to the given public key. Return the encrypted AES
 * key concattenated with the cipher text.
 *
 * @param { content, publicKey } opts The content to encrypt and key to
 *   encrypt to.
 * @param {SymmKey|Uint8Array|string} [aesKey] Optional -- the AES key. One will
 *   be created if not passed in.
 * @returns {Promise<string>} The encrypted AES key concattenated with the
 *   cipher text.
 */
encryptTo.asString = async function (
    opts:{ content:string|Uint8Array; publicKey:CryptoKey|string },
    aesKey?:SymmKey|Uint8Array|string
):Promise<string> {
    const { content, publicKey } = opts
    const key = aesKey || await AES.create()
    const encryptedContent = await AES.encrypt(
        typeof content === 'string' ? fromString(content) : content,
        typeof key === 'string' ? await AES.import(key) : key,
        'arraybuffer'
    )

    const encryptedKey = await encryptKeyTo({ key, publicKey })
    const joined = joinBufs(encryptedKey, encryptedContent)

    return toString(new Uint8Array(joined), 'base64pad')
}

// export const AES = {
//     create (opts:{ alg:string, length:number } = {
//         alg: DEFAULT_SYMM_ALGORITHM,
//         length: DEFAULT_SYMM_LENGTH
//     }):Promise<CryptoKey> {
//         return webcrypto.subtle.generateKey({
//             name: opts.alg,
//             length: opts.length
//         }, true, ['encrypt', 'decrypt'])
//     },

//     export: Object.assign(
//         async (key:CryptoKey):Promise<Uint8Array> => {
//             const raw = await webcrypto.subtle.exportKey('raw', key)
//             return new Uint8Array(raw)
//         },

//         {
//             asString: async (key:CryptoKey, format?:SupportedEncodings) => {
//                 const raw = await AES.export(key)
//                 return format ? toString(raw, format) : toBase64(raw)
//             }
//         }
//     ),

//     import (key:Uint8Array|string):Promise<CryptoKey> {
//         return importAesKey(typeof key === 'string' ? base64ToArrBuf(key) : key)
//     },

//     async exportAsString (key:CryptoKey):Promise<string> {
//         const raw = await AES.export(key)
//         return toBase64(raw)
//     },

//     encrypt,

//     async decrypt (
//         encryptedData:Uint8Array|string|ArrayBuffer,
//         cryptoKey:CryptoKey|Uint8Array|ArrayBuffer,
//         iv?:Uint8Array
//     ):Promise<Uint8Array> {
//         const key = (isCryptoKey(cryptoKey) ?
//             cryptoKey :
//             await importAesKey(cryptoKey))

//         // the `iv` is prefixed to the cipher text
//         const decrypted = (iv ?
//             await webcrypto.subtle.decrypt(
//                 {
//                     name: AES_GCM,
//                     iv
//                 },
//                 key,
//                 (typeof encryptedData === 'string' ?
//                     fromString(encryptedData) :
//                     encryptedData)
//             ) :

//             await decryptBytes(encryptedData, key))

//         return new Uint8Array(decrypted)
//     },
// }

export async function encryptKeyTo ({ key, publicKey }:{
    key:string|Uint8Array|CryptoKey;
    publicKey:CryptoKey|Uint8Array|string;
}, format:'arraybuffer'):Promise<ArrayBuffer>

export async function encryptKeyTo ({ key, publicKey }:{
    key:string|Uint8Array|CryptoKey;
    publicKey:CryptoKey|Uint8Array|string;
}, format:'uint8array'):Promise<Uint8Array>

export async function encryptKeyTo ({ key, publicKey }:{
    key:string|Uint8Array|CryptoKey;
    publicKey:CryptoKey|Uint8Array|string;
}, format?:undefined):Promise<Uint8Array>

/**
 * Encrypt the given content to the given public key. This is RSA encryption,
 * and should be used only to encrypt AES keys.
 *
 * @param {{ content, publicKey }} params The content to encrypt, and public key
 * to encrypt it to.
 * @returns {Promise<Uint8Array>}
 */
export async function encryptKeyTo ({ key, publicKey }:{
    key:string|Uint8Array|CryptoKey;
    publicKey:CryptoKey|Uint8Array|string;
}, format?:'uint8array'|'arraybuffer'):Promise<Uint8Array|ArrayBuffer> {
    let _key:Uint8Array|string
    if (key instanceof CryptoKey) {
        _key = await AES.export(key)
    } else {
        _key = key
    }

    const buf = await rsaOperations.encrypt(_key, publicKey)
    if (format && format === 'arraybuffer') return buf
    return new Uint8Array(buf)
}

encryptKeyTo.asString = async function ({ key, publicKey }:{
    key:string|Uint8Array|CryptoKey;
    publicKey:CryptoKey|string|Uint8Array;
}, format?:SupportedEncodings):Promise<string> {
    const asArr = await encryptKeyTo({ key, publicKey })
    return format ? toString(asArr, format) : toBase64(asArr)
}

export async function encrypt (
    data:Uint8Array,
    cryptoKey:CryptoKey|Uint8Array,
    format?:undefined,
    iv?:Uint8Array
):Promise<Uint8Array>

export async function encrypt (
    data:Uint8Array,
    cryptoKey:CryptoKey|Uint8Array,
    format:'uint8array',
    iv?:Uint8Array
):Promise<Uint8Array>

export async function encrypt (
    data:Uint8Array,
    cryptoKey:CryptoKey|Uint8Array,
    format:'arraybuffer',
    iv?:Uint8Array
):Promise<ArrayBuffer>

/**
 * Encrypt the given data
 */
export async function encrypt (
    data:Uint8Array,
    cryptoKey:CryptoKey|Uint8Array,
    format?:'uint8array'|'arraybuffer',
    iv?:Uint8Array
):Promise<Uint8Array|ArrayBuffer> {
    // get a crypto key
    const key = (isCryptoKey(cryptoKey) ?
        cryptoKey :
        await importAesKey(cryptoKey)
    )

    // prefix the `iv` into the cipher text
    const encrypted = (iv ?
        await webcrypto.subtle.encrypt({ name: AES_GCM, iv }, key, data) :
        await encryptBytes(data, key)
    )

    if (format && format === 'arraybuffer') return encrypted

    return new Uint8Array(encrypted)
}

async function encryptBytes (
    msg:Msg,
    key:CryptoKey|string,
    opts?:Partial<{ iv:ArrayBuffer, charsize:number }>
):Promise<ArrayBuffer> {
    const data = normalizeUnicodeToBuf(msg, opts?.charsize ?? DEFAULT_CHAR_SIZE)
    const importedKey = typeof key === 'string' ?
        await importKey(key, opts) :
        key
    const iv:ArrayBuffer = opts?.iv || randomBuf(IV_LENGTH)
    const cipherBuf = await webcrypto.subtle.encrypt({
        name: AES_GCM,
        iv
    }, importedKey, data)

    // prefix the `iv` to the ciphertext
    return joinBufs(iv, cipherBuf)
}
