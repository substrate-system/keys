import { webcrypto } from '@substrate-system/one-webcrypto'
import { toString, type SupportedEncodings, fromString } from 'uint8arrays'
import {
    toBase64,
    base64ToArrBuf,
    isCryptoKey,
    normalizeUnicodeToBuf,
    importKey,
    joinBufs,
    randomBuf,
    normalizeBase64ToBuf
} from '../util.js'
import { SymmKeyLength, type Msg, type SymmAlgorithm } from '../types.js'
import {
    DEFAULT_SYMM_ALGORITHM,
    DEFAULT_SYMM_LENGTH,
    AES_GCM,
    DEFAULT_CHAR_SIZE,
    IV_LENGTH
} from '../constants.js'

export const AES = {
    create (opts:{ alg?:string, length?:number } = {
        alg: DEFAULT_SYMM_ALGORITHM,
        length: DEFAULT_SYMM_LENGTH
    }):Promise<CryptoKey> {
        const length = opts.length || DEFAULT_SYMM_LENGTH
        const alg = opts.alg || DEFAULT_SYMM_ALGORITHM

        return webcrypto.subtle.generateKey({
            name: alg,
            length
        }, true, ['encrypt', 'decrypt'])
    },

    export: Object.assign(
        async (key:CryptoKey):Promise<Uint8Array> => {
            const raw = await webcrypto.subtle.exportKey('raw', key)
            return new Uint8Array(raw)
        },

        {
            asString: async (key:CryptoKey, format?:SupportedEncodings) => {
                const raw = await AES.export(key)
                return format ? toString(raw, format) : toBase64(raw)
            }
        }
    ),

    import (key:Uint8Array|string):Promise<CryptoKey> {
        return importAesKey(typeof key === 'string' ? base64ToArrBuf(key) : key)
    },

    async exportAsString (key:CryptoKey):Promise<string> {
        const raw = await AES.export(key)
        return toBase64(raw)
    },

    encrypt,

    async decrypt (
        encryptedData:Uint8Array|string|ArrayBuffer,
        cryptoKey:CryptoKey|Uint8Array|ArrayBuffer,
        iv?:Uint8Array
    ):Promise<Uint8Array> {
        const key = (isCryptoKey(cryptoKey) ?
            cryptoKey :
            await importAesKey(cryptoKey))

        // the `iv` is prefixed to the cipher text
        const decrypted = (iv ?
            await webcrypto.subtle.decrypt(
                {
                    name: AES_GCM,
                    iv
                },
                key,
                (typeof encryptedData === 'string' ?
                    fromString(encryptedData) :
                    encryptedData)
            ) :

            await decryptBytes(encryptedData, key))

        return new Uint8Array(decrypted)
    }
}

export function importAesKey (
    key:Uint8Array|ArrayBuffer,
    length?:number
):Promise<CryptoKey> {
    return webcrypto.subtle.importKey(
        'raw',
        key,
        {
            name: AES_GCM,
            length: length || SymmKeyLength.B256,
        },
        true,
        ['encrypt', 'decrypt']
    )
}

async function encrypt (
    data:Uint8Array,
    cryptoKey:CryptoKey|Uint8Array,
    format?:undefined,
    iv?:Uint8Array
):Promise<Uint8Array>

async function encrypt (
    data:Uint8Array,
    cryptoKey:CryptoKey|Uint8Array,
    format:'uint8array',
    iv?:Uint8Array
):Promise<Uint8Array>

async function encrypt (
    data:Uint8Array,
    cryptoKey:CryptoKey|Uint8Array,
    format:'arraybuffer',
    iv?:Uint8Array
):Promise<ArrayBuffer>

async function encrypt (
    data:Uint8Array,
    cryptoKey:CryptoKey|Uint8Array,
    format?:'uint8array'|'arraybuffer',
    iv?:Uint8Array
):Promise<Uint8Array|ArrayBuffer> {
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

    return joinBufs(iv, cipherBuf)
}

/**
 * Decrypt the given message with the given key. We expect the `iv` to be
 * prefixed to the encrypted message.
 *
 * @param msg The message to decrypt
 * @param key The key to decrypt with
 * @param opts Optional args for algorithm and stuff
 * @returns {Promise<ArrayBuffer>}
 */
async function decryptBytes (
    msg:Msg,
    key:CryptoKey|string,
    opts?:Partial<{
        alg:SymmAlgorithm;
        length: SymmKeyLength;
        iv: ArrayBuffer;
    }>
):Promise<ArrayBuffer> {
    const cipherText = normalizeBase64ToBuf(msg)
    const importedKey = typeof key === 'string' ?
        await importKey(key, opts) :
        key
    // `iv` is prefixed to the cypher text
    const iv = cipherText.slice(0, IV_LENGTH)
    const cipherBytes = cipherText.slice(IV_LENGTH)
    const msgBuff = await webcrypto.subtle.decrypt({
        name: DEFAULT_SYMM_ALGORITHM,
        iv
    }, importedKey, cipherBytes)

    return msgBuff
}
