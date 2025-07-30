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
import {
    type DID,
    type Msg,
    type SymmKeyLength,
    type SymmKey
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
     * Decrypt the given encrypted AES key.
     * Return the key as `Uint8Array`.
     */
    decryptKey = Object.assign(
        async (key:string|Uint8Array|ArrayBuffer):Promise<Uint8Array> => {
            const decrypted = await rsaOperations.decrypt(
                key,
                this.exchangeKey.privateKey
            )
            return decrypted
        },

        {
            /**
             * Decrypt the given AES key, return the result as a string.
             */
            asString: async (
                msg:string|Uint8Array,
                format?:SupportedEncodings
            ):Promise<string> => {
                const decrypted = await rsaOperations.decrypt(
                    msg,
                    this.exchangeKey.privateKey
                )

                return toString(decrypted, format)
            }
        }
    )

    encrypt = Object.assign(
        async (
            content:string|Uint8Array,
            recipient?:CryptoKey|string,
            aesKey?:SymmKey|Uint8Array|string,
            keysize?:SymmKeyLength
        ) => {
            const publicKey = recipient || this.exchangeKey.publicKey
            const key = aesKey || await AES.create({ length: keysize })
            const encryptedContent = await AES.encrypt(
                typeof content === 'string' ? fromString(content) : content,
                typeof key === 'string' ? await AES.import(key) : key,
            )
            const encryptedKey = await encryptKeyTo({ key, publicKey })

            return joinBufs(encryptedKey, encryptedContent)
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
            const length = keysize || DEFAULT_SYMM_LENGTH
            const cipherText = normalizeToBuf(msg, base64ToArrBuf)
            const key = cipherText.slice(0, length)
            const data = cipherText.slice(length)
            const decryptedKey = await this.decryptKey(key)
            const decryptedContent = await AES.decrypt(data, decryptedKey)
            return decryptedContent
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
//  * Class for ECC keys
//  */
// export class EccKeys extends AbstractKeys {
//     get publicExchangeKey ():CryptoKey {
//         return this.exchangeKey.publicKey
//     }

//     get publicWriteKey ():CryptoKey {
//         return this.writeKey.publicKey
//     }
// }

// /**
//  * Expose RSA keys only for now, because we are
//  * waiting for more browsers to support ECC.
//  *
//  * Create an instance with `Keys.create` b/c async.
//  */
// export class RsaKeys extends AbstractKeys {
//     static _instance  // a cache for indexedDB

//     constructor (opts:KeyArgs) {
//         // super(opts)
//         // const { keys } = opts
//         // this._encryptKey = keys.encrypt
//         // this._signKey = keys.sign
//         // this.DID = opts.did
//         // this.persisted = opts.persisted
//         // this.session = opts.session ?? false
//         // Keys._instance = this
//     }

//     get signKeypair ():CryptoKeyPair {
//         return {
//             privateKey: this.privateSignKey,
//             publicKey: this.publicSignKey
//         }
//     }

//     get encryptKeypair ():CryptoKeyPair {
//         return {
//             privateKey: this.privateEncryptKey,
//             publicKey: this.publicEncryptKey
//         }
//     }

//     get publicSignKey ():CryptoKey {
//         return this._signKey.publicKey
//     }

//     get privateSignKey ():CryptoKey {
//         return this._signKey.privateKey
//     }

//     get privateEncryptKey ():CryptoKey {
//         return this._encryptKey.privateKey
//     }

//     get publicEncryptKey ():CryptoKey {
//         return this._encryptKey.publicKey
//     }

//     get deviceName ():Promise<string> {
//         return Keys.deviceName(this.DID)
//     }

//     /**
//      * Delete the keys stored in indexedDB.
//      */
//     async delete ():Promise<void> {
//         await delMany([this.ENCRYPTION_KEY_NAME, this.SIGNING_KEY_NAME])
//         this.persisted = false
//     }

//     /**
//      * Get the public encryption key as a string.
//      *
//      * @param {SupportedEncodings} [format] Optional string format for
//      * `uint8arrays`. Defaults to base64.
//      * @returns {string} Return a string b/c mostly would use this for
//      * serializing the public encryption key.
//      */
//     getPublicEncryptKey = Object.assign(
//         async (format?:SupportedEncodings):Promise<string> => {
//             const { publicKey } = this._encryptKey
//             const spki = await webcrypto.subtle.exportKey(
//                 'spki',
//                 publicKey
//             )

//             return (format ?
//                 toString(new Uint8Array(spki), format) :
//                 toBase64(spki))
//         },

//         {
//             uint8Array: async ():Promise<Uint8Array> => {
//                 const { publicKey } = this._encryptKey
//                 const arr = await getPublicKeyAsUint8Array(publicKey)
//                 return arr
//             }
//         }
//     )

//     /**
//      * Return a 32-character, DNS-friendly hash of the given DID.
//      *
//      * @param {DID} did a DID format string
//      * @returns {string} 32 character, base32 hash of the DID
//      */
//     static deviceName (did:DID):Promise<string> {
//         return getDeviceName(did)
//     }

//     /**
//      * Factory function b/c async.
//      * Create a new `Keys` instance.
//      *
//      * @returns {Promise<Keys>}
//      */
//     static async create (
//         opts:{ session:boolean } = { session: false }
//     ):Promise<Keys> {
//         const encryptionKeypair = await makeRSAKeypair(
//             DEFAULT_RSA_SIZE,
//             DEFAULT_HASH_ALGORITHM,
//             KeyUse.Exchange
//         )
//         const signingKeypair = await makeRSAKeypair(
//             DEFAULT_RSA_SIZE,
//             DEFAULT_HASH_ALGORITHM,
//             KeyUse.Sign
//         )

//         const { session } = opts
//         const publicSigningKey = await getPublicKeyAsArrayBuffer(signingKeypair)
//         const did = await publicKeyToDid(new Uint8Array(publicSigningKey), 'rsa')

//         const keys = new Keys({
//             keys: { encrypt: encryptionKeypair, sign: signingKeypair },
//             did,
//             persisted: false,
//             session
//         })

//         return keys
//     }

//     /**
//      * Save this keys instance to `indexedDB`.
//      */
//     async persist ():Promise<void> {
//         if (this.session) return

//         await Promise.all([
//             set(this.ENCRYPTION_KEY_NAME, this._encryptKey),
//             set(this.SIGNING_KEY_NAME, this._signKey)
//         ])

//         this.persisted = true
//     }

//     /**
//      * Return a 32-character, DNS friendly hash of the public signing key.
//      *
//      * @returns {Promise<string>}
//      */
//     async getDeviceName ():Promise<string> {
//         return Keys.deviceName(this.DID)
//     }

//     /**
//      * Restore some keys from indexedDB, or create a new keypair if it doesn't
//      * exist yet.
//      *
//      * @param {{ encryptionKeyName, signingKeyName }} opts Strings to use as
//      * keys in indexedDB.
//      * @returns {Promise<Keys>}
//      */
//     static async load (opts:Partial<{
//         encryptionKeyName:string,
//         signingKeyName:string,
//         session:boolean,
//     }> = {
//         encryptionKeyName: DEFAULT_RSA_EXCHANGE,
//         signingKeyName: DEFAULT_RSA_WRITE,
//         session: false
//     }):Promise<InstanceType<typeof Keys>> {
//         if (Keys._instance) return Keys._instance  // cache

//         let persisted = true
//         let encKeys:CryptoKeyPair|undefined = await get(
//             opts.encryptionKeyName || DEFAULT_RSA_EXCHANGE
//         )
//         let signKeys:CryptoKeyPair|undefined = await get(
//             opts.signingKeyName || DEFAULT_RSA_WRITE
//         )

//         if (!encKeys) {
//             persisted = false
//             encKeys = await makeRSAKeypair(
//                 DEFAULT_RSA_SIZE,
//                 DEFAULT_HASH_ALGORITHM,
//                 KeyUse.Exchange
//             )
//         }
//         if (!signKeys) {
//             persisted = false
//             signKeys = await makeRSAKeypair(
//                 DEFAULT_RSA_SIZE,
//                 DEFAULT_HASH_ALGORITHM,
//                 KeyUse.Sign
//             )
//         }

//         const publicKey = await getPublicKeyAsArrayBuffer(signKeys)
//         const did = await publicKeyToDid(new Uint8Array(publicKey), 'rsa')

//         const keys = new Keys({
//             keys: { encrypt: encKeys, sign: signKeys },
//             did,
//             persisted,
//             session: opts.session ?? false
//         })

//         return keys
//     }

//     decrypt = Object.assign(
//         /**
//          * Expect the given cipher content to be the format returned by
//          * encryptTo`. That is, encrypted AES key + `iv` + encrypted content.
//          */
//         async (
//             msg:string|Uint8Array|ArrayBuffer,
//             keysize?:SymmKeyLength
//         ):Promise<Uint8Array> => {
//             const length = keysize || DEFAULT_SYMM_LENGTH
//             const cipherText = normalizeToBuf(msg, base64ToArrBuf)
//             const key = cipherText.slice(0, length)
//             const data = cipherText.slice(length)
//             const decryptedKey = await this.decryptKey(key)
//             const decryptedContent = await AES.decrypt(data, decryptedKey)
//             return decryptedContent
//         },

//         {
//             asString: async (msg:string, keysize?:SymmKeyLength):Promise<string> => {
//                 const dec = await this.decrypt(msg, keysize)
//                 return toString(dec)
//             }
//         }
//     )

//     sign = Object.assign(
//         /**
//          * Sign the message, and return the signature as a `Uint8Array`.
//          */
//         async (
//             msg:Msg,
//             charsize:CharSize = DEFAULT_CHAR_SIZE
//         ):Promise<Uint8Array> => {
//             const key = this._signKey
//             const sig = await rsaOperations.sign(
//                 msg,
//                 key.privateKey,
//                 charsize
//             )

//             return new Uint8Array(sig)
//         },

//         {
//             /**
//              * Sign a message, return the signature as a base64 encoded string.
//              *
//              * @param {Msg} msg The message to sign
//              * @param {CharSize} [charsize] Character size
//              * @returns {Promise<string>}
//              */
//             asString: async (msg:Msg, charsize?:CharSize):Promise<string> => {
//                 const sig = await this.sign(msg, charsize)
//                 return toBase64(sig)
//             }
//         }
//     )

//     /**
//      * Decrypt the given encrypted AES key.
//      * Return the key as `Uint8Array`.
//      */
//     decryptKey = Object.assign(
//         async (key:string|Uint8Array|ArrayBuffer):Promise<Uint8Array> => {
//             const decrypted = await rsaOperations.decrypt(
//                 key,
//                 this.privateEncryptKey
//             )
//             return decrypted
//         },

//         {
//             /**
//              * Decrypt the given AES key, return the result as a string.
//              */
//             asString: async (
//                 msg:string|Uint8Array,
//                 format?:SupportedEncodings
//             ):Promise<string> => {
//                 const decrypted = await rsaOperations.decrypt(
//                     msg,
//                     this.privateEncryptKey
//                 )

//                 return toString(decrypted, format)
//             }
//         }
//     )

//     /**
//      * Serialize this keys instance. Will return an object of
//      * { DID, publicEncryptionKey }, where DID is the public signature key,
//      * and `publicEncryptKey` is the encryption key, `base64` encoded.
//      * @returns {Promise<{ DID:DID, publicEncryptKey:string }>}
//      */
//     async toJson ():Promise<{ DID:DID; publicEncryptKey:string; }> {
//         const pubEnc = await this.getPublicEncryptKey()
//         const did = this.DID

//         return {
//             publicEncryptKey: pubEnc,
//             DID: did
//         }
//     }
// }

// async function makeRSAKeypair (
//     size:RsaSize,
//     hashAlg:HashAlg,
//     use:KeyUse
// ):Promise<CryptoKeyPair> {
//     if (!(Object.values(KeyUse).includes(use))) {
//         throw new Error('invalid key use')
//     }
//     const alg = use === KeyUse.Exchange ? RSA_ALGORITHM : RSA_SIGN_ALGORITHM
//     const uses:KeyUsage[] = (use === KeyUse.Exchange ?
//         ['encrypt', 'decrypt'] :
//         ['sign', 'verify'])

//     return webcrypto.subtle.generateKey({
//         name: alg,
//         modulusLength: size,
//         publicExponent: publicExponent(),
//         hash: { name: hashAlg }
//     }, false, uses)
// }

// function publicExponent ():Uint8Array {
//     return new Uint8Array([0x01, 0x00, 0x01])
// }

// /**
//  * Check that the given signature is valid with the given message.
//  */
// export async function verify (
//     msg:string|Uint8Array,
//     sig:string|Uint8Array,
//     signingDid:DID
// ):Promise<boolean> {
//     const _key = didToPublicKey(signingDid)
//     const key = await importPublicKey(
//         _key.publicKey.buffer,
//         HashAlg.SHA_256,
//         KeyUse.Sign
//     )

//     try {
//         const isOk = rsaOperations.verify(msg, sig, key)
//         return isOk
//     } catch (_err) {
//         return false
//     }
// }

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

// /**
//  * Encrypt the given AES key to the given public key. Return the encrypted AES
//  * key concattenated with the cipher text.
//  *
//  * @param { content, publicKey } opts The content to encrypt and key to
//  *   encrypt to.
//  * @param {SymmKey|Uint8Array|string} [aesKey] Optional -- the AES key. One will
//  *   be created if not passed in.
//  * @returns {Promise<string>} The encrypted AES key concattenated with the
//  *   cipher text.
//  */
// encryptTo.asString = async function (
//     opts:{ content:string|Uint8Array; publicKey:CryptoKey|string },
//     aesKey?:SymmKey|Uint8Array|string
// ):Promise<string> {
//     const { content, publicKey } = opts
//     const key = aesKey || await AES.create()
//     const encryptedContent = await AES.encrypt(
//         typeof content === 'string' ? fromString(content) : content,
//         typeof key === 'string' ? await AES.import(key) : key,
//         'arraybuffer'
//     )

//     const encryptedKey = await encryptKeyTo({ key, publicKey })
//     const joined = joinBufs(encryptedKey, encryptedContent)

//     return toString(new Uint8Array(joined), 'base64pad')
// }

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
