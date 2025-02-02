import { webcrypto } from '@bicycle-codes/one-webcrypto'
import { fromString, type SupportedEncodings, toString } from 'uint8arrays'
import { get, set } from 'idb-keyval'
import {
    RSA_ALGORITHM,
    DEFAULT_RSA_SIZE,
    DEFAULT_HASH_ALGORITHM,
    RSA_SIGN_ALGORITHM,
    DEFAULT_CHAR_SIZE,
    DEFAULT_SYMM_ALGORITHM,
    DEFAULT_SYMM_LENGTH,
    AES_GCM,
    DEFAULT_ENC_NAME,
    DEFAULT_SIG_NAME,
    IV_LENGTH,
} from './constants'
import {
    SymmKeyLength,
    type SymmAlgorithm,
    KeyUse,
    type RsaSize,
    HashAlg,
    type DID,
    type Msg,
    type CharSize,
    type SymmKey,
    type EncryptedMessage
} from './types'
import {
    publicKeyToDid,
    getPublicKeyAsArrayBuffer,
    rsaOperations,
    didToPublicKey,
    importPublicKey,
    toBase64,
    isCryptoKey,
    normalizeUnicodeToBuf,
    importKey,
    randomBuf,
    joinBufs,
    normalizeBase64ToBuf,
    base64ToArrBuf,
    sha256,
    getPublicKeyAsUint8Array
} from './util'

export { publicKeyToDid, getPublicKeyAsArrayBuffer }

export type { DID }

export { getPublicKeyAsUint8Array } from './util'

// import Debug from '@bicycle-codes/debug'
// const debug = Debug()

type ConstructorOpts = {
    keys: { encrypt:CryptoKeyPair, sign:CryptoKeyPair };
    did:DID;
    persisted:boolean;
}

export type SerializedKeys = {
    DID:DID;
    publicEncryptKey:string;
}

/**
 * Expose RSA keys only for now, because we are
 * waiting for more browsers to support ECC.
 *
 * Create an instance with `Keys.create` b/c async.
 */
export class Keys {
    private _encryptKey:CryptoKeyPair
    private _signKey:CryptoKeyPair
    static _instance  // a cache for indexedDB
    persisted:boolean
    ENCRYPTION_KEY_NAME:string = DEFAULT_ENC_NAME
    SIGNING_KEY_NAME:string = DEFAULT_SIG_NAME
    DID:DID

    constructor (opts:ConstructorOpts) {
        const { keys } = opts
        this._encryptKey = keys.encrypt
        this._signKey = keys.sign
        this.DID = opts.did
        this.persisted = opts.persisted
        Keys._instance = this
    }

    get signKeypair ():CryptoKeyPair {
        return {
            privateKey: this.privateSignKey,
            publicKey: this.publicSignKey
        }
    }

    get encryptKeypair ():CryptoKeyPair {
        return {
            privateKey: this.privateEncryptKey,
            publicKey: this.publicEncryptKey
        }
    }

    get publicSignKey ():CryptoKey {
        return this._signKey.publicKey
    }

    get privateSignKey ():CryptoKey {
        return this._signKey.privateKey
    }

    get privateEncryptKey ():CryptoKey {
        return this._encryptKey.privateKey
    }

    get publicEncryptKey ():CryptoKey {
        return this._encryptKey.publicKey
    }

    /**
     * Get the public encryptioawait n key as a string.
     *
     * @returns {string} Return a string b/c mostly would use this for
     * serializing the public encryption key.
     */
    getPublicEncryptKey = Object.assign(
        async (format?:SupportedEncodings):Promise<string> => {
            const { publicKey } = this._encryptKey
            const spki = await webcrypto.subtle.exportKey(
                'spki',
                publicKey
            )

            return (format ?
                toString(new Uint8Array(spki), format) :
                toBase64(spki))
        },

        {
            uint8Array: async ():Promise<Uint8Array> => {
                const { publicKey } = this._encryptKey
                const arr = await getPublicKeyAsUint8Array(publicKey)
                return arr
            }
        }
    )

    /**
     * Return a 32-character, DNS-friendly hash of the given DID.
     *
     * @param {DID} did a DID format string
     * @returns {string} 32 character, base32 hash of the DID
     */
    static async deviceName (did:DID):Promise<string> {
        const normalizedDid = did.normalize('NFD')
        const hashedUsername = await sha256(
            new TextEncoder().encode(normalizedDid)
        )

        return toString(hashedUsername, 'base32').slice(0, 32)
    }

    /**
     * Create a new `Keys` instance.
     *
     * @returns {Keys}
     */
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

        const publicSigningKey = await getPublicKeyAsArrayBuffer(signingKeypair)
        const did = await publicKeyToDid(new Uint8Array(publicSigningKey), 'rsa')

        const constructorOpts:ConstructorOpts = {
            keys: { encrypt: encryptionKeypair, sign: signingKeypair },
            did,
            persisted: false
        }

        const keys = new Keys(constructorOpts)
        return keys
    }

    /**
     * Save this keys instance to `indexedDB`.
     */
    async persist ():Promise<void> {
        await Promise.all([
            set(this.ENCRYPTION_KEY_NAME, this._encryptKey),
            set(this.SIGNING_KEY_NAME, this._signKey)
        ])
        this.persisted = true
    }

    /**
     * Return a 32-character, DNS friendly hash of this public signing key.
     *
     * @returns {string}
     */
    async getDeviceName ():Promise<string> {
        return Keys.deviceName(this.DID)
    }

    /**
     * Restore some keys from indexedDB, or create a new keypair if it doesn't
     * exist yet.
     *
     * @param {{ encryptionKeyName, signingKeyName }} opts Strings to use as
     * keys in indexedDB.
     * @returns {Promise<Keys>}
     */
    static async load (opts:{
        encryptionKeyName,
        signingKeyName
    } = {
        encryptionKeyName: DEFAULT_ENC_NAME,
        signingKeyName: DEFAULT_SIG_NAME
    }):Promise<Keys> {
        if (Keys._instance) return Keys._instance  // cache

        let persisted = true
        let encKeys:CryptoKeyPair|undefined = await get(opts.encryptionKeyName)
        let signKeys:CryptoKeyPair|undefined = await get(opts.signingKeyName)

        if (!encKeys) {
            persisted = false
            encKeys = await makeRSAKeypair(
                DEFAULT_RSA_SIZE,
                DEFAULT_HASH_ALGORITHM,
                KeyUse.Encrypt
            )
        }
        if (!signKeys) {
            persisted = false
            signKeys = await makeRSAKeypair(
                DEFAULT_RSA_SIZE,
                DEFAULT_HASH_ALGORITHM,
                KeyUse.Sign
            )
        }

        const publicKey = await getPublicKeyAsArrayBuffer(signKeys)
        const did = await publicKeyToDid(new Uint8Array(publicKey), 'rsa')

        const constructorOpts:ConstructorOpts = {
            keys: { encrypt: encKeys, sign: signKeys },
            did,
            persisted
        }

        const keys = new Keys(constructorOpts)
        return keys
    }

    sign = Object.assign(
        /**
         * Sign the message, and return the signature as a `Uint8Array`.
         */
        async (msg:Msg, charsize?:CharSize):Promise<Uint8Array> => {
            const key = this._signKey
            const sig = await rsaOperations.sign(
                msg,
                key.privateKey,
                charsize || DEFAULT_CHAR_SIZE
            )

            return new Uint8Array(sig)
        },

        {
            /**
             * Sign a message, return the signature as a base64 encoded string.
             *
             * @param {Msg} msg The message to sign
             * @param {CharSize} [charsize] Character size
             * @returns {Promise<string>}
             */
            asString: async (msg:Msg, charsize?:CharSize):Promise<string> => {
                const sig = await this.sign(msg, charsize)
                return toBase64(sig)
            }
        }
    )

    decrypt = Object.assign(
        /**
         * Decrypt the given message. Message must have { content, key }
         * properties.
         *
         * @param {EncryptedMessage} msg The message to decrypt.
         * @returns {Uint8Array}
         */
        async (msg:EncryptedMessage):Promise<Uint8Array> => {
            const decryptedKey = await this.decryptKey(msg.key)
            const decryptedContent = await AES.decrypt(msg.content, decryptedKey)
            return decryptedContent
        },

        {
            /**
             * Decrypt the given message, return the result as a string.
             * @returns {string}
             */
            asString: async (
                msg:EncryptedMessage,
                format?:SupportedEncodings
            ):Promise<string> => {
                const decryptedKey = await this.decryptKey(msg.key)
                const decryptedContent = await AES.decrypt(
                    msg.content,
                    decryptedKey
                )

                return toString(decryptedContent, format)
            }
        }
    )

    /**
     * Decrypt the given encrypted AES key.
     * Return the key as `Uint8Array`.
     */
    decryptKey = Object.assign(
        async (key:string|Uint8Array):Promise<Uint8Array> => {
            const decrypted = await rsaOperations.decrypt(
                key,
                this.privateEncryptKey
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
                    this.privateEncryptKey
                )

                return toString(decrypted, format || 'utf-8')
            }
        }
    )

    /**
     * Serialize this keys instance. Will return an object of
     * { DID, publicEncryptionKey }, where DID is the public signature key,
     * and `publicEncryptKey` is the encryption key, `base64` encoded.
     * @returns {Promise<{ DID:DID, publicEncryptKey:string }>}
     */
    async toJson ():Promise<{ DID:DID; publicEncryptKey:string; }> {
        const pubEnc = await this.getPublicEncryptKey()
        const did = this.DID

        return {
            publicEncryptKey: pubEnc,
            DID: did
        }
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
 * Check that the given signature is valid with the given message.
 */
export async function verify (
    msg:string|Uint8Array,
    sig:string|Uint8Array,
    signingDid:DID
):Promise<boolean> {
    const _key = didToPublicKey(signingDid)
    const key = await importPublicKey(
        _key.publicKey.buffer,
        HashAlg.SHA_256,
        KeyUse.Sign
    )

    try {
        const isOk = rsaOperations.verify(msg, sig, key)
        return isOk
    } catch (_err) {
        return false
    }
}

/**
 * Encrypt the given message to the given public key. If an AES key is not
 * provided, one will be created. This uses an AES key to encrypt the given
 * content, then we encrypt the AES key to the given public key.
 *
 * @param {{ content, publicKey }} opts The content to encrypt and
 * public key to encrypt to
 * @param {SymmKey|Uint8Array|string} [aesKey] An optional AES key to encrypt
 * to the given public key
 *
 * @returns {Promise<{content, key}>} The encrypted content and encrypted key
 */
export async function encryptTo (
    opts:{
        content:string|Uint8Array;
        publicKey:CryptoKey|string;
    },
    aesKey?:SymmKey|Uint8Array|string,
):Promise<{
    content:Uint8Array;
    key:Uint8Array;
}> {
    const { content, publicKey } = opts
    const key = aesKey || await AES.create()
    const encryptedContent = await AES.encrypt(
        typeof content === 'string' ? fromString(content) : content,
        typeof key === 'string' ? await AES.import(key) : key,
    )
    const encryptedKey = await encryptKeyTo({ key, publicKey })

    return { content: encryptedContent, key: encryptedKey }
}

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

    let pubKeyBuf:ArrayBuffer
    if (typeof publicKey === 'string') {
        pubKeyBuf = fromString(publicKey).buffer
    } else {
        pubKeyBuf = await getPublicKeyAsArrayBuffer(publicKey)
    }
    const joined = joinBufs(pubKeyBuf, encryptedContent)

    return toString(new Uint8Array(joined), 'base64pad')
}

// /**
//  * Encrypt a message, return everything as strings.
//  */
// encryptTo.asString = async function (opts:{
//     content:string|Uint8Array;
//     publicKey:CryptoKey|string;
// }, aesKey?:SymmKey|Uint8Array|string):Promise<{ content:string; key:string }> {
//     const encrypted = await encryptTo(opts, aesKey)
//     return {
//         content: toBase64(encrypted.content),
//         key: toBase64(encrypted.key)
//     }
// }

export const AES = {
    create (opts:{ alg:string, length:number } = {
        alg: DEFAULT_SYMM_ALGORITHM,
        length: DEFAULT_SYMM_LENGTH
    }):Promise<CryptoKey> {
        return webcrypto.subtle.generateKey({
            name: opts.alg,
            length: opts.length
        }, true, ['encrypt', 'decrypt'])
    },

    export: Object.assign(
        async (key:CryptoKey):Promise<Uint8Array> => {
            const raw = await webcrypto.subtle.exportKey('raw', key)
            return new Uint8Array(raw)
        },

        {
            asString: async (key:CryptoKey) => {
                const raw = await AES.export(key)
                return toBase64(raw)
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
        encryptedData:Uint8Array|string,
        cryptoKey:CryptoKey|Uint8Array|ArrayBuffer,
        iv?:Uint8Array
    ):Promise<Uint8Array> {
        const key = isCryptoKey(cryptoKey) ? cryptoKey : await importAesKey(cryptoKey)
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
}):Promise<Uint8Array> {
    let _key:Uint8Array|string
    if (key instanceof CryptoKey) {
        _key = await AES.export(key)
    } else {
        _key = key
    }

    const buf = await rsaOperations.encrypt(_key, publicKey)
    return new Uint8Array(buf)
}

encryptKeyTo.asString = async function ({ key, publicKey }:{
    key:string|Uint8Array|CryptoKey;
    publicKey:CryptoKey|string|Uint8Array;
}, format?:SupportedEncodings):Promise<string> {
    const asArr = await encryptKeyTo({ key, publicKey })
    return format ? toString(asArr, format) : toBase64(asArr)
}

function importAesKey (
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
