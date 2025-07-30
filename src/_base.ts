import { fromString, type SupportedEncodings, toString } from 'uint8arrays'
import { get, set, delMany } from 'idb-keyval'
import { DEFAULT_RSA_EXCHANGE, DEFAULT_RSA_WRITE, } from './constants.js'
import { type SymmKeyLength, type DID, type SymmKey, } from './types.js'
import { AES } from './aes/index.js'
import {
    publicKeyToDid,
    getPublicKeyAsArrayBuffer,
    rsaOperations,
    toBase64,
    joinBufs,
    sha256,
} from './util.js'

export { publicKeyToDid, getPublicKeyAsArrayBuffer }
export * from './constants.js'

export type { DID }

export { getPublicKeyAsUint8Array } from './util.js'

export type SerializedKeys = {
    DID:DID;
    publicEncryptKey:string;
}

/**
 * Function that returns a promise for Uint8Array.
 * Has a property `asString` that returns a string.
 */
export interface Decryptor {
    (
        msg:string|Uint8Array|ArrayBuffer,
        keysize?:SymmKeyLength
    ):Promise<Uint8Array>;
    asString:(msg:string, keysize?:SymmKeyLength)=>Promise<string>
}

export interface Encryptor {
    (
        opts:{
            content:string|Uint8Array;
            publicKey:CryptoKey|string;
        },
        recipient?:CryptoKey|Uint8Array,
        aesKey?:SymmKey|Uint8Array|string,
        keysize?:SymmKeyLength
    ):Promise<Uint8Array>;
    asString:(
        msg:string,
        keysize?:SymmKeyLength
    )=>Promise<string>
}

export interface Signer {
    (msg:string|Uint8Array):Promise<Uint8Array>;
    asString: (msg:string, keysize?:SymmKeyLength)=>Promise<string>
}

/**
 * Args to constructor.
 */
export type KeyArgs = {
    type:'ecc'|'rsa'
    keys:{ exchange:CryptoKeyPair, write:CryptoKeyPair };
    did:DID;
    hasPersisted:boolean;
    isSessionOnly?:boolean;  // in memory only?
    exchangeKeyName?:string;
    writeKeyName?:string;
}

/**
 * The class that extends AbstractKeys
 */
interface ChildKeys<T extends AbstractKeys = AbstractKeys> {
    new (opts:KeyArgs):T;
    _instance:T;
    _createExchangeKeys():Promise<CryptoKeyPair>
    _createWriteKeys():Promise<CryptoKeyPair>
}

/**
 * The parent key. Doesn't implement the encrypt/sign functions.
 */
export abstract class AbstractKeys {
    DID:DID
    exchangeKey:CryptoKeyPair
    writeKey:CryptoKeyPair
    hasPersisted:boolean
    isSessionOnly:boolean
    type:'ecc'|'rsa'
    static EXCHANGE_KEY_NAME:string  // needs to be defined by child class
    static WRITE_KEY_NAME:string
    static _instance  // a cache for indexedDB

    constructor (opts:KeyArgs) {
        const { keys } = opts
        this.DID = opts.did
        this.exchangeKey = keys.exchange
        this.writeKey = keys.write
        this.hasPersisted = opts.hasPersisted
        this.isSessionOnly = !!opts.isSessionOnly
        this.type = opts.type
    }

    /**
     * By default, encrypt the given data to yourself, as a "note to self".
     */
    abstract encrypt:Encryptor
    abstract decrypt:Decryptor
    abstract sign:Signer

    get publicWriteKey ():CryptoKey {
        return this.writeKey.publicKey
    }

    get publicExchangeKey ():CryptoKey {
        return this.exchangeKey.publicKey
    }

    get privateWriteKey ():CryptoKey {
        return this.writeKey.privateKey
    }

    get privateExchangeKey ():CryptoKey {
        return this.exchangeKey.privateKey
    }

    /**
     * The machine-readable name for this keypair.
     */
    get deviceName ():Promise<string> {
        return AbstractKeys.deviceName(this.DID)
    }

    /**
     * Return a 32-character, DNS-friendly hash of the given DID.
     *
     * @param {DID} did A DID format string
     * @returns {string} 32 character, base32 hash of the DID
     */
    static deviceName (did:DID):Promise<string> {
        return getDeviceName(did)
    }

    /**
     * Save this keys instance to `indexedDB`.
     */
    async persist ():Promise<void> {
        if (this.isSessionOnly) return

        const exchange = (this.constructor as typeof AbstractKeys).EXCHANGE_KEY_NAME
        const write = (this.constructor as typeof AbstractKeys).WRITE_KEY_NAME

        await Promise.all([
            set(exchange, this.exchangeKey),
            set(write, this.writeKey)
        ])

        this.hasPersisted = true
    }

    /**
     * Delete the keys stored in indexedDB.
     */
    async delete ():Promise<void> {
        await delMany([
            (this.constructor as typeof AbstractKeys).EXCHANGE_KEY_NAME,
            (this.constructor as typeof AbstractKeys).WRITE_KEY_NAME,
        ])
        this.hasPersisted = false
    }

    /**
     * Return a 32-character, DNS friendly hash of the public signing key.
     *
     * @returns {Promise<string>}
     */
    async getDeviceName ():Promise<string> {
        return AbstractKeys.deviceName(this.DID)
    }

    static _createExchangeKeys ():Promise<CryptoKeyPair> {
        throw new Error('The child should implement this')
    }

    static _createWriteKeys ():Promise<CryptoKeyPair> {
        throw new Error('The child should implement this')
    }

    static async create<T extends AbstractKeys> (
        this:ChildKeys,
        session:boolean,
        type:'ecc'|'rsa'
    ):Promise<T> {
        // encryption
        const exchange = await this._createExchangeKeys()
        // signatures
        const write = await this._createWriteKeys()

        const publicSigningKey = await getPublicKeyAsArrayBuffer(write)
        const did = await publicKeyToDid(
            new Uint8Array(publicSigningKey),
            type === 'ecc' ? 'ed25519' : 'rsa'
        )

        const keys = new this({
            keys: { exchange, write },
            type,
            did,
            hasPersisted: false,
            isSessionOnly: !!session
        })

        return keys as T
    }

    /**
     * Restore some keys from indexedDB, or create a new keypair if it doesn't
     * exist yet.
     *
     * @param {{ encryptionKeyName, signingKeyName, session }} opts Strings to
     *   use as keys in indexedDB, and a session boolean, is this in memory
     *   only? Or can it be persisted.
     * @returns {Promise<AbstractKeys>}
     */
    static async load<T extends AbstractKeys = AbstractKeys> (
        this:ChildKeys & typeof AbstractKeys,
        opts:Partial<{
            encryptionKeyName:string,
            signingKeyName:string,
            session:boolean,
            type:'ecc'|'rsa'
        }> = {
            session: false,
            type: 'rsa'
        }
    ):Promise<T> {
        if (this._instance) return this._instance  // cache
        const type = opts.type || 'rsa'

        let hasPersisted = true
        let exchangeKeys:CryptoKeyPair|undefined = await get(
            opts.encryptionKeyName || DEFAULT_RSA_EXCHANGE
        )
        let writeKeys:CryptoKeyPair|undefined = await get(
            opts.signingKeyName || DEFAULT_RSA_WRITE
        )

        if (!exchangeKeys) {
            hasPersisted = false
            exchangeKeys = await this._createExchangeKeys()
        }
        if (!writeKeys) {
            hasPersisted = false
            writeKeys = await this._createWriteKeys()
        }

        const publicSigningKey = await getPublicKeyAsArrayBuffer(writeKeys)
        const did = await publicKeyToDid(
            new Uint8Array(publicSigningKey),
            type === 'ecc' ? 'ed25519' : 'rsa'
        )

        const keys = new this({
            keys: { exchange: exchangeKeys, write: writeKeys },
            did,
            type,
            hasPersisted,
            isSessionOnly: !!opts.session
        }) as T

        return keys
    }

    // /**
    //  * Decrypt the given message.
    //  */
    // decrypt = Object.assign(
    //     /**
    //      * Expect the given cipher content to be the format returned by
    //      * encryptTo`. That is, encrypted AES key + `iv` + encrypted content.
    //      */
    //     async (
    //         msg:string|Uint8Array|ArrayBuffer,
    //         keysize?:SymmKeyLength
    //     ):Promise<Uint8Array> => {
    //         const length = keysize || DEFAULT_SYMM_LENGTH
    //         const cipherText = normalizeToBuf(msg, base64ToArrBuf)
    //         const key = cipherText.slice(0, length)
    //         const data = cipherText.slice(length)
    //         const decryptedKey = await this.decryptKey(key)
    //         const decryptedContent = await AES.decrypt(data, decryptedKey)
    //         return decryptedContent
    //     },

    //     {
    //         asString: async (msg:string, keysize?:SymmKeyLength):Promise<string> => {
    //             const dec = await this.decrypt(msg, keysize)
    //             return toString(dec)
    //         }
    //     }
    // )
}

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

// /**
//  * Decrypt the given message with the given key. We expect the `iv` to be
//  * prefixed to the encrypted message.
//  * @param msg The message to decrypt
//  * @param key The key to decrypt with
//  * @param opts Optional args for algorithm and stuff
//  * @returns {Promise<ArrayBuffer>}
//  */
// async function decryptBytes (
//     msg:Msg,
//     key:CryptoKey|string,
//     opts?:Partial<{
//         alg:SymmAlgorithm;
//         length: SymmKeyLength;
//         iv: ArrayBuffer;
//     }>
// ):Promise<ArrayBuffer> {
//     const cipherText = normalizeBase64ToBuf(msg)
//     const importedKey = typeof key === 'string' ?
//         await importKey(key, opts) :
//         key
//     // `iv` is prefixed to the cypher text
//     const iv = cipherText.slice(0, IV_LENGTH)
//     const cipherBytes = cipherText.slice(IV_LENGTH)
//     const msgBuff = await webcrypto.subtle.decrypt({
//         name: DEFAULT_SYMM_ALGORITHM,
//         iv
//     }, importedKey, cipherBytes)

//     return msgBuff
// }

export async function getDeviceName (did:DID|string) {
    const hashedUsername = await sha256(
        new TextEncoder().encode(did.normalize('NFD'))
    )

    return toString(hashedUsername, 'base32').slice(0, 32)
}

