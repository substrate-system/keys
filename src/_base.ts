import { fromString, type SupportedEncodings, toString } from 'uint8arrays'
import { get, set, delMany } from 'idb-keyval'
import type {
    CharSize,
    Msg,
    SymmKeyLength,
    DID,
    SymmKey,
} from './types.js'
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

export interface RsaEncryptor {
    (
        content:string|Uint8Array,
        recipient?:CryptoKey|string,
        aesKey?:SymmKey|Uint8Array|string,
        keysize?:SymmKeyLength
    ):Promise<Uint8Array>
}

export interface EccEncryptor {
    (
        content:string|Uint8Array,
        recipient?:CryptoKey|string,
        info?:string,
        aesKey?:SymmKey|Uint8Array|string,
        keysize?:SymmKeyLength
    ):Promise<Uint8Array>
}

export interface RsaEncryptorAsString {
    (
        content:string|Uint8Array,
        recipient?:CryptoKey|string,
        aesKey?:SymmKey|Uint8Array|string,
        keysize?:SymmKeyLength
    ):Promise<string>
}

export interface EccEncryptorAsString {
    (
        content:string|Uint8Array,
        recipient?:CryptoKey|string,
        info?:string,
        aesKey?:SymmKey|Uint8Array|string,
        keysize?:SymmKeyLength
    ):Promise<string>
}

// Type helpers to constrain implementations
export type RsaKeysType = AbstractKeys & {
    encrypt: RsaEncryptor;
    encryptAsString: RsaEncryptorAsString;
}

export type EccKeysType = AbstractKeys & {
    encrypt: EccEncryptor;
    encryptAsString: EccEncryptorAsString;
}

/**
 * Args to constructor.
 */
export type KeyArgs = {
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
    TYPE: 'ecc' | 'rsa';
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
    // type:'ecc'|'rsa'
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
    }

    /**
     * By default, encrypt the given data to yourself, as a "note to self".
     */
    abstract encrypt (
        content:string|Uint8Array,
        recipient?:CryptoKey|string,
        aesKeyOrInfo?:SymmKey|Uint8Array|string,
        keysizeOrAesKey?:SymmKeyLength|SymmKey|Uint8Array|string,
        keysize?:SymmKeyLength
    ):Promise<Uint8Array>

    abstract encryptAsString (
        content:string|Uint8Array,
        recipient?:CryptoKey|string,
        aesKeyOrInfo?:SymmKey|Uint8Array|string,
        keysizeOrAesKey?:SymmKeyLength|SymmKey|Uint8Array|string,
        keysize?:SymmKeyLength
    ):Promise<string>

    abstract decrypt(
        msg:string|Uint8Array|ArrayBuffer,
        publicKeyOrKeysize?:CryptoKey|string|SymmKeyLength,
        aesAlgorithm?:string,
    ):Promise<ArrayBuffer|Uint8Array>

    abstract decryptAsString(
        msg:string|Uint8Array|ArrayBuffer,
        publicKeyOrKeysize?:CryptoKey|string|SymmKeyLength,
        aesAlgorithm?:string,
    ):Promise<string>

    abstract sign(msg:Msg, charsize?:CharSize):Promise<Uint8Array>
    abstract signAsString(msg:string, charsize?:CharSize):Promise<string>

    publicExchangeKeyAsString (format?:SupportedEncodings):Promise<string> {
        return this.publicExchangeKey.asString(format)
    }

    publicWriteKeyAsString (format?:SupportedEncodings):Promise<string> {
        return this.publicWriteKey.asString(format)
    }

    get publicWriteKey () {
        const publicKey = this.writeKey.publicKey
        return Object.assign(publicKey, {
            asString: async (format?:SupportedEncodings):Promise<string> => {
                const arrayBuffer = await getPublicKeyAsArrayBuffer(this.writeKey)
                const uint8Array = new Uint8Array(arrayBuffer)
                return format ? toString(uint8Array, format) : toBase64(uint8Array)
            }
        })
    }

    get publicExchangeKey () {
        const publicKey = this.exchangeKey.publicKey
        return Object.assign(publicKey, {
            asString: async (format?: SupportedEncodings): Promise<string> => {
                const arrayBuffer = await getPublicKeyAsArrayBuffer(this.exchangeKey)
                const uint8Array = new Uint8Array(arrayBuffer)
                return format ? toString(uint8Array, format) : toBase64(uint8Array)
            }
        })
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
     * Get the relevant AES key.
     *   - if this is an ECC keypair, then use DHKE with the given public key
     *   - if this is RSA, use your private key to decrypt the given AES key
     */
    abstract getAesKey (
        publicKey?:CryptoKey|string|null,
        info?:string|null
    ):Promise<CryptoKey>

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

    abstract toJson (format?:SupportedEncodings):Promise<{
        DID:DID;
        publicExchangeKey:string;
    }>

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
        session?:boolean
    ):Promise<T> {
        // encryption
        const exchange = await this._createExchangeKeys()
        // signatures
        const write = await this._createWriteKeys()

        const publicSigningKey = await getPublicKeyAsArrayBuffer(write)
        const did = await publicKeyToDid(
            new Uint8Array(publicSigningKey),
            this.TYPE === 'ecc' ? 'ed25519' : 'rsa'
        )

        const keys = new this({
            keys: { exchange, write },
            did,
            hasPersisted: false,
            isSessionOnly: !!session
        })

        this._instance = keys

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
        }> = {
            session: false,
        }
    ):Promise<T> {
        if (this._instance) return this._instance  // cache

        let hasPersisted = true
        let exchangeKeys:CryptoKeyPair|undefined = await get(
            opts.encryptionKeyName || this.EXCHANGE_KEY_NAME
        )
        let writeKeys:CryptoKeyPair|undefined = await get(
            opts.signingKeyName || this.WRITE_KEY_NAME
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
            this.TYPE === 'ecc' ? 'ed25519' : 'rsa'
        )

        const keys = new this({
            keys: { exchange: exchangeKeys, write: writeKeys },
            did,
            hasPersisted,
            isSessionOnly: !!opts.session
        }) as T

        this._instance = keys
        return keys
    }
}

/**
 * Encrypt the given message to the given public key. If an AES key is not
 * provided, one will be created. Use an AES key to encrypt the given
 * content, then we encrypt the AES key to the given public key.
 *
 * @param {{ content, publicKey }} opts The content to encrypt and
 *   public key to encrypt to
 * @param {SymmKey|Uint8Array|string} [aesKey] An optional AES key to encrypt
 *   to the given public key
 * @returns {Promise<ArrayBuffer>} The encrypted AES key, concattenated with
 *   the encrypted content.
 */
export async function encryptTo (
    opts:{ content:string|Uint8Array; publicKey:CryptoKey|string; },
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
    const joined = await encryptTo(opts, aesKey)
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
