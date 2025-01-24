import { webcrypto } from '@bicycle-codes/one-webcrypto'
import { fromString, toString } from 'uint8arrays'
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
    sha256
} from './util'
// import Debug from '@bicycle-codes/debug'
// const debug = Debug()

type ConstructorOpts = {
    keys: { encrypt:CryptoKeyPair, sign:CryptoKeyPair }
    did:DID
}

/**
 * Expose RSA keys only for now, because we are
 * waiting for more browsers to support ECC.
 *
 * Create an instance with `Keys.create` b/c async.
 */
export class Keys {
    private encryptKey:CryptoKeyPair
    private signKey:CryptoKeyPair
    ENCRYPTION_KEY_NAME:string = DEFAULT_ENC_NAME
    SIGNING_KEY_NAME:string = DEFAULT_SIG_NAME
    DID:DID

    constructor (opts:ConstructorOpts) {
        const { keys } = opts
        this.encryptKey = keys.encrypt
        this.signKey = keys.sign
        this.DID = opts.did
    }

    get privateKey ():CryptoKey {
        return this.encryptKey.privateKey
    }

    get publicEncryptKey ():CryptoKey {
        return this.encryptKey.publicKey
    }

    /**
     * Get the public encryptioawait n key as a string.
     *
     * @returns {string} Return a string b/c mostly would use this for
     * serializing the public encryption key.
     */
    async getPublicEncryptKey ():Promise<string> {
        const { publicKey } = this.encryptKey
        const spki = await webcrypto.subtle.exportKey(
            'spki',
            publicKey
        )

        return toBase64(spki)
    }

    get publicSignKey ():CryptoKey {
        return this.signKey.publicKey
    }

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
        const did = publicKeyToDid(new Uint8Array(publicSigningKey), 'rsa')

        const constructorOpts:ConstructorOpts = {
            keys: { encrypt: encryptionKeypair, sign: signingKeypair },
            did,
        }

        const keys = new Keys(constructorOpts)

        return keys
    }

    async persist ():Promise<void> {
        await Promise.all([
            set(this.ENCRYPTION_KEY_NAME, this.encryptKey),
            set(this.SIGNING_KEY_NAME, this.signKey)
        ])
    }

    async getDeviceName ():Promise<string> {
        return Keys.deviceName(this.DID)
    }

    /**
     * Restore some keys from indexedDB.
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
        const encKeys = await get(opts.encryptionKeyName)
        const sigKeys = await get(opts.signingKeyName)

        const publicKey = await getPublicKeyAsArrayBuffer(sigKeys)
        const did = publicKeyToDid(new Uint8Array(publicKey), 'rsa')

        const constructorOpts:ConstructorOpts = {
            keys: { encrypt: encKeys, sign: sigKeys },
            did
        }

        const keys = new Keys(constructorOpts)
        return keys
    }

    /**
     * Sign a string. Return the signature as Uint8Array.
     *
     * @param msg The message to sign
     * @returns {Promise<Uint8Array>} The signature
     */
    async sign (
        msg:Msg,
        charsize?:CharSize,
    ):Promise<Uint8Array> {
        const key = this.signKey

        const sig = await rsaOperations.sign(
            msg,
            key.privateKey,
            charsize || DEFAULT_CHAR_SIZE
        )

        return new Uint8Array(sig)
    }

    async signAsString (msg:Msg, charsize?:CharSize):Promise<string> {
        const sig = await this.sign(msg, charsize)
        return toBase64(sig)
    }

    async decrypt (msg:EncryptedMessage):Promise<Uint8Array> {
        const decryptedKey = await this.decryptKey(msg.key)
        const decryptedContent = await AES.decrypt(msg.content, decryptedKey)
        return decryptedContent
    }

    async decryptToString (msg:EncryptedMessage):Promise<string> {
        const decryptedKey = await this.decryptKey(msg.key)
        const decryptedContent = await AES.decrypt(msg.content, decryptedKey)
        return toString(decryptedContent)
    }

    async decryptKey (key:string|Uint8Array):Promise<Uint8Array> {
        const decrypted = await rsaOperations.decrypt(key, this.privateKey)
        return decrypted
    }

    async decryptKeyAsString (msg:string|Uint8Array):Promise<string> {
        const decrypted = await rsaOperations.decrypt(msg, this.privateKey)
        return toString(decrypted)
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
export async function encryptTo (opts:{
    content:string|Uint8Array;
    publicKey:CryptoKey|string;
}, aesKey?:SymmKey|Uint8Array|string):Promise<{
    content:Uint8Array;
    key:Uint8Array;
}> {
    const { content, publicKey } = opts
    const key = aesKey || await AES.create()
    const encryptedContent = await AES.encrypt(
        typeof content === 'string' ? fromString(content) : content,
        typeof key === 'string' ? await AES.import(key) : key
    )
    const encryptedKey = await encryptKeyTo({ key, publicKey })

    return { content: encryptedContent, key: encryptedKey }
}

/**
 * Encrypt a message, return everything as strings.
 */
encryptTo.asString = async function (opts:{
    content:string|Uint8Array;
    publicKey:CryptoKey|string;
}, aesKey?:SymmKey|Uint8Array|string):Promise<{ content:string; key:string }> {
    const encrypted = await encryptTo(opts, aesKey)
    return {
        content: toBase64(encrypted.content),
        key: toBase64(encrypted.key)
    }
}

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

    async encrypt (
        data:Uint8Array,
        cryptoKey:CryptoKey|Uint8Array,
        iv?:Uint8Array
    ):Promise<Uint8Array> {
        const key = (isCryptoKey(cryptoKey) ?
            cryptoKey :
            await importAesKey(cryptoKey)
        )

        // prefix the `iv` into the cipher text
        const encrypted = (iv ?
            await webcrypto.subtle.encrypt({ name: AES_GCM, iv }, key, data) :
            await encryptBytes(data, key)
        )

        return new Uint8Array(encrypted)
    },

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

// AES.export.asString = async function (key:CryptoKey):Promise<string> {
//     const raw = await AES.export(key)
//     return toBase64(raw)
// }

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
}):Promise<string> {
    const asArr = await encryptKeyTo({ key, publicKey })
    return toBase64(asArr)
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
