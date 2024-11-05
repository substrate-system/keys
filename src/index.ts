import { webcrypto } from '@bicycle-codes/one-webcrypto'
import { fromString, toString } from 'uint8arrays'
import { set } from 'idb-keyval'
import {
    RSA_ALGORITHM,
    DEFAULT_RSA_SIZE,
    DEFAULT_HASH_ALGORITHM,
    RSA_SIGN_ALGORITHM,
    DEFAULT_CHAR_SIZE,
    DEFAULT_SYMM_ALGORITHM,
    DEFAULT_SYMM_LENGTH,
    AES_GCM
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
    base64ToArrBuf
} from './util'
import Debug from '@bicycle-codes/debug'
const debug = Debug()

type ConstructorOpts = {
    keys: { encrypt:CryptoKeyPair, sign:CryptoKeyPair }
    names?: { encryption:string, sign:string }
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
    ENCRYPTION_KEY_NAME:string = 'encryption-key'
    SIGNING_KEY_NAME:string = 'signing-key'
    DID:DID

    constructor (opts:ConstructorOpts) {
        const { keys } = opts
        this.encryptKey = keys.encrypt
        this.signKey = keys.sign
        this.DID = opts.did
        if (opts.names) {
            this.ENCRYPTION_KEY_NAME = opts.names.encryption
            this.SIGNING_KEY_NAME = opts.names.sign
        }
    }

    get privateKey ():CryptoKey {
        return this.encryptKey.privateKey
    }

    get publicEncryptKey ():CryptoKey {
        return this.encryptKey.publicKey
    }

    get publicSignKey ():CryptoKey {
        return this.signKey.publicKey
    }

    static async create (opts?:{
        encryptionKeyName:string,
        signingKeyName:string
    }):Promise<Keys> {
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

        const arr = await getPublicKeyAsArrayBuffer(signingKeypair)

        const did = publicKeyToDid(new Uint8Array(arr), 'rsa')

        const constructorOpts:ConstructorOpts = {
            keys: { encrypt: encryptionKeypair, sign: signingKeypair },
            did
        }

        if (opts?.encryptionKeyName) {
            constructorOpts.names = {
                encryption: opts.encryptionKeyName,
                sign: opts.signingKeyName
            }
        }

        const keys = new Keys(constructorOpts)

        debug('create new keys', keys)

        // save the keys to indexedDB
        await Promise.all([
            set(keys.ENCRYPTION_KEY_NAME, encryptionKeypair),
            set(keys.SIGNING_KEY_NAME, signingKeypair)
        ])

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
 * Encrypt the given content to the given public key. This is RSA encryption,
 * and should be used only to encrypt AES keys.
 *
 * @param {{ content, publicKey }} params The content to encrypt, and public key
 * to encrypt it to.
 * @returns {Promise<Uint8Array>}
 */
export async function encryptKeyTo ({ content, publicKey }:{
    content:string|Uint8Array;
    publicKey:CryptoKey|string;
}):Promise<Uint8Array> {
    const buf = await rsaOperations.encrypt(content, publicKey)
    return new Uint8Array(buf)
}

/**
 * Encrypt the given message to the given public key. If an AES key is not
 * provided, one will be created.
 *
 * @param {{ content, publicKey }} params The content to encrypt and public key
 * to encrypt to
 * @param {SymmKey|Uint8Array|string} [aesKey] An optional AES key to encrypt
 * to the given public key
 *
 * @returns {Promise<{content, key}>} The encrypted content and encrypted key
 */
export async function encryptTo ({ content, publicKey }:{
    content:string|Uint8Array;
    publicKey:CryptoKey|string;
}, aesKey?:SymmKey|Uint8Array|string):Promise<EncryptedMessage> {
    const key = aesKey || await AES.create()
    const encryptedContent = await AES.encrypt(
        typeof content === 'string' ? fromString(content) : content,
        typeof key === 'string' ? await AES.import(key) : key
    )
    const encryptedKey = await encryptKeyTo({
        content: (key instanceof CryptoKey ? await AES.export(key) : key),
        publicKey
    })

    return { content: encryptedContent, key: encryptedKey }
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

    async export (key:CryptoKey):Promise<Uint8Array> {
        const raw = await webcrypto.subtle.exportKey('raw', key)
        return new Uint8Array(raw)
    },

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
        const encrypted = iv ? await webcrypto.subtle.encrypt(
            { name: AES_GCM, iv },
            key,
            data
        ) : await encryptBytes(data, key)

        return new Uint8Array(encrypted)
    },

    async decrypt (
        encryptedData:Uint8Array|string,
        cryptoKey:CryptoKey|Uint8Array|ArrayBuffer,
        iv?:Uint8Array
    ) {
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

function importAesKey (key:Uint8Array|ArrayBuffer):Promise<CryptoKey> {
    return webcrypto.subtle.importKey(
        'raw',
        key,
        {
            name: AES_GCM,
            length: SymmKeyLength.B256,
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
    const iv:ArrayBuffer = opts?.iv || randomBuf(12)
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
    const iv = cipherText.slice(0, 12)
    const cipherBytes = cipherText.slice(12)
    const msgBuff = await webcrypto.subtle.decrypt({
        name: DEFAULT_SYMM_ALGORITHM,
        iv
    }, importedKey, cipherBytes)

    return msgBuff
}
