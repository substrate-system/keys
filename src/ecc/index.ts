import { type SupportedEncodings, toString, fromString } from 'uint8arrays'
import {
    DEFAULT_ECC_EXCHANGE,
    DEFAULT_ECC_WRITE,
    DEFAULT_SYMM_ALGORITHM,
    SALT_LENGTH,
    IV_LENGTH,
    DEFAULT_SYMM_LENGTH,
    ECC_WRITE_ALGORITHM,
    ECC_EXCHANGE_ALGORITHM,
    X25519_PUBLIC_KEY_LENGTH,
    WRAP_FORMAT_VERSION,
    AES_GCM_TAG_LENGTH
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
    type WrappedKey,
} from '../types.js'
import {
    base64ToArrBuf,
    normalizeToBuf,
    toBase64,
    didToPublicKey
} from '../util.js'
import { checkValidKeyUse } from '../errors.js'
import { AbstractKeys } from '../_base.js'
import { AES } from '../aes/index.js'

const webcrypto = globalThis.crypto

// Helper function to ensure proper ArrayBuffer type
function toArrayBuffer (data:Uint8Array):ArrayBuffer {
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

    /**
     * Factory function.
     * @param {boolean} [session] Session only? i.e., not saved in indexedDB.
     *   Default `false`.
     * @param {boolean} [extractable] Can we extract the private keys? Default
     *   `false`.
     * @param {{ dbKey, exchangeKeys, writeKeys }} [keys] Key options.
     *   `dbKey` prefixes the IndexedDB names used for both keypairs.
     * @returns {Promise<EccKeys>} A new class instance.
     */
    static async create<T extends AbstractKeys = EccKeys> (
        session?:boolean,
        extractable?:boolean,
        keys?:{
            dbKey?:string,
            exchangeKeys?:CryptoKeyPair|null,
            writeKeys?:CryptoKeyPair|null,
        }
    ):Promise<T> {
        return await super.create<T>(session, extractable, keys)
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

    static async _createExchangeKeys (
        extractable:boolean = false
    ):Promise<CryptoKeyPair> {
        /**
         * don't use `{ name: ECDH, namedCurve: 'X25519' }`, use
         * `{ name: 'X25519' }`.
         *
         * X25519/Ed25519 don't use `namedCurve`.
         */
        return await webcrypto.subtle.generateKey(
            {
                name: ECC_EXCHANGE_ALGORITHM
                // namedCurve: EccCurve.X25519
            },
            extractable,
            ['deriveKey', 'deriveBits']
        ) as CryptoKeyPair
    }

    static async _createWriteKeys (extractable:boolean = false):Promise<CryptoKeyPair> {
        return await webcrypto.subtle.generateKey(
            {
                name: ECC_WRITE_ALGORITHM
            },
            extractable,
            ['sign', 'verify']
        )
    }

    /**
     * Restore some keys from indexedDB, or create a new keypair if it doesn't
     * exist yet. Overrides base class to use ECC-specific key names.
     *
     * Saves the keys to `indexedDB` before returning, unless you pass
     * `{ persist: false }`.
     *
     * @param {{ dbKey }} [opts] Prefix for both IndexedDB key names.
     */
    static async load<T extends AbstractKeys = EccKeys> (
        this:typeof EccKeys,
        opts:Partial<{
            dbKey:string,
            encryptionKeyName:string,
            writeKeyName:string,
            session:boolean,
            extractable:boolean,
            persist:boolean,
        }> = {
            session: false,
        }
    ):Promise<T> {
        return super.load(opts) as Promise<T>
    }

    /**
     * Serialize this keys instance. Will return an object of
     * { DID, publicExchangeKey }, where DID is the public write key,
     * and `publicExchangeKey` is the encryption key, `base64` encoded.
     * @returns {Promise<{ DID:DID, publicExchangeKey:string }>}
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
     * "Add a device," meaning, take an existing AES key and add the ability
     * for a new keypair to decrypt/use the AES key.
     *
     * This implements HPKE-style key wrapping:
     *   1. Generate ephemeral X25519 keypair
     *   2. Do ECDH with recipient's public key -> shared secret
     *   3. Use HKDF to derive a KEK (key encryption key)
     *   4. AES-GCM encrypt the content
     *   5. Return the ephemeral public key (encapsulation) + wrapped key
     *
     * The result is signed with our Ed25519 write key, so the recipient
     * can verify who created the wrap. `unwrap` requires our DID and
     * rejects the wrap unless the signature matches it.
     *
     * @param {SymmKey|Uint8Array|string} contentKey The existing AES key used
     *   to encrypt the content. Can be a base64 encoded string.
     * @param {CryptoKey} newPublicKey The new device's public X25519 key.
     * @param {string} [info] Optional info parameter for HKDF.
     *   Defaults to 'key-wrap'.
     * @returns {Promise<WrappedKey>} The ephemeral public key (base64),
     *          the wrapped AES key (base64), and a signature (base64) by
     *          our write key.
     */
    async wrap (
        contentKey:SymmKey|Uint8Array|string,
        newPublicKey:CryptoKey,  // the new device's public key
        info?:string
    ):Promise<WrappedKey> {
        // 1. Generate ephemeral X25519 keypair. Only the public half is
        // ever exported, so the private half does not need to be
        // extractable.
        const ephemeralKeypair = await EccKeys._createExchangeKeys(false)

        // 2. Export the ephemeral and recipient public keys up front, so
        // they can be bound into the KEK derivation below (HPKE-style)
        const ephemeralPubKeyBuffer = await exportPublicKey(ephemeralKeypair)
        const ephemeralPubKeyBytes = new Uint8Array(ephemeralPubKeyBuffer)
        const recipientPubKey = new Uint8Array(
            await webcrypto.subtle.exportKey('raw', newPublicKey)
        )
        const baseInfo = info || 'key-wrap'

        // 3. Generate random salt for HKDF
        const salt = webcrypto.getRandomValues(new Uint8Array(SALT_LENGTH))

        // 4. Derive KEK using ECDH + HKDF with ephemeral private key and
        // recipient's public key. The HKDF `info` binds the ephemeral and
        // recipient public keys into the derivation, so a KEK can't be
        // replayed against a different ephemeral/recipient pairing.
        const kek = await deriveKey(
            ephemeralKeypair.privateKey,
            newPublicKey,
            salt,
            wrapKekInfo(ephemeralPubKeyBytes, recipientPubKey, baseInfo)
        )

        // 5. Prepare the content key for encryption. Buffers we allocate
        // ourselves (from a CryptoKey export or a base64 string) are
        // zeroed below once no longer needed; a caller-supplied
        // Uint8Array is left alone, since zeroing it would mutate memory
        // the caller still owns a reference to.
        let contentKeyBytes:Uint8Array
        let ownsContentKeyBytes = false
        if (contentKey instanceof CryptoKey) {
            // Export the AES key to raw format
            const exported = await webcrypto.subtle.exportKey('raw', contentKey)
            contentKeyBytes = new Uint8Array(exported)
            ownsContentKeyBytes = true
        } else if (typeof contentKey === 'string') {
            contentKeyBytes = fromString(contentKey, 'base64pad')
            ownsContentKeyBytes = true
        } else {
            contentKeyBytes = contentKey
        }

        // 6. Generate IV for AES-GCM encryption
        const iv = webcrypto.getRandomValues(new Uint8Array(IV_LENGTH))

        // 7. Encrypt the content key with the KEK
        const wrappedKeyBuffer = await webcrypto.subtle.encrypt(
            { name: DEFAULT_SYMM_ALGORITHM, iv },
            kek,
            toArrayBuffer(contentKeyBytes)
        )
        if (ownsContentKeyBytes) contentKeyBytes.fill(0)

        // 8. Combine version + salt + iv + wrapped key for the final
        // wrapped key blob. The version byte lets future format or
        // algorithm changes be detected in `unwrap` instead of silently
        // misparsed.
        const ivBuf = new Uint8Array(iv)
        const wrappedBuf = new Uint8Array(wrappedKeyBuffer)
        const combinedSize = 1 + SALT_LENGTH + ivBuf.length + wrappedBuf.length
        const combined = new Uint8Array(combinedSize)
        combined[0] = WRAP_FORMAT_VERSION
        combined.set(salt, 1)
        combined.set(ivBuf, 1 + SALT_LENGTH)
        combined.set(wrappedBuf, 1 + SALT_LENGTH + ivBuf.length)

        // 9. Sign the wrap with our write key, binding the ephemeral
        // public key, the recipient, the blob, and the info string
        const signData = wrapSignData(
            ephemeralPubKeyBytes,
            recipientPubKey,
            combined,
            baseInfo
        )
        const signature = await this.sign(signData)

        // 10. Return base64-encoded results
        return {
            enc: toBase64(ephemeralPubKeyBytes),
            wrappedKey: toBase64(combined),
            signature: toString(signature, 'base64pad')
        }
    }

    /**
     * Unwrap a content key that another device wrapped for this device
     * with `wrap`.
     *
     * The recipient device uses its private key + the ephemeral public key
     * to rederive the KEK and decrypt the wrapped content key.
     *
     * The wrap's signature is always checked against `signer` before
     * anything is decrypted, and this throws if the signature is missing
     * or invalid. `signer` must be the DID of the device you expect the
     * key from, obtained over a channel an attacker cannot tamper with.
     * A DID that travels alongside the wrapped key proves nothing, since
     * an attacker who can swap the wrapped key can swap the DID too.
     *
     * @param wrapped The `{ enc, wrappedKey, signature }` object returned
     *   by `wrap`.
     * @param signer The DID of the expected sender.
     * @param opts.info The HKDF info string. Must match what was passed to
     *   `wrap`. Defaults to 'key-wrap'.
     * @param opts.extractable Can the returned key be exported with
     *   `crypto.subtle.exportKey`? Default `true`.
     * @returns {Promise<CryptoKey>} The unwrapped AES content key.
     */
    async unwrap (
        wrapped:WrappedKey,
        signer:DID,
        opts:{ info?:string, extractable?:boolean } = {}
    ):Promise<CryptoKey> {
        const { enc, wrappedKey, signature } = wrapped
        const info = opts.info
        const extractable = opts.extractable ?? true

        // Fail closed for JS callers, or anyone who casts around the
        // types: an unsigned or unattributed wrap is never accepted.
        if (!signer) {
            throw new Error('`unwrap` requires the DID of the sender')
        }
        if (!signature) {
            throw new Error('The wrapped key is not signed')
        }

        // 1. Decode and validate the ephemeral public key and wrapped
        // key blob up front, so truncated/malformed input fails with a
        // clear error instead of an opaque `OperationError` deep inside
        // WebCrypto.
        const encBytes = fromString(enc, 'base64pad')
        if (encBytes.length !== X25519_PUBLIC_KEY_LENGTH) {
            throw new Error(
                `\`enc\` must be a ${X25519_PUBLIC_KEY_LENGTH}-byte ` +
                `X25519 public key, got ${encBytes.length} bytes`
            )
        }

        const wrappedBuf = new Uint8Array(base64ToArrBuf(wrappedKey))
        const baseInfo = info || 'key-wrap'
        const minWrappedLength = 1 + SALT_LENGTH + IV_LENGTH + AES_GCM_TAG_LENGTH
        if (wrappedBuf.length < minWrappedLength) {
            throw new Error(
                `Wrapped key must be at least ${minWrappedLength} bytes, ` +
                `got ${wrappedBuf.length} bytes`
            )
        }

        // 2. Check the format version, so a future format/algorithm
        // change can be detected instead of silently misparsed
        const version = wrappedBuf[0]
        if (version !== WRAP_FORMAT_VERSION) {
            throw new Error(
                `Unsupported wrapped key format version: ${version}`
            )
        }

        const ourPubKeyBytes = new Uint8Array(
            await exportPublicKey(this.exchangeKey)
        )

        // 3. Verify the sender's signature before decrypting anything
        const signData = wrapSignData(
            encBytes,
            ourPubKeyBytes,
            wrappedBuf,
            baseInfo
        )
        const isValid = await verify(signData, signature, signer)
        if (!isValid) {
            throw new Error('Invalid signature for the wrapped key')
        }

        // 4. Import the ephemeral public key
        const ephemeralPubKey = await importPublicKey(
            enc,
            EccCurve.X25519,
            KeyUse.Exchange
        )

        // 5. Extract salt, iv, and ciphertext (after the version byte)
        const salt = wrappedBuf.slice(1, 1 + SALT_LENGTH)
        const iv = wrappedBuf.slice(
            1 + SALT_LENGTH,
            1 + SALT_LENGTH + IV_LENGTH
        )
        const ciphertext = wrappedBuf.slice(1 + SALT_LENGTH + IV_LENGTH)

        // 6. Derive the same KEK using our private key and the ephemeral
        // public key. The HKDF `info` must match what `wrap` bound in:
        // the ephemeral public key + our own (recipient) public key.
        const kek = await deriveKey(
            this.exchangeKey.privateKey,
            ephemeralPubKey,
            salt,
            wrapKekInfo(encBytes, ourPubKeyBytes, baseInfo)
        )

        // 7. Decrypt the wrapped key
        const contentKeyBytes = await webcrypto.subtle.decrypt(
            { name: DEFAULT_SYMM_ALGORITHM, iv },
            kek,
            toArrayBuffer(ciphertext)
        )

        // 8. Import the content key back as a CryptoKey
        const contentKey = await webcrypto.subtle.importKey(
            'raw',
            contentKeyBytes,
            { name: DEFAULT_SYMM_ALGORITHM },
            extractable,
            ['encrypt', 'decrypt']
        )

        return contentKey
    }

    /**
     * Encrypt the given content to the given public key, or encrypt to
     * our own public key if a key is not passed in.
     *
     * This does ECIES style encryption -- a new ephemeral keypair is generated
     * and used to encrypt the message with ephemeral private + recipient public.
     * The public key from the ephemeral keypair is prefixed to the cipher text.
     *
     * @param {string|Uint8Array} content Content to encrypt
     * @param {CryptoKey|string} [recipient] Their public key. Optional b/c we
     *        will use our own public key if not passed in. Can be a CryptoKey
     *        or a base64 encoded string.
     * @param {string} [info] info tag for HKDF. Default is the class property.
     * @param {SymmKey|Uint8Array|string} [aesKey] Use this exact AES key
     *        instead of deriving one from ECDH. Not relevant for most use
     *        cases. Pass the same key to `decrypt` to read it back.
     * @param {SymmKeyLength} [keysize] Default is 256
     * @returns {Promise<ArrayBuffer>} Buffer of ephemeral-public-key + salt +
     *          iv + cipher text
     */
    async encrypt (
        content:string|Uint8Array,
        recipient?:CryptoKey|string|null,  // their public key
        info?:string|null,
        aesKey?:SymmKey|Uint8Array|string|null,
        keysize?:SymmKeyLength|null
    ):Promise<Uint8Array> {
        const salt = webcrypto.getRandomValues(new Uint8Array(SALT_LENGTH))

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

        // ECIES: Generate ephemeral keypair for this encryption. Only the
        // public half is ever exported, so the private half does not need
        // to be extractable.
        const ephemeralKeypair = await EccKeys._createExchangeKeys(false)

        // honor a caller-supplied key end to end; otherwise derive one
        // using the ephemeral private key
        const key = aesKey ?
            (aesKey instanceof CryptoKey ? aesKey : await AES.import(aesKey)) :
            await deriveKey(
                ephemeralKeypair.privateKey,  // use ephemeral private key
                publicKey,
                salt,
                info || EccKeys.INFO,
                keysize
            )

        const iv = webcrypto.getRandomValues(new Uint8Array(IV_LENGTH))
        const plaintext:Uint8Array = (typeof content === 'string' ?
            new TextEncoder().encode(content) :
            content)

        const ciphertext = await webcrypto.subtle.encrypt(
            { name: DEFAULT_SYMM_ALGORITHM, iv },
            key,
            toArrayBuffer(plaintext)
        )

        // Export ephemeral public key to prepend to ciphertext
        const ephemeralPubKeyBuf = new Uint8Array(
            await exportPublicKey(ephemeralKeypair)
        )

        // Prepend ephemeral public key, salt and IV to the ciphertext
        const saltBuffer = new Uint8Array(salt)
        const ivBuffer = new Uint8Array(iv)
        const cipherBuf = new Uint8Array(ciphertext)
        const size = ephemeralPubKeyBuf.length + saltBuffer.length +
            ivBuffer.length + cipherBuf.length
        const result = new Uint8Array(size)
        result.set(ephemeralPubKeyBuf, 0)
        result.set(saltBuffer, ephemeralPubKeyBuf.length)
        result.set(ivBuffer, ephemeralPubKeyBuf.length + saltBuffer.length)
        result.set(cipherBuf, ephemeralPubKeyBuf.length + saltBuffer.length +
            ivBuffer.length)

        return result
    }

    /**
     * Encrypt and return as base64 string.
     */
    async encryptAsString (
        content:string|Uint8Array,
        recipient?:CryptoKey|string|null,  // their public key
        info?:string|null,
        aesKey?:SymmKey|Uint8Array|string|null,
        keysize?:SymmKeyLength|null,
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
     * ephemeral public key + salt + iv + cipher text.
     *
     * The ephemeral public key is extracted from the beginning of the message
     * and used with our private key to derive the AES decryption key.
     *
     * @param msg The encrypted content
     * @param {string} aesAlgorithm The algorithm. Default is AES-GCM.
     * @param {string} info Custom "info" parameter
     * @param {SymmKey|Uint8Array|string} [aesKey] Use this exact AES key
     *        instead of deriving one from ECDH. Must match the `aesKey`
     *        passed to the corresponding `encrypt` call.
     * @returns {Promise<ArrayBuffer>} The decrypted content.
     */
    async decrypt (
        msg:string|Uint8Array|ArrayBuffer,
        aesAlgorithm?:string|null,
        info?:string|null,
        aesKey?:SymmKey|Uint8Array|string|null,
    ):Promise<ArrayBuffer|Uint8Array> {
        // ECIES: Extract ephemeral public key from the beginning of the message
        const encrypted = normalizeToBuf(msg, base64ToArrBuf)
        const ephemeralPubKeyBuf = encrypted.slice(0, X25519_PUBLIC_KEY_LENGTH)

        // ephemeral public key should be prepended to the data
        const ephemeralPublicKey = await webcrypto.subtle.importKey(
            'raw',
            ephemeralPubKeyBuf,
            { name: ECC_EXCHANGE_ALGORITHM },
            true,
            []
        )

        // Extract salt, iv, and ciphertext after the ephemeral public key
        const salt = encrypted.slice(
            X25519_PUBLIC_KEY_LENGTH,
            X25519_PUBLIC_KEY_LENGTH + SALT_LENGTH
        )
        const iv = encrypted.slice(
            X25519_PUBLIC_KEY_LENGTH + SALT_LENGTH,
            X25519_PUBLIC_KEY_LENGTH + SALT_LENGTH + IV_LENGTH
        )
        const ciphertext = encrypted.slice(
            X25519_PUBLIC_KEY_LENGTH + SALT_LENGTH + IV_LENGTH
        )

        // honor a caller-supplied key end to end; otherwise derive one
        // with our private key + the ephemeral public key
        const { privateKey } = this.exchangeKey
        const key = aesKey ?
            (aesKey instanceof CryptoKey ? aesKey : await AES.import(aesKey)) :
            await deriveKey(
                privateKey,
                ephemeralPublicKey,
                salt,
                info || EccKeys.INFO
            )

        // we have the key, now decrypt the message
        const decrypted = await webcrypto.subtle.decrypt(
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
     * Decrypt and return as string using ECIES. The encrypted message should be
     * ephemeral public key + salt + iv + cipher text.
     *
     * The ephemeral public key is extracted from the beginning of the message
     * and used with our private key to derive the AES decryption key.
     *
     * @param msg The encrypted content
     * @param {string} aesAlgorithm The algorithm. Default is AES-GCM.
     * @param {string} info Custom "info" parameter
     * @returns {Promise<string>} The decrypted content as a string.
     */
    async decryptAsString (
        msg:string|Uint8Array|ArrayBuffer,
        aesAlgorithm?:string|null,
        info?:string|null,
        aesKey?:SymmKey|Uint8Array|string|null,
    ):Promise<string> {
        const dec = await this.decrypt(msg, aesAlgorithm, info, aesKey)
        return toString(new Uint8Array(dec))
    }

    /**
     * Do DHKE, create a new AES-GCM key.
     *
     * The HKDF salt is either supplied by the caller (so both sides can
     * re-derive the exact same key later) or generated at random, in
     * which case it is returned as a `.salt` (base64) property on the
     * key so the caller can persist it for later re-derivation.
     *
     * @param {CryptoKey|string|null} [publicKey] Public key to use in DHKE.
     *        Will use our public key if it is not passed in.
     * @param {string} info The info parameter for DHKE. Will use the class
     *        property `INFO` if it is not passed in.
     * @param {Uint8Array|ArrayBuffer|string|null} [salt] Reuse this salt
     *        instead of generating a random one -- pass the same salt on
     *        both sides to re-derive the same key.
     * @returns {CryptoKey} New AES key, with a `.salt` (base64) property
     */
    async getAesKey (
        publicKey?:CryptoKey|string|null,
        info?:string|null,
        salt?:Uint8Array|ArrayBuffer|string|null,
    ):Promise<CryptoKey & { salt:string }> {
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

        // Reuse the given salt, or generate a random one for HKDF
        const saltBytes:Uint8Array = (salt ?
            new Uint8Array(
                typeof salt === 'string' ? base64ToArrBuf(salt) : salt
            ) :
            webcrypto.getRandomValues(new Uint8Array(SALT_LENGTH)))

        // Derive AES key using ECDH + HKDF
        const aesKey = await deriveKey(
            this.exchangeKey.privateKey,
            pub,
            saltBytes,
            info || EccKeys.INFO
        )

        // expose the salt used, so a randomly-generated one isn't lost
        return Object.assign(aesKey, { salt: toBase64(saltBytes) })
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
            { name: ECC_WRITE_ALGORITHM },
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
export async function exportPublicKey(
    keypair:CryptoKeyPair,
    format:'jwk'
):Promise<JsonWebKey>

export async function exportPublicKey(
    keypair:CryptoKeyPair,
    format?:'raw'|'spki'|'pkcs8'
):Promise<ArrayBuffer>

export async function exportPublicKey (
    keypair:CryptoKeyPair,
    format:KeyFormat = 'raw'
):Promise<JsonWebKey|ArrayBuffer> {
    return await webcrypto.subtle.exportKey(format, keypair.publicKey)
}

export async function importPublicKey (
    base64Key:string,
    curve:EccCurve,
    use:KeyUse
):Promise<PublicKey> {
    checkValidKeyUse(use)
    const alg = use === KeyUse.Exchange ? ECC_EXCHANGE_ALGORITHM : ECC_WRITE_ALGORITHM
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
        aesAlgorithm?: string
    ): Promise<string> {
        return this.decryptAsString(msg, aesAlgorithm)
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
            { name: ECC_WRITE_ALGORITHM },
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
            { name: ECC_WRITE_ALGORITHM },
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
 * Build the HKDF `info` used to derive a `wrap`/`unwrap` KEK: the
 * ephemeral public key + recipient public key + the caller's info string
 * (HPKE-style). Binding both public keys into the derivation means a KEK
 * can only ever be reconstructed for this exact ephemeral/recipient
 * pairing. The two public keys are fixed-length X25519 keys, so they
 * can't be shifted into each other or into the trailing, variable-length
 * info string.
 */
function wrapKekInfo (
    ephemeralPubKey:Uint8Array,
    recipientPubKey:Uint8Array,
    info:string
):Uint8Array {
    const infoBytes = new TextEncoder().encode(info)
    const data = new Uint8Array(
        ephemeralPubKey.length + recipientPubKey.length + infoBytes.length
    )
    data.set(ephemeralPubKey, 0)
    data.set(recipientPubKey, ephemeralPubKey.length)
    data.set(infoBytes, ephemeralPubKey.length + recipientPubKey.length)
    return data
}

/**
 * Build the message that `wrap` signs and `unwrap` verifies:
 * ephemeral public key + recipient public key + wrapped key blob + info.
 * The blob gets a length prefix so variable-length fields can't be
 * shifted into each other.
 */
function wrapSignData (
    ephemeralPubKey:Uint8Array,
    recipientPubKey:Uint8Array,
    wrappedBlob:Uint8Array,
    info:string
):Uint8Array {
    const infoBytes = new TextEncoder().encode(info)
    const blobLength = new Uint8Array(4)
    new DataView(blobLength.buffer).setUint32(0, wrappedBlob.length)

    const data = new Uint8Array(
        ephemeralPubKey.length + recipientPubKey.length +
        blobLength.length + wrappedBlob.length + infoBytes.length
    )
    let offset = 0
    data.set(ephemeralPubKey, offset)
    offset += ephemeralPubKey.length
    data.set(recipientPubKey, offset)
    offset += recipientPubKey.length
    data.set(blobLength, offset)
    offset += blobLength.length
    data.set(wrappedBlob, offset)
    offset += wrappedBlob.length
    data.set(infoBytes, offset)

    return data
}

/**
 * Derive an AES key from X25519 keypair via ECDH + HKDF.
 * @param {string|Uint8Array} info Passing a `Uint8Array` lets callers bind
 *   extra transcript data (e.g. the ephemeral and recipient public keys)
 *   into the HKDF `info` field, HPKE-style.
 */
async function deriveKey (
    privateKey:CryptoKey,
    publicKey:CryptoKey,
    salt:Uint8Array|ArrayBuffer,
    info:string|Uint8Array,
    keysize?:number|null
):Promise<CryptoKey> {
    const encoder = new TextEncoder()
    const infoBytes = typeof info === 'string' ? encoder.encode(info) : info
    const sharedSecret = await webcrypto.subtle.deriveBits(
        { name: 'X25519', public: publicKey },
        privateKey,
        256
    )

    const hkdfBaseKey = await webcrypto.subtle.importKey(
        'raw',
        sharedSecret,
        'HKDF',
        false,
        ['deriveKey']
    )

    return webcrypto.subtle.deriveKey(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: salt instanceof Uint8Array ? toArrayBuffer(salt) : salt,
            info: toArrayBuffer(infoBytes)
        },
        hkdfBaseKey,
        { name: 'AES-GCM', length: keysize || DEFAULT_SYMM_LENGTH },
        false,
        ['encrypt', 'decrypt']
    )
}
