import { webcrypto } from '@substrate-system/one-webcrypto'
import { fromString, concat, toString as uToString } from 'uint8arrays'
import tweetnacl from 'tweetnacl'
import type {
    DID,
    Msg,
    HashAlg,
    SymmKeyOpts,
    SymmKey,
    RsaSize
} from './types.js'
import {
    KeyUse,
    CharSize,
} from './types.js'
import {
    BASE58_DID_PREFIX,
    KEY_USE,
    RSA_SIGN_ALGORITHM,
    RSA_ALGORITHM,
    DEFAULT_HASH_ALGORITHM,
    DEFAULT_CHAR_SIZE,
    RSA_SALT_LENGTH,
    RSA_HASHING_ALGORITHM,
    RSA_DID_PREFIX,
    KEY_TYPE,
    EDWARDS_DID_PREFIX,
    BLS_DID_PREFIX,
    DEFAULT_SYMM_ALGORITHM,
    DEFAULT_SYMM_LENGTH,
} from './constants.js'

export type VerifyArgs = {
    message:Uint8Array
    publicKey:Uint8Array
    signature:Uint8Array
}

/**
 * Using the key type as the record property name (ie. string = key type)
 *
 * The magic bytes are the `code` found in {@link https://github.com/multiformats/multicodec/blob/master/table.csv}
 * encoded as a variable integer (more info about that at {@link https://github.com/multiformats/unsigned-varint)}.
 *
 * The key type is also found in that table.
 * It's the name of the codec minus the `-pub` suffix.
 *
 * Example
 * -------
 * Ed25519 public key
 * Key type: "ed25519"
 * Magic bytes: [ 0xed, 0x01 ]
 */
type KeyTypes = Record<string, {
    magicBytes:Uint8Array
    verify:(args:VerifyArgs)=>Promise<boolean>
}>

export const did:{ keyTypes:KeyTypes } = {
    keyTypes: {
        'bls12-381': {
            magicBytes: new Uint8Array([0xea, 0x01]),
            verify: () => { throw new Error('Not implemented') },
        },
        rsa: {
            magicBytes: new Uint8Array([0x00, 0xf5, 0x02]),
            verify: rsaVerify,
        },
        ed25519: {
            magicBytes: new Uint8Array([0xed, 0x01]),
            verify: ed25519Verify
        },
    }
}

export async function ed25519Verify ({
    message,
    publicKey,
    signature
}:VerifyArgs):Promise<boolean> {
    return tweetnacl.sign.detached.verify(message, signature, publicKey)
}

/**
 * Create a 32 character, DNS-friendly hash of the given DID.
 *
 * @param {DID} did String representation of the DID for the device
 * @returns {string} The 32 character, DNS friendly hash
 */
export async function createDeviceName (did:DID):Promise<string> {
    const normalizedDid = did.normalize('NFD')
    const hashedUsername = await sha256(
        new TextEncoder().encode(normalizedDid)
    )
    return uToString(hashedUsername, 'base32').slice(0, 32)
}

export async function sha256 (bytes:Uint8Array):Promise<Uint8Array> {
    return new Uint8Array(await webcrypto.subtle.digest('sha-256', bytes))
}

/**
 * Convert a public key to a DID format string.
 *
 * @param {Uint8Array|CryptoKey|CryptoKeyPair} publicKey Public key as Uint8Array
 * @param {'rsa'} [keyType] 'rsa' or 'ecc'
 * @returns {DID} A DID format string
 */
export async function publicKeyToDid (
    _publicKey:Uint8Array|CryptoKey,
    keyType:'rsa'|'ed25519' = 'rsa'
):Promise<DID> {
    const publicKey = ((_publicKey instanceof CryptoKey) ?
        new Uint8Array(await getPublicKeyAsArrayBuffer(_publicKey)) :
        _publicKey
    )

    // Prefix public-write key
    const prefix = did.keyTypes[keyType]?.magicBytes
    if (!prefix) {
        throw new Error(`Key type '${keyType}' not supported, ` +
            `available types: ${Object.keys(did.keyTypes).join(', ')}`)
    }

    const prefixedBuf = concat([prefix, publicKey])

    return (BASE58_DID_PREFIX + uToString(prefixedBuf, 'base58btc')) as DID
}

export const rsaOperations = {
    verify: async function rsaVerify (
        msg:Msg,
        sig:Msg,
        publicKey:string|CryptoKey,
        charSize:CharSize = DEFAULT_CHAR_SIZE,
        hashAlg:HashAlg = DEFAULT_HASH_ALGORITHM
    ):Promise<boolean> {
        return webcrypto.subtle.verify(
            {
                name: RSA_SIGN_ALGORITHM,
                saltLength: RSA_SALT_LENGTH
            },
            (typeof publicKey === 'string' ?
                await importPublicKey(publicKey, hashAlg, KeyUse.Sign) :
                publicKey),
            normalizeBase64ToBuf(sig),
            normalizeUnicodeToBuf(msg, charSize)
        )
    },

    sign: async function sign (
        msg:Msg,
        privateKey:CryptoKey,
        charSize:CharSize = DEFAULT_CHAR_SIZE
    ):Promise<ArrayBuffer> {
        return webcrypto.subtle.sign(
            { name: RSA_SIGN_ALGORITHM, saltLength: RSA_SALT_LENGTH },
            privateKey,
            normalizeUnicodeToBuf(msg, charSize)
        )
    },

    /**
     * Encrypt the given AES key *to* a given public key.
     */
    encrypt: async function rsaEncrypt (
        msg:Msg,
        publicKey:string|CryptoKey|Uint8Array,
        charSize:CharSize = DEFAULT_CHAR_SIZE,
        hashAlg:HashAlg = DEFAULT_HASH_ALGORITHM
    ):Promise<ArrayBuffer> {
        let pubKey:CryptoKey
        if (typeof publicKey === 'string') {
            pubKey = await importPublicKey(publicKey, hashAlg, KeyUse.Exchange)
        } else {
            pubKey = publicKey instanceof Uint8Array ?
                await importPublicKey(publicKey, hashAlg, KeyUse.Exchange) :
                publicKey
        }

        return webcrypto.subtle.encrypt(
            { name: RSA_ALGORITHM },
            pubKey,
            normalizeUnicodeToBuf(msg, charSize)
        )
    },

    /**
     * Use RSA to decrypt the given data.
     */
    decrypt: async function rsaDecrypt (
        _data:Uint8Array|string|ArrayBuffer,
        privateKey:CryptoKey|Uint8Array|ArrayBuffer
    ):Promise<Uint8Array> {
        const key = isCryptoKey(privateKey) ?
            privateKey :
            await importRsaKey(privateKey, ['decrypt'])

        let data:Uint8Array|ArrayBuffer
        if (typeof _data === 'string') {
            data = fromString(_data, 'base64pad')
        } else {
            data = _data
        }

        const arrayBuffer = await webcrypto.subtle.decrypt(
            { name: RSA_ALGORITHM },
            key,
            data
        )

        const arr = new Uint8Array(arrayBuffer)

        return arr
    }
}

export async function rsaVerify ({
    message,
    publicKey,
    signature
}:{
    message: Uint8Array
    publicKey: Uint8Array
    signature: Uint8Array
}):Promise<boolean> {
    return rsaOperations.verify(
        message,
        signature,
        await webcrypto.subtle.importKey(
            'spki',
            publicKey,
            { name: RSA_SIGN_ALGORITHM, hash: RSA_HASHING_ALGORITHM },
            false,
            ['verify']
        ),
        8
    )
}

export async function importPublicKey (
    base64Key:string|ArrayBuffer,
    hashAlg:HashAlg,
    use:KeyUse
):Promise<CryptoKey> {
    checkValidKeyUse(use)
    const alg = (use === KeyUse.Exchange ? RSA_ALGORITHM : RSA_SIGN_ALGORITHM)
    const uses:KeyUsage[] = use === KeyUse.Exchange ?
        ['encrypt'] :
        ['verify']
    const buf = typeof base64Key === 'string' ?
        base64ToArrBuf(stripKeyHeader(base64Key)) :
        base64Key

    return webcrypto.subtle.importKey('spki', buf, {
        name: alg,
        hash: { name: hashAlg }
    }, true, uses)
}

export const InvalidKeyUse = new Error("Invalid key use. Please use 'encryption' or 'signing")
export const InvalidMaxValue = new Error('Max must be less than 256 and greater than 0')

export function checkValidKeyUse (use:KeyUse):void {
    checkValid(use, [KeyUse.Sign, KeyUse.Exchange], InvalidKeyUse)
}

function checkValid<T> (toCheck: T, opts: T[], error: Error): void {
    const match = opts.some(opt => opt === toCheck)
    if (!match) {
        throw error
    }
}

function stripKeyHeader (base64Key:string):string {
    return base64Key
        .replace('-----BEGIN PUBLIC KEY-----\n', '')
        .replace('\n-----END PUBLIC KEY-----', '')
}

export function base64ToArrBuf (string:string):ArrayBuffer {
    return fromString(string, 'base64pad').buffer
}

export const normalizeToBuf = (
    msg:Msg,
    strConv:(str:string)=>ArrayBuffer
):ArrayBuffer => {
    if (typeof msg === 'string') {
        return strConv(msg)
    } else if (typeof msg === 'object' && msg.byteLength !== undefined) {
        // this is the best runtime check I could find for ArrayBuffer/Uint8Array
        const temp = new Uint8Array(msg)
        return temp.buffer
    } else {
        throw new Error('Improper value. Must be a string, ArrayBuffer, Uint8Array')
    }
}

export function normalizeBase64ToBuf (msg:Msg):ArrayBuffer {
    return normalizeToBuf(msg, base64ToArrBuf)
}

export const normalizeUtf8ToBuf = (msg:Msg): ArrayBuffer => {
    return normalizeToBuf(msg, (str) => strToArrBuf(str, CharSize.B8))
}

export function strToArrBuf (str:string, charSize:CharSize):ArrayBuffer {
    const view = charSize === 8 ?
        new Uint8Array(str.length) :
        new Uint16Array(str.length)

    for (let i = 0, strLen = str.length; i < strLen; i++) {
        view[i] = str.charCodeAt(i)
    }

    return view.buffer
}

export const normalizeUtf16ToBuf = (msg:Msg): ArrayBuffer => {
    return normalizeToBuf(msg, (str) => strToArrBuf(str, CharSize.B16))
}

export function normalizeUnicodeToBuf (msg:Msg, charSize:CharSize) {
    switch (charSize) {
        case 8: return normalizeUtf8ToBuf(msg)
        default: return normalizeUtf16ToBuf(msg)
    }
}

export function importRsaKey (
    key:Uint8Array|ArrayBuffer,
    keyUsages:KeyUsage[]
):Promise<CryptoKey> {
    return webcrypto.subtle.importKey(
        'spki',
        key,
        { name: RSA_ALGORITHM, hash: RSA_HASHING_ALGORITHM },
        false,
        keyUsages
    )
}

export function isCryptoKey (val:unknown):val is CryptoKey {
    return (
        hasProp(val, 'algorithm') &&
        hasProp(val, 'extractable') &&
        hasProp(val, 'type')
    )
}

function hasProp<K extends PropertyKey> (
    data:unknown,
    prop:K
): data is Record<K, unknown> {
    return (typeof data === 'object' && data != null && prop in data)
}

export async function getPublicKeyAsArrayBuffer (
    keypair:CryptoKeyPair|CryptoKey
):Promise<ArrayBuffer> {
    const spki = (keypair instanceof CryptoKey ?
        await webcrypto.subtle.exportKey(
            'spki',
            keypair
        ) :
        await webcrypto.subtle.exportKey(
            'spki',
            keypair.publicKey
        )
    )

    return spki
}

export async function getPublicKeyAsUint8Array (
    keypair:CryptoKeyPair|CryptoKey
):Promise<Uint8Array> {
    const arr = await getPublicKeyAsArrayBuffer(keypair)
    return new Uint8Array(arr)
}

export function didToPublicKey (did:string):({
    publicKey:Uint8Array,
    type:'rsa' | 'ed25519' | 'bls12-381'
}) {
    if (!did.startsWith(BASE58_DID_PREFIX)) {
        throw new Error(
            'Please use a base58-encoded DID formatted `did:key:z...`')
    }

    const didWithoutPrefix = ('' + did.substring(BASE58_DID_PREFIX.length))
    const magicalBuf = fromString(didWithoutPrefix, 'base58btc')
    const { keyBuffer, type } = parseMagicBytes(magicalBuf)

    return {
        publicKey: new Uint8Array(keyBuffer),
        type
    }
}

/**
 * Parse magic bytes on prefixed key-buffer
 * to determine cryptosystem & the unprefixed key-buffer.
 */
function parseMagicBytes (prefixedKey:ArrayBuffer) {
    // RSA
    if (hasPrefix(prefixedKey, RSA_DID_PREFIX)) {
        return {
            keyBuffer: prefixedKey.slice(RSA_DID_PREFIX.byteLength),
            type: KEY_TYPE.RSA
        }
    // EDWARDS
    } else if (hasPrefix(prefixedKey, EDWARDS_DID_PREFIX)) {
        return {
            keyBuffer: prefixedKey.slice(EDWARDS_DID_PREFIX.byteLength),
            type: KEY_TYPE.Edwards
        }
    // BLS
    } else if (hasPrefix(prefixedKey, BLS_DID_PREFIX)) {
        return {
            keyBuffer: prefixedKey.slice(BLS_DID_PREFIX.byteLength),
            type: KEY_TYPE.BLS
        }
    }

    throw new Error('Unsupported key algorithm. Try using RSA.')
}

const arrBufs = {
    equal: (aBuf:ArrayBuffer, bBuf:ArrayBuffer) => {
        const a = new Uint8Array(aBuf)
        const b = new Uint8Array(bBuf)
        if (a.length !== b.length) return false
        for (let i = 0; i < a.length; i++) {
            if (a[i] !== b[i]) return false
        }
        return true
    }
}

function hasPrefix (prefixedKey:ArrayBuffer, prefix:ArrayBuffer) {
    return arrBufs.equal(prefix, prefixedKey.slice(0, prefix.byteLength))
}

export function toBase64 (arr:Uint8Array|ArrayBuffer) {
    return uToString(
        arr instanceof ArrayBuffer ?
            new Uint8Array(arr) :
            arr,
        'base64pad'
    )
}

export function fromBase64 (str:string) {
    return fromString(str, 'base64pad')
}

export async function importKey (
    key:string|Uint8Array,
    opts?:Partial<SymmKeyOpts>
):Promise<SymmKey> {
    const buf = typeof key === 'string' ? base64ToArrBuf(key) : key

    return webcrypto.subtle.importKey(
        'raw',
        buf,
        {
            name: opts?.alg || DEFAULT_SYMM_ALGORITHM,
            length: opts?.length || DEFAULT_SYMM_LENGTH,
        },
        true,
        ['encrypt', 'decrypt']
    )
}

export function randomBuf (
    length:number,
    { max }:{ max:number } = { max: 255 }
):ArrayBuffer {
    if (max < 1 || max > 255) {
        throw InvalidMaxValue
    }

    const arr = new Uint8Array(length)

    if (max === 255) {
        webcrypto.getRandomValues(arr)
        return arr.buffer
    }

    let index = 0
    const interval = max + 1
    const divisibleMax = Math.floor(256 / interval) * interval
    const tmp = new Uint8Array(1)

    while (index < arr.length) {
        webcrypto.getRandomValues(tmp)
        if (tmp[0] < divisibleMax) {
            arr[index] = tmp[0] % interval
            index++
        }
    }

    return arr.buffer
}

export function joinBufs (fst:ArrayBuffer, snd:ArrayBuffer):ArrayBuffer {
    const view1 = new Uint8Array(fst)
    const view2 = new Uint8Array(snd)
    const joined = new Uint8Array(view1.length + view2.length)
    joined.set(view1)
    joined.set(view2, view1.length)
    return joined.buffer
}

export async function makeEccKeypair (
    curve:'X25519'|'ECDSA',
    uses:'encyrpt'|'sign'
):Promise<CryptoKeyPair> {
    const keys = await webcrypto.subtle.generateKey(
        { name: curve },  // X25519 or ECDSA
        false,  // extractable
        KEY_USE[uses]
    ) as CryptoKeyPair

    return keys
}

export async function makeRSAKeypair (
    size:RsaSize,
    hashAlg:HashAlg,
    use:KeyUse
):Promise<CryptoKeyPair> {
    if (!(Object.values(KeyUse).includes(use))) {
        throw new Error('invalid key use')
    }
    const alg = use === KeyUse.Exchange ? RSA_ALGORITHM : RSA_SIGN_ALGORITHM
    const uses:KeyUsage[] = (use === KeyUse.Exchange ?
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

export async function getDeviceName (did:DID|string) {
    const hashedUsername = await sha256(
        new TextEncoder().encode(did.normalize('NFD'))
    )

    return uToString(hashedUsername, 'base32').slice(0, 32)
}
