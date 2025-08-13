import { webcrypto } from '@substrate-system/one-webcrypto'
import { fromString, toString as uToString, concat } from 'uint8arrays'
import tweetnacl from 'tweetnacl'
import {
    type VerifyArgs,
    toArrayBuffer,
    normalizeBase64ToBuf,
    normalizeUnicodeToBuf,
    base64ToArrBuf,
    InvalidKeyUse,
    hasPrefix
} from './util.js'
import {
    DEFAULT_HASH_ALGORITHM,
    DEFAULT_CHAR_SIZE,
    SALT_LENGTH,
    RSA_SIGN_ALGORITHM,
    RSA_HASHING_ALGORITHM,
    RSA_ALGORITHM,
    BASE58_DID_PREFIX
} from './constants.js'
import {
    type Msg,
    type HashAlg,
    KeyUse,
    type CharSize,
    type DID
} from './types.js'

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

/**
 * Verify either Ed25519 or RSA
 */
export async function verify ({
    message,
    publicKey,
    signature
}:VerifyArgs) {

}

/**
 * Convert a DID (did:key) to a base64 public key.
 */
export function didToPublicKey (inputDid:string): {
  publicKey: Uint8Array
  type: string
} {
    if (!did.startsWith(BASE58_DID_PREFIX)) {
        throw new Error('Please use a base58-encoded DID formatted `did:key:z...`')
    }

    const didWithoutPrefix = inputDid.substr(BASE58_DID_PREFIX.length)
    const magicalBuf = fromString(didWithoutPrefix, 'base58btc')
    const result = Object.entries(did.keyTypes).find(
        ([_key, attr]) => hasPrefix(magicalBuf, attr.magicBytes)
    )

    if (!result) {
        throw new Error('Unsupported key algorithm.')
    }

    return {
        publicKey: magicalBuf.slice(result[1].magicBytes.length),
        type: result[0]
    }
}

export async function ed25519Verify ({
    message,
    publicKey,
    signature
}:VerifyArgs):Promise<boolean> {
    return tweetnacl.sign.detached.verify(message, signature, publicKey)
}

export async function rsaVerify ({
    message,
    publicKey,
    signature
}:VerifyArgs):Promise<boolean> {
    return rsaOperations.verify(
        message,
        signature,
        await webcrypto.subtle.importKey(
            'spki',
            toArrayBuffer(publicKey),
            { name: RSA_SIGN_ALGORITHM, hash: RSA_HASHING_ALGORITHM },
            false,
            ['verify']
        ),
        8
    )
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
                saltLength: SALT_LENGTH
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
            { name: RSA_SIGN_ALGORITHM, saltLength: SALT_LENGTH },
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
                await importPublicKey(toArrayBuffer(publicKey), hashAlg, KeyUse.Exchange) :
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
            data instanceof Uint8Array ? toArrayBuffer(data) : data
        )

        const arr = new Uint8Array(arrayBuffer)

        return arr
    }
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

export function importRsaKey (
    key:Uint8Array|ArrayBuffer,
    keyUsages:KeyUsage[]
):Promise<CryptoKey> {
    return webcrypto.subtle.importKey(
        'spki',
        key instanceof Uint8Array ? toArrayBuffer(key) : key,
        { name: RSA_ALGORITHM, hash: RSA_HASHING_ALGORITHM },
        false,
        keyUsages
    )
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
