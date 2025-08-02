import { RsaSize, HashAlg, CharSize, EccCurve } from './types.js'

export const BASE58_DID_PREFIX = 'did:key:z'

// ECC
export const ECC_WRITE_ALG = 'Ed25519'
export const ECC_EXCHANGE_ALG = 'X25519'
export const DEFAULT_ECC_EXCHANGE_CURVE = EccCurve.X25519
export const ECC_WRITE_NAME = 'Ed25519'
export const ECC_EXCHANGE_NAME = EccCurve.X25519

export const KEY_USE = {
    sign: ['sign', 'verify'],
    encrypt: ['deriveKey', 'deriveBits']
}

// RSA
export const RSA_ALGORITHM = 'RSA-OAEP'
export const RSA_SIGN_ALGORITHM = 'RSASSA-PKCS1-v1_5'
export const RSA_HASHING_ALGORITHM = 'SHA-256'
export const RSA_DID_PREFIX = new Uint8Array([0x00, 0xf5, 0x02])
export const DEFAULT_RSA_SIZE = RsaSize.B2048
export const DEFAULT_HASH_ALGORITHM = HashAlg.SHA_256
export const DEFAULT_CHAR_SIZE = CharSize.B8

// AES
export const AES_GCM = 'AES-GCM' as const
export const DEFAULT_SYMM_ALGORITHM = AES_GCM
export const DEFAULT_SYMM_LENGTH = 256
export const IV_LENGTH = 12

// Misc
export const BLS_DID_PREFIX = new Uint8Array([0xea, 0x01])
export const EDWARDS_DID_PREFIX = new Uint8Array([0xed, 0x01])
export const KEY_TYPE = {
    RSA: 'rsa',
    Edwards: 'ed25519',
    BLS: 'bls12-381'
} as const

// app specific
export const DEFAULT_RSA_EXCHANGE = 'rsa-exchange-key'
export const DEFAULT_RSA_WRITE = 'rsa-write-key'
export const DEFAULT_ECC_EXCHANGE = 'ecc-exchange'
export const DEFAULT_ECC_WRITE = 'ecc-write'
export const SALT_LENGTH = 16
