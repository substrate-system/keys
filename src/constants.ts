import { RsaSize, HashAlg, CharSize } from './types'

export const BASE58_DID_PREFIX = 'did:key:z'

export const RSA_ALGORITHM = 'RSA-OAEP'
export const RSA_SIGN_ALGORITHM = 'RSASSA-PKCS1-v1_5'
export const RSA_HASHING_ALGORITHM = 'SHA-256'

export const DEFAULT_RSA_SIZE = RsaSize.B2048
export const DEFAULT_HASH_ALGORITHM = HashAlg.SHA_256
export const DEFAULT_CHAR_SIZE = CharSize.B8

export const SALT_LENGTH = 128
