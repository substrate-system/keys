export type DID = `did:key:z${string}`

export enum RsaSize {
    B1024 = 1024,
    B2048 = 2048,
    B4096 = 4096
}

export enum SymmKeyLength {
    B128 = 128,
    B192 = 192,
    B256 = 256,
}

export type EncryptedMessage = {
    content:string|Uint8Array;
    key:string|Uint8Array;
}

export enum HashAlg {
    SHA_1 = 'SHA-1',
    SHA_256 = 'SHA-256',
    SHA_384 = 'SHA-384',
    SHA_512 = 'SHA-512',
}

export enum KeyUse {
    Encrypt = 'encryption',  // encrypt/decrypt
    Sign = 'signing',  // sign
}

export type SymmKey = CryptoKey

export enum CharSize {
    B8 = 8,
    B16 = 16,
}

export type SymmAlgorithm = 'AES-CTR'|'AES-CBC'|'AES-GCM'
export type Msg = ArrayBuffer|string|Uint8Array

export type SymmKeyOpts = {
    alg:SymmAlgorithm
    length:SymmKeyLength
    iv:ArrayBuffer
}
