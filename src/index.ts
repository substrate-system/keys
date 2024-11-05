import { webcrypto } from '@bicycle-codes/one-webcrypto'
import { set } from 'idb-keyval'
import {
    RSA_ALGORITHM,
    DEFAULT_RSA_SIZE,
    DEFAULT_HASH_ALGORITHM,
    RSA_SIGN_ALGORITHM,
    DEFAULT_CHAR_SIZE
} from './constants'
import {
    KeyUse,
    type RsaSize,
    type HashAlg,
    type DID,
    type Msg,
    type CharSize
} from './types'
import {
    publicKeyToDid,
    getPublicKeyAsArrayBuffer,
    rsaOperations
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
