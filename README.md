# keys
[![tests](https://img.shields.io/github/actions/workflow/status/substrate-system/keys/nodejs.yml?style=flat-square)](https://github.com/substrate-system/keys/actions/workflows/nodejs.yml)
[![types](https://img.shields.io/npm/types/@substrate-system/keys?style=flat-square)](README.md)
[![module](https://img.shields.io/badge/module-ESM%2FCJS-blue?style=flat-square)](README.md)
[![semantic versioning](https://img.shields.io/badge/semver-2.0.0-blue?logo=semver&style=flat-square)](https://semver.org/)
[![Common Changelog](https://nichoth.github.io/badge/common-changelog.svg)](./CHANGELOG.md)
[![install size](https://flat.badgen.net/packagephobia/install/@substrate-system/keys?cache-control=no-cache)](https://packagephobia.com/result?p=@substrate-system/keys)
[![GZip size](https://flat.badgen.net/bundlephobia/minzip/@substrate-system/keys)](https://bundlephobia.com/package/@substrate-system/keys)
[![license](https://img.shields.io/badge/license-Big_Time-blue?style=flat-square)](LICENSE)


Create and store keypairs in the browser with the [web crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API).

Use [indexedDB](https://developer.mozilla.org/en-US/docs/Web/API/IndexedDB_API)
to store [non-extractable keypairs](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/generateKey#extractable)
in the browser. "Non-extractable" means that the browser prevents you from ever
reading the private key, but the keys can be persisted and re-used indefinitely.

>
> [!TIP]
> Use the [persist method](https://developer.mozilla.org/en-US/docs/Web/API/StorageManager/persist)
> to tell the browser not to delete from `indexedDB`.
>

Each instance of `Keys` has two keypairs -- one for signing, and another for
encrypting. 

See also, [the API docs generated from typescript](https://substrate-system.github.io/keys/).

<details><summary><h2>Contents</h2></summary>

<!-- toc -->

- [Install](#install)
- [Modules](#modules)
  * [`exports`](#exports)
  * [ESM](#esm)
  * [Common JS](#common-js)
  * [pre-built JS](#pre-built-js)
- [Get started](#get-started)
  * [Verify a signature](#verify-a-signature)
  * [ECC](#ecc)
  * [some notes about the `keys` instance](#some-notes-about-the-keys-instance)
  * [Delete a keypair](#delete-a-keypair)
  * [Sign and Verify Something](#sign-and-verify-something)
  * [encrypt something](#encrypt-something)
  * [decrypt something](#decrypt-something)
- [examples](#examples)
  * [Create a new `Keys` instance](#create-a-new-keys-instance)
  * [Get a hash of the DID](#get-a-hash-of-the-did)
  * [Persist the keys](#persist-the-keys)
  * [Restore from indexedDB](#restore-from-indexeddb)
  * [Sign something](#sign-something)
  * [Get a signature as a string](#get-a-signature-as-a-string)
  * [Verify a signature](#verify-a-signature-1)
  * [Encrypt a key](#encrypt-a-key)
  * [Asymmetrically encrypt some arbitrary data](#asymmetrically-encrypt-some-arbitrary-data)
  * [Asymmetrically encrypt a string, return a new string](#asymmetrically-encrypt-a-string-return-a-new-string)
  * [Decrypt a message](#decrypt-a-message)
  * [Backward compatibility: `.decrypt.asString`](#backward-compatibility-decryptasstring)
  * [In memory only](#in-memory-only)
- [AES](#aes)
  * [`create`](#create)
  * [`export`](#export)
  * [`exportAsString`](#exportasstring)
  * [`AES.encrypt`](#aesencrypt)
  * [`AES.decrypt`](#aesdecrypt)

<!-- tocstop -->

</details>


## Install

```sh
npm i -S @substrate-system/keys
```

## Modules

### `exports`

This exposes ESM and common JS via [package.json `exports` field](https://nodejs.org/api/packages.html#exports).

### ESM
```js
import { EccKeys, verify } from '@substrate-system/keys/ecc'
import { RsaKeys, verify } from '@substrate-system/keys/rsa'
import { AES } from '@substrate-system/keys/aes'
```

### Common JS
```js
const { EccKeys, verify } = require('@substrate-system/keys/ecc')
const { RsaKeys, verify } = require('@substrate-system/keys/rsa')
const { AES } = require('@substrate-system/keys/aes')
```

### pre-built JS
This package exposes minified JS files too. Copy them to a location that is
accessible to your web server, then link to them in HTML.

#### copy
```sh
cp ./node_modules/@substrate-system/keys/dist/index.min.js ./public/keys.min.js
```

#### HTML
```html
<script type="module" src="./keys.min.js"></script>
```

------------------------------------------------------


## Get started

### Verify a signature

This function takes either an Ed25519 key or an RSA key.

```js
import { verify } from '@substrate-system/keys/crypto'

// ed25519
const isOk = await verify({ message, publicKey: ecc.DID, signature })

// RSA
const isOk = await verify({ message, publicKey: rsa.DID, signature })
```

### ECC

#### Create a keypair
Create a new keypair, then save it in `indexedDB`.

ECC is now supported in all major browsers.

```js
import { EccKeys, verify } from '@substrate-system/keys/ecc'

const keys = await EccKeys.create()

// save the keys to indexedDB
await keys.persist()

// ... sometime in the future ...
// get our keys from indexedDB
const keysAgain = await EccKeys.load()

console.assert(keys.DID === keysAgain.DID)  // true
```

### some notes about the `keys` instance

#### `keys.DID`

```js
'did:key:z13V3Sog2YaUKhdGCmgx9UZuW...'
```

This is the [DID string](https://www.w3.org/TR/did-1.0/) for the signing key for
this instance. The DID looks like this:

The Ed25519 DID looks like this:

```
did:key:zStERvoWtx7FQS432smzbGENZHjsN55X8pUZ3np8DXGhZFf3TCorijCPeJoLytwb
```

The RSA DID looks like this:

```
did:key:z13V3Sog2YaUKhdGCmgx9UZuW1o1ShFJYc6DvGYe7NTt689NoL2HdpC46K4PjfsUVAopaqmnySjJV8T6K9dMB2FUXhqfKYLUz9o9fA7xkgiNr25sUQq4vJPuPfP1kbSqtYXe5V2CZTUMucF2jfNMrWjHHRUZpEzPwGeZd5prsu9pxnVhPKnVxxKTJAVqQCp3CDRASeYKQmqVRmyPSrdQaYz4AoQxaBd52mNC7dEC4xXKbVw45dhQc52j5chR8YKCeaNANWh8DEZ7U8Dtb89PL5qP8817oxswQhz4e97p8EGtJDVrGbCXN4EucnpYaacRane4YPcmevs1pMYV8iqzJd8UZLWtDcUBNrCkeVTdnzXnM4Rq9sWiFwF3nYk6fxqfUZDfYyfPtxacSoGaSjo38ye
```

#### `keys.getDeviceName` / `keys.deviceName`

Return a 32 character, DNS friendly hash of the signing public key.

```js
const name = await keys.getDeviceName()

// a promise is exposed as property `deviceName`
const name = await keys.deviceName
```

#### `keys.hasPersisted`

A flag indicating whether `.persist` has been called, meaning that these keys
are saved in `indexedDB`.

#### `keys.publicExchangeKey`

The public encryption `CryptoKey`. For ECC keys, this is the X25519 exchange key.
For RSA keys, this is the RSA encryption key.

#### `keys.publicExchangeKeyAsString()`

Get the public encryption key as a `base64` string. For other formats,
[see below](#format-options).

```ts
{
  async publicExchangeKeyAsString (format?:SupportedEncodings):Promise<string>
}
```

#### `keys.publicWriteKey`

The public signing `CryptoKey`. This is the Ed25519 or RSA signing key.

#### `keys.publicWriteKeyAsString()`

Get the public signing key as a string.

```ts
{
  async publicWriteKeyAsString (format?:SupportedEncodings):Promise<string>
}
```

### Delete a keypair

Delete the keys from `indexedDB`.

```js
await keys.delete()
```

--------------------------------------------------------------------------


### Sign and Verify Something

`.verify` takes the content, the signature, and the DID for the public key
used to sign. The DID is exposed as the property `.DID` on a `Keys` instance.

>
> [!NOTE]  
> `verify` is exposed as a separate function, so you don't
> have to include all of `Keys` just to verify a signature.
>

```js
import { RsaKeys, verify } from '@substrate-system/keys/rsa'
// or: import { EccKeys, verify } from '@substrate-system/keys/ecc'

const keys = await RsaKeys.create()
// or: const keys = await EccKeys.create()

// sign something
const sig = await keys.signAsString('hello string')
// or string format: const sig = await keys.sign.asString('hello string')

// verify the signature
const isOk = await verify('hello string', sig, keys.DID)
```

### encrypt something
Take the public key we are encrypting to, return encrypted content.

#### `keys.encrypt` methods

Encrypt something, return a Uint8Array.

**ECC:**

>
> [!NOTE]  
> `recipient` is optional. If it is omitted, then this will encrypt to
> its own public key, a "note to self."
>

```ts
async encrypt (
  content:string|Uint8Array,
  recipient?:CryptoKey|string,  // their public key
  info?:string,
  aesKey?:SymmKey|Uint8Array|string,
  keysize?:SymmKeyLength
):Promise<Uint8Array>
```

**RSA:**
```ts
async encrypt (
  content:string|Uint8Array,
  recipient?:CryptoKey|string,
  aesKey?:SymmKey|Uint8Array|string,  // For RSA, can pass in AES key
  keysize?:SymmKeyLength,
):Promise<Uint8Array>
```

#### `keys.encryptAsString` methods

Encrypt something, return a string.

**ECC:**
```ts
async encryptAsString (
  content:string|Uint8Array,
  recipient?:CryptoKey|string,
  info?:string,
  aesKey?:SymmKey|Uint8Array|string,
  keysize?:SymmKeyLength,
):Promise<string>
```

**RSA:**
```ts
async encryptAsString (
  content:string|Uint8Array,
  recipient?:CryptoKey|string,
  aesKey?:SymmKey|Uint8Array|string,
  keysize?:SymmKeyLength,
):Promise<string>
```

```js
import { encryptTo } from '@substrate-system/keys/rsa'  // RSA version

// need to know the public key we are encrypting for
const publicKey = await keys.publicExchangeKeyAsString()  // Both ECC and RSA

const encrypted = await encryptTo({
  content: 'hello public key',
  publicKey
})  // => ArrayBuffer

const encrypted = await encryptTo.asString({
  content: 'hello public key',
  publicKey
})  // => <encrypted text>
```

### decrypt something
A `Keys` instance has a method `decrypt`. The `encryptedMessage` argument is
an `ArrayBuffer`, as returned from `encryptTo`, above.

```js
import { EccKeys } from '@substrate-system/keys/ecc'
// or: import { RsaKeys } from '@substrate-system/keys/rsa'

const keys = await EccKeys.create()
// or: const keys = await RsaKeys.create()

// This will decrypt the message using our own public key
const decrypted = await keys.decrypt(encryptedMsg)
```

----------------------------------------------------------------------

## examples

### Create a new `Keys` instance

Use the factory function `EccKeys.create` or `RsaKeys.create`. The optional parameters,
`encryptionKeyName` and `signingKeyName`, are added as properties to the
`keys` instance. These are used as indexes for saving the keys in `indexedDB`.

**ECC:**
```ts
class EccKeys {
  static EXCHANGE_KEY_NAME:string = 'ecc-exchange'
  static WRITE_KEY_NAME:string = 'ecc-write'

  static async create (session?:boolean):Promise<EccKeys>
}
```

**RSA:**
```ts
class RsaKeys {
  static EXCHANGE_KEY_NAME:string = 'rsa-exchange'
  static WRITE_KEY_NAME:string = 'rsa-write'

  static async create (session?:boolean):Promise<RsaKeys>
}
```

#### `.create()` example

Use the factory function b/c async.

```js
import { EccKeys } from '@substrate-system/keys/ecc'
// or: import { RsaKeys } from '@substrate-system/keys/rsa'

const keys = await EccKeys.create()
```

### Get a hash of the DID
Get a 32-character, DNS-friendly string of the hash of the given `DID`.
Available as static or instance method. If called as an instance method,
this will use the `DID` assigned to the given `Keys` instance.

The static method requires a `DID` string to be passed in.

#### static method

```ts
class EccKeys {  // or RsaKeys
  static async deviceName (did:DID):Promise<string>
}
```

#### instance method

If used as an instance method, this will use the `DID` assigned to the instance.

```ts
class EccKeys {  // or RsaKeys
  async getDeviceName ():Promise<string>
}
```

### Persist the keys
Save the keys to `indexedDB`. This depends on the values of the static class
properties `EXCHANGE_KEY_NAME` and `WRITE_KEY_NAME`.
Set them if you want to change the indexes under which the keys are
saved to `indexedDB`.

By default we use these:
- **ECC**: `'ecc-exchange'` and `'ecc-write'`
- **RSA**: `'rsa-exchange'` and `'rsa-write'`

#### `.persist`

```ts
class EccKeys {  // or RsaKeys
  async persist ():Promise<void>
}
```

#### `.persist` example
```js
import { EccKeys } from '@substrate-system/keys/ecc'

const keys = await EccKeys.create()
EccKeys.EXCHANGE_KEY_NAME = 'encryption-key-custom-name'
EccKeys.WRITE_KEY_NAME = 'signing-key-custom-name'
await keys.persist()
```

### Restore from indexedDB
Create a `Keys` instance from data saved to `indexedDB`. Pass in different
`indexedDB` key names for the keys if you need to.

#### `static .load`
```ts
class EccKeys {  // or RsaKeys
    static async load (opts?:{
      encryptionKeyName?:string,
      signingKeyName?:string,
      session?:boolean,
    }):Promise<EccKeys>
}
```

#### example
```js
import { EccKeys } from '@substrate-system/keys/ecc'
// or: import { RsaKeys } from '@substrate-system/keys/rsa'

const newKeys = await EccKeys.load()
```


### Sign something
Create a new signature for the given input.

**ECC:**
```ts
async sign (msg:Msg, _charsize?:CharSize):Promise<Uint8Array>
```

**RSA:**
```ts
async sign (
  msg:Msg,
  charsize:CharSize = DEFAULT_CHAR_SIZE
):Promise<Uint8Array>
```

#### example
```js
const sig = await keys.sign('hello signatures')
```

### Get a signature as a string

#### `keys.signAsString(msg)`

Sign a message and return the signature as a base64 encoded string.

```ts
{
  async signAsString (msg:string, charsize?:CharSize):Promise<string>
}
```

```js
const sig = await keys.signAsString('hello string')
// => ubW9PIjb360v...
```

#### Backward compatibility: `keys.sign.asString(msg)`

For backward compatibility, the `.asString` method is still available:

```js
const sig = await keys.sign.asString('hello string')
// => ubW9PIjb360v...
```

### Verify a signature
Check if a given signature is valid. This is exposed as a stateless function so
that it can be used independently from any keypairs. You need to pass in the
data that was signed, the signature, and the `DID` string of the public key used
to create the signature.

This works the same for either RSA or ECC keys.

```ts
async function verify (
    msg:string|Uint8Array,
    sig:string|Uint8Array,
    signingDid:DID
):Promise<boolean>
```

**RSA verification uses RSA-PSS with SHA-256:**

```js
import { verify } from '@substrate-system/keys/rsa'

const isOk = await verify('hello string', sig, keys.DID)
```

**ECC verification uses Ed25519:**

```js
import { verify } from '@substrate-system/keys/ecc'

const isOk = await verify('hello string', sig, keys.DID)
```

### Encrypt a key

Use asymmetric (RSA) encryption to encrypt an AES key to the given public key.

```ts
async function encryptKeyTo ({ key, publicKey }:{
    key:string|Uint8Array|CryptoKey;
    publicKey:CryptoKey|Uint8Array|string;
}, format?:'uint8array'|'arraybuffer'):Promise<Uint8Array|ArrayBuffer>
```

#### example
```js
import { encryptKeyTo } from '@substrate-system/keys/rsa'

// pass in a CryptoKey
const encrypted = await encryptKeyTo({
    key: myAesKey,
    publicKey: keys.publicExchangeKey
})

// pass in a base64 string
const encryptedTwo = await encryptKeyTo({
  key: aesKey,
  publicKey: await keys.publicExchangeKeyAsString()
})  // => Uint8Array
```

#### encrypt a key, return a string

Encrypt the given key to the public key, and return the result as a
base64 string.

> !NOTE
> This is only relevant for RSA keys

```ts
import { encryptKeyTo } from '@substrate-system/keys/rsa'

encryptKeyTo.asString = async function ({ key, publicKey }:{
    key:string|Uint8Array|CryptoKey;
    publicKey:CryptoKey|string|Uint8Array;
}, format?:SupportedEncodings):Promise<string> {
```

#### format
`encryptKeyTo.asString` takes an optional second argument for
[the format](https://github.com/achingbrain/uint8arrays/blob/26684d4fa1a78f3e5c16e74bf13192e881db4fcf/src/util/bases.ts#L46)
of the returned string.
Format is anything supported by [uint8arrays](https://github.com/achingbrain/uint8arrays).
By default, if omitted, it is `base64`.


### Asymmetrically encrypt some arbitrary data

Encrypt the given message to the given public key. If an AES key is not
provided, one will be created. Use the AES key to encrypt the given
content, then encrypt the AES key to the given public key.

> !NOTE
> This is only relevant for RSA keys.
> If using ECC keys, a symmetric key is automatically generated
> via diffie-hellman.

The return value is an ArrayBuffer containing the encrypted AES key +
the `iv` + the encrypted content if using RSA. It is `salt` + `iv` + cipher text
if using ECC.

To decrypt, pass the returned value to `keys.decrypt`, where `keys` is an
instance with the corresponding private key.

```ts
async function encryptTo (
    opts:{
        content:string|Uint8Array;
        publicKey:CryptoKey|string;
    },
    aesKey?:SymmKey|Uint8Array|string,
):Promise<ArrayBuffer>
```

#### example
```js
import { encryptTo } from '@substrate-system/keys/rsa'

const encrypted = await encryptTo({
    content: 'hello encryption',
    publicKey: keys.publicExchangeKey
})

// => ArrayBuffer
```

### Asymmetrically encrypt a string, return a new string

Encrypt the given string, and return a new string that is the (encrypted) AES
key concatenated with the `iv` and cipher text. The
corresponding method `keys.decryptAsString` will know how to parse and
decrypt the resulting text.

Use the functions `encryptTo.asString` and `keys.decryptAsString`.

#### `keys.decryptAsString`

**ECC:**
```ts
async decryptAsString (
  msg:string|Uint8Array|ArrayBuffer,
  publicKey?:CryptoKey|string,
  aesAlgorithm?:string,
  info?:string,
):Promise<string>
```

**RSA:**
```ts
async decryptAsString (
  msg:string|Uint8Array|ArrayBuffer,
  keysize?:CryptoKey|string|SymmKeyLength,
  _aesAlgorithm?:string,
):Promise<string>
```

##### example

```js
import { RsaKeys, encryptTo } from '@substrate-system/keys/rsa'  // RSA example
// or: import { EccKeys } from '@substrate-system/keys/ecc'

const keys = await RsaKeys.create()
// or: const keys = await EccKeys.create()
const pubKey = await keys.publicExchangeKeyAsString()  // Both ECC and RSA
const msg = { type: 'test', content: 'hello' }
const cipherText = await encryptTo.asString({
    content: JSON.stringify(msg),
    // pass in a string public key or crypto key or Uint8Array
    publicKey: pubKey
})  // => string

const text = await keys.decryptAsString(cipherText)
const data = JSON.parse(text)
// => { type: 'test', content: 'hello' }
```

### Decrypt a message

**ECC:**
```ts
async decrypt (
  msg:string|Uint8Array|ArrayBuffer,
  publicKey?:CryptoKey|string,
  aesAlgorithm?:string,
  info?:string,
):Promise<ArrayBuffer>
```

> !NOTE
> ECC keys will use our own public key if it is not passed in.

**RSA:**
```ts
async decrypt (
  msg:string|Uint8Array|ArrayBuffer,
  keysize?:CryptoKey|string|SymmKeyLength,
  _aesAlgorithm?:string,
):Promise<Uint8Array>
```

```js
const decrypted = await keys.decrypt(encrypted)
// => ArrayBuffer (ECC) or Uint8Array (RSA)
```

### Backward compatibility: `.decrypt.asString`
Decrypt a message, and stringify the result.

```js
await keys.decrypt.asString(encryptedString)
// => 'hello encryption'
```

### In memory only
Create a keypair, but do not save it in `indexedDB`, even if you call `persist`.
Pass `true` as the session parameter to `.create` or pass `{ session: true }` to `.load`.

```js
import { EccKeys } from '@substrate-system/keys/ecc'
// or: import { RsaKeys } from '@substrate-system/keys/rsa'

const keys = await EccKeys.create(true)
// or: const keys = await RsaKeys.create(true)

// or pass it to `.load`
const keysTwo = await EccKeys.load({ session: true })
// or: const keysTwo = await RsaKeys.load({ session: true })
```

## AES
Expose several AES functions with nice defaults.

* algorithm: `AES-GCM`
* key size: `256`
* `iv` size: [`12` bytes](https://crypto.stackexchange.com/questions/41601/aes-gcm-recommended-iv-size-why-12-bytes) (96 bits)

```js
import { AES } from '@substrate-system/keys/aes'

const key = await AES.create(/* ... optional arguments ... */)
```

### `create`
Create a new AES key. By default uses 256 bits & GCM algorithm.

```ts
function create (opts:{ alg:string, length:number } = {
    alg: DEFAULT_SYMM_ALGORITHM,  // AES-GCM
    length: DEFAULT_SYMM_LENGTH  // 256
}):Promise<CryptoKey>
```

```ts
import { AES } from '@substrate-system/keys/aes'
const aesKey = await AES.create()
```

### `export`
Get the AES key as a `Uint8Array`.

```ts
  async function export (key:CryptoKey):Promise<Uint8Array>
```

```js
import { AES } from '@substrate-system/keys/aes'
const exported = await AES.export(aesKey)
```

### `exportAsString`
Get the key as a string, `base64` encoded.

```ts
async function asString (
  key:CryptoKey,
  format?:SupportedEncoding
):Promise<string>
```

```js
import { AES } from '@substrate-system/keys/aes'
const exported = await AES.export.asString(aesKey)
```

### `AES.encrypt`

Take a `Uint8Array`, return an encrypted `Uint8Array`.

```ts
async function encrypt (
  data:Uint8Array,
  cryptoKey:CryptoKey|Uint8Array,
  iv?:Uint8Array
):Promise<Uint8Array>
```

```js
import { AES } from '@substrate-system/keys/aes'
import { fromString } from 'uint8arrays'

const encryptedText = await AES.encrypt(fromString('hello AES'), aesKey)
```

### `AES.decrypt`
```ts
async function decrypt (
  encryptedData:Uint8Array|string,
  cryptoKey:CryptoKey|Uint8Array|ArrayBuffer,
  iv?:Uint8Array
):Promise<Uint8Array>
```

```js
import { AES } from '@substrate-system/keys/aes'

const decryptedText = await AES.decrypt(encryptedText, aesKey)
```
