# keys
![tests](https://github.com/bicycle-codes/keys/actions/workflows/nodejs.yml/badge.svg)
[![types](https://img.shields.io/npm/types/@bicycle-codes/keys?style=flat-square)](README.md)
[![module](https://img.shields.io/badge/module-ESM%2FCJS-blue?style=flat-square)](README.md)
[![semantic versioning](https://img.shields.io/badge/semver-2.0.0-blue?logo=semver&style=flat-square)](https://semver.org/)
[![Common Changelog](https://nichoth.github.io/badge/common-changelog.svg)](./CHANGELOG.md)
[![install size](https://flat.badgen.net/packagephobia/install/@bicycle-codes/keys?cache-control=no-cache)](https://packagephobia.com/result?p=@bicycle-codes/keys)
[![license](https://img.shields.io/badge/license-Polyform_Non_Commercial-26bc71?style=flat-square)](LICENSE)


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
encrypting. We are **using RSA keys only** right now, because we are
[waiting for all browsers to support ECC](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/generateKey#browser_compatibility).

See also, [the API docs generated from typescript](https://bicycle-codes.github.io/keys/).

## install

```sh
npm i -S @bicycle-codes/keys
```

<details><summary><h2>Contents</h2></summary>

<!-- toc -->

- [Asymmetric Encryption](#asymmetric-encryption)
- [Modules](#modules)
  * [`exports`](#exports)
  * [ESM](#esm)
  * [Common JS](#common-js)
  * [pre-built JS](#pre-built-js)
- [get started](#get-started)
  * [Create a keypair](#create-a-keypair)
  * [some notes about the `keys` instance](#some-notes-about-the-keys-instance)
  * [sign and verify something](#sign-and-verify-something)
  * [encrypt something](#encrypt-something)
  * [decrypt something](#decrypt-something)
- [examples](#examples)
  * [Create a new `Keys` instance](#create-a-new-keys-instance)
  * [Get a hash of the DID](#get-a-hash-of-the-did)
  * [Persist the keys](#persist-the-keys)
  * [Restore from indexedDB](#restore-from-indexeddb)
  * [Sign something](#sign-something)
  * [Get a signature as a string](#get-a-signature-as-a-string)
  * [Verify a signature](#verify-a-signature)
  * [Encrypt a key](#encrypt-a-key)
  * [Asymmetrically encrypt some arbitrary data](#asymmetrically-encrypt-some-arbitrary-data)
  * [Asymmetrically encrypt a string, return a new string](#asymmetrically-encrypt-a-string-return-a-new-string)
  * [Decrypt a message](#decrypt-a-message)
  * [`.decrypt.asString`](#decryptasstring)
- [AES](#aes)
  * [`create`](#create)
  * [`export`](#export)
  * [`exportAsString`](#exportasstring)
  * [`AES.encrypt`](#aesencrypt)
  * [`AES.decrypt`](#aesdecrypt)

<!-- tocstop -->

</details>


## Asymmetric Encryption

Asymmetric encryption means using an AES key to encrypt the content, then
encrypting the AES key to a public RSA key. If you encrypt something to Bob's
public key, that means we create a new buffer of encrypted AES key +
encrypted content, where the encrypted AES key can only be decrypted by Bob's
private key.

## Modules

### `exports`

This exposes ESM and common JS via [package.json `exports` field](https://nodejs.org/api/packages.html#exports).

### ESM
```js
import { Keys } from '@bicycle-codes/keys'
```

### Common JS
```js
const { Keys } = require('@bicycle-codes/keys')
```

### pre-built JS
This package exposes minified JS files too. Copy them to a location that is
accessible to your web server, then link to them in HTML.

#### copy
```sh
cp ./node_modules/@bicycle-codes/keys/dist/index.min.js ./public/keys.min.js
```

#### HTML
```html
<script type="module" src="./keys.min.js"></script>
```

------------------------------------------------------


## get started

### Create a keypair
Create a new keypair, then save it in `indexedDB`.

```js
import { Keys } from '@bicycle-codes/keys'

const keys = await Keys.create()

// save the keys to indexedDB
await keys.persist()

// ... sometime in the future ...
// get our keys from indexedDB
const keysAgain = await Keys.load()

console.assert(keys.DID === keysAgain.DID)  // true
```

### some notes about the `keys` instance

#### `keys.DID`

This is the [DID string](https://www.w3.org/TR/did-1.0/) for the signing key for
this instance.

#### `keys.getDeviceName` / `keys.deviceName`

Return the 32 character, DNS friendly hash of the signing public key.

```js
const name = await keys.getDeviceName()

// a promise is exposed as property `deviceName`
const name = await keys.deviceName
```

#### `keys.persisted`

A flag indicating whether `.persist` has been called, meaning that these keys
are saved in `indexedDB`.

#### `keys.publicEncryptKey`

The public encryption `CryptoKey`.

#### `keys.getPublicEncryptKey()`

Get the public encryption key, as a `base64` string. For other formats,
[see below](#keysgetpublicencryptkeyformat).

```ts
{
  async getPublicEncryptKey ():Promise<string>
}
```

#####  `keys.getPublicEncryptKey(format)`

Get the public encryption key. The given format should be a
[supported encoding](https://github.com/achingbrain/uint8arrays/blob/26684d4fa1a78f3e5c16e74bf13192e881db4fcf/src/util/bases.ts#L46) in
[uint8arrays](https://github.com/achingbrain/uint8arrays).

```ts
{
  async getPublicEncryptKey (
    format?:SupportedEncodings
  ):Promise<string>
}
```

#### keys.getPublicEncryptKey.uint8Array

Get the public encryption key as a `Uint8Array`.

```ts
{
  function uint8Array:()=>Promise<Uint8Array<ArrayBufferLike>>
}
```


--------------------------------------------------------------------------


### sign and verify something
`.verify` takes the content, the signature, and the DID for the public key
used to sign. The DID is exposed as the property `.DID` on a `Keys` instance.

>
> [!NOTE]  
> `verify` is exposed as a separate function, so you don't
> have to include all of `Keys` just to verify a signature.
>

```js
import { Keys, verify } from '@bicycle-codes/keys'

const keys = await Keys.create()

// sign something
const sig = await keys.sign.asString('hello string')

// verify the signature
const isOk = await verify('hello string', sig, keys.DID)
```

### encrypt something
Take the public key we are encrypting to, return an `ArrayBuffer`, containing
the encrypted AES key concattenated with the `iv` and encrypted content.


```js
import { encryptTo } from '@bicycle-codes/keys'

// need to know the public key we are encrypting for
const publicKey = await keys.getPublicEncryptKey()

const encrypted = await encryptTo({
  content: 'hello public key',
  publicKey
})  // => ArrayBuffer

const encrypted = await encryptTo.asString({
  content: 'hello public key',
  publicKey
})
// => <encrypted text>
```

### decrypt something
A `Keys` instance has a method `decrypt`. The `encryptedMessage` argument is
an `ArrayBuffer` as returned from `encryptTo`, above.

```js
import { Keys } from '@bicycle-codes/keys'

const keys = await Keys.create()
// ...
const decrypted = await keys.decrypt(encryptedMsg)
```

----------------------------------------------------------------------

## examples

### Create a new `Keys` instance

Use the factory function `Keys.create`. The optional parameters,
`encryptionKeyName` and `signingKeyName`, are added as properties to the
`keys` instance -- `ENCRYPTION_KEY_NAME` and `SIGNING_KEY_NAME`. These are
used as indexes for saving the keys in `indexedDB`.

```ts
class Keys {
  ENCRYPTION_KEY_NAME:string = 'encryption-key'
  SIGNING_KEY_NAME:string = 'signing-key'

  static async create (opts?:{
      encryptionKeyName:string,
      signingKeyName:string
  }):Promise<Keys>
}
```

#### `.create()` example

Use the factory function b/c async.

```js
import { Keys } from '@bicycle-codes/keys'

const keys = await Keys.create()
```

### Get a hash of the DID
Get a 32-character, DNS-friendly string of the hash of the given `DID`.
Available as static or instance method. If called as an instance method,
this will use the `DID` assigned to the given `Keys` instance.

The static method requires a `DID` string to be passed in.

#### static method

```ts
class Keys {
  static async deviceName (did:DID):Promise<string>
}
```

#### instance method

If used as an instance method, this will use the `DID` assigned to the instance.

```ts
class Keys {
  async getDeviceName ():Promise<string>
}
```

### Persist the keys
Save the keys to `indexedDB`. This depends on the values of class properties
`ENCRYPTION_KEY_NAME` and `SIGNING_KEY_NAME`. Set them if you want to change the
indexes under which the keys are saved to `indexedDB`.

By default we use these:
```js
const DEFAULT_ENC_NAME = 'encryption-key'
const DEFAULT_SIG_NAME = 'signing-key'
```

#### `.persist`

```ts
class Keys {
  async persist ():Promise<void>
}
```

#### `.persist` example
```js
import { Keys } from '@bicycle-codes/keys'

const keys = await Keys.create()
keys.ENCRYPTION_KEY_NAME = 'encryption-key-custom-name'
keys.SIGNING_KEY_NAME = 'signing-key-custom-name'
await keys.persist()
```

### Restore from indexedDB
Create a `Keys` instance from data saved to `indexedDB`. Pass in different
`indexedDB` key names for the keys if you need to.

#### `static .load`
```ts
class Keys {
    static async load (opts:{
      encryptionKeyName,
      signingKeyName
    } = {
      encryptionKeyName: DEFAULT_ENC_NAME,
      signingKeyName: DEFAULT_SIG_NAME
    }):Promise<Keys>
}
```

#### example
```js
import { Keys } from '@bicycle-codes/keys'

const newKeys = await Keys.load()
```


### Sign something
Create a new signature for the given input.

```ts
class Keys {
  async sign (
    msg:ArrayBuffer|string|Uint8Array,
    charsize?:CharSize,
  ):Promise<Uint8Array>
}
```

#### example
```js
const sig = await keys.sign('hello signatures')
```

### Get a signature as a string

#### `keys.sign.asString(msg)`

```ts
{
  /**
   * Sign a message, return the signature as a base64 encoded string.
   *
   * @param {Msg} msg The message to sign
   * @param {CharSize} [charsize] Character size
   * @returns {Promise<string>}
   */
  asString: async (msg:Msg, charsize?:CharSize):Promise<string>
}
```

```js
const sig = await keys.sign.asString('hello string')
// => ubW9PIjb360v...
```

### Verify a signature
Check if a given signature is valid. This is exposed as a stateless function so
that it can be used independently from any keypairs. You need to pass in the
data that was signed, the signature, and the `DID` string of the public key used
to create the signature.

```ts
async function verify (
    msg:string|Uint8Array,
    sig:string|Uint8Array,
    signingDid:DID
):Promise<boolean>
```

```js
import { verify } from '@bicycle-codes/keys'

const isOk = await verify('hello string', sig, keys.DID)
```

### Encrypt a key

Use asynchronous (RSA) encryption to encrypt an AES key to the given public key.

```ts
async function encryptKeyTo ({ key, publicKey }:{
    key:string|Uint8Array|CryptoKey;
    publicKey:CryptoKey|Uint8Array|string;
}, format?:'uint8array'|'arraybuffer'):Promise<Uint8Array|ArrayBuffer>
```

#### example
```js
import { encryptKeyTo } from '@bicycle-codes/keys'

// pass in a CryptoKey
const encrypted = await encryptKeyTo({
    key: myAesKey,
    publicKey: keys.publicEncryptKey
})

// pass in a base64 string
const encryptedTwo = await encryptKeyTo({
  key: aesKey,
  publicKey: await keys.getPublicEncryptKey()
})  // => Uint8Array
```

#### encrypt a key, return a string

Encrypt the given key to the public key, and return the result as a
base64 string.

```ts
import { encryptKeyTo } from '@bicycle-codes/keys'

encryptKeyTo.asString = async function ({ key, publicKey }:{
    key:string|Uint8Array|CryptoKey;
    publicKey:CryptoKey|string|Uint8Array;
}, format?:SupportedEncodings):Promise<string> {
```

#### format
`encryptKeyTo.asString` takes an optional second argument for [the format](https://github.com/achingbrain/uint8arrays/blob/26684d4fa1a78f3e5c16e74bf13192e881db4fcf/src/util/bases.ts#L46)
of the returned string. Format is anything supported by [uint8arrays](https://github.com/achingbrain/uint8arrays). By default, if omitted, it is `base64`.


### Asymmetrically encrypt some arbitrary data

Encrypt the given message to the given public key. If an AES key is not
provided, one will be created. Use the AES key to encrypt the given
content, then encrypt the AES key to the given public key.

The return value is an ArrayBuffer containing the encrypted AES key +
the `iv` + the encrypted content.

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
import { encryptTo } from '@bicycle-codes/keys'

const encrypted = await encryptTo({
    content: 'hello encryption',
    publicKey: keys.publicEncryptKey
})

// => ArrayBuffer
```

### Asymmetrically encrypt a string, return a new string

Encrypt the given string, and return a new string that is the (encrypted) AES
key concattenated with the `iv` and cipher text. The
corresponding method `keys.decrypt.asString` will know how to parse and
decrypt the resulting text.

Use the functions `encryptTo.asString` and `keys.decrypt.asString`.

#### `keys.decrypt.asString`
```ts
async function asString (msg:string, keysize?:SymmKeyLength):Promise<string> 
```

```js
import { Keys, encryptTo } from '@bicycle-codes/keys'

const keys = await Keys.create()
const pubKey = await keys.getPublicEncryptKey()
const msg = { type: 'test', content: 'hello' }
const cipherText = await encryptTo.asString({
    content: JSON.stringify(msg),
    // pass in a string public key or crypto key or Uint8Array
    publicKey: pubKey
})  // => string

const text = await keys.decrypt.asString(cipherText)
const data = JSON.parse(text)
// => { type: 'test', content: 'hello' }
```

### Decrypt a message
```ts
class Keys {
  async decrypt (
    msg:string|Uint8Array|ArrayBuffer,
    keysize?:SymmKeyLength
  ):Promise<Uint8Array>
}
```

```js
const decrypted = await keys.decrypt(encrypted)
// => Uint8Array
```

### `.decrypt.asString`
Decrypt a message, and stringify the result.

```ts
{
  async function asString (msg:EncryptedMessage):Promise<string>
}
```

```js
await keys.decrypt.asString(encryptedString)
// => 'hello encryption'
```

## AES
Expose several AES functions with nice defaults.

* algorithm: `AES-GCM`
* key size: `256`
* `iv` size: [`12` bytes](https://crypto.stackexchange.com/questions/41601/aes-gcm-recommended-iv-size-why-12-bytes) (96 bits)

```js
import { AES } from '@bicycle-codes/keys'

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
import { AES } from '@bicycle-codes/keys'
const aesKey = await AES.create()
```

### `export`
Get the AES key as a `Uint8Array`.

```ts
  async function export (key:CryptoKey):Promise<Uint8Array>
```

```js
import { AES } from '@bicycle-codes/keys'
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
import { AES } from '@bicycle-codes/keys'
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
import { AES } from '@bicycle-codes/keys'
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
import { AES } from '@bicycle-codes/keys'

const decryptedText = await AES.decrypt(encryptedText, aesKey)
```
