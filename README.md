# keys
![tests](https://github.com/bicycle-codes/keys/actions/workflows/nodejs.yml/badge.svg)
[![types](https://img.shields.io/npm/types/@bicycle-codes/keys?style=flat-square)](README.md)
[![module](https://img.shields.io/badge/module-ESM%2FCJS-blue?style=flat-square)](README.md)
[![semantic versioning](https://img.shields.io/badge/semver-2.0.0-blue?logo=semver&style=flat-square)](https://semver.org/)
[![Common Changelog](https://nichoth.github.io/badge/common-changelog.svg)](./CHANGELOG.md)
[![install size](https://flat.badgen.net/packagephobia/install/@bicycle-codes/keys)](https://packagephobia.com/result?p=@bicycle-codes/keys)
[![license](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square)](LICENSE)

Create and store keypairs in-browser with the [web crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API).

Use [indexedDB](https://developer.mozilla.org/en-US/docs/Web/API/IndexedDB_API) to store [non-extractable keypairs](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/generateKey#extractable). "Non-extractable" means that the browser prevents you from ever reading the private key, but the keys can be persisted and re-used indefinitely.

<details><summary><h2>Contents</h2></summary>

<!-- toc -->

- [install](#install)
- [API](#api)
  * [ESM](#esm)
  * [Common JS](#common-js)
  * [pre-built JS](#pre-built-js)
- [example](#example)
  * [Create a new `Keys` instance](#create-a-new-keys-instance)
  * [Sign something](#sign-something)
  * [Get a signature as a string](#get-a-signature-as-a-string)
  * [Verify a signature](#verify-a-signature)
  * [Encrypt a key](#encrypt-a-key)
  * [Encrypt some arbitrary data](#encrypt-some-arbitrary-data)
  * [Decrypt a message](#decrypt-a-message)
  * [`decryptToString`](#decrypttostring)

<!-- tocstop -->

</details>

## install

```sh
npm i -S @bicycle-codes/keys
```

## API

This exposes ESM and common JS via [package.json `exports` field](https://nodejs.org/api/packages.html#exports).

### ESM
```js
import '@bicycle-codes/keys'
```

### Common JS
```js
require('@bicycle-codes/keys')
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

## example

### Create a new `Keys` instance

Use the factory function `Keys.create` because `async`. The optional parameters, `encryptionKeyName` and `signingKeyName`, are added as properties to the `keys` instance -- `ENCRYPTION_KEY_NAME` and `SIGNING_KEY_NAME`. These are used as keys for saving the keys in `indexedDB`.

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

#### example
```js
import { Keys } from '@bicycle-codes/keys'

const keys = await Keys.create()
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
```ts
class Keys {
  async signAsString (
    msg:ArrayBuffer|string|Uint8Array,
    charsize?:CharSize
  ):Promise<string>
}
```

```js
const sig = await keys.signAsString('hello string')
// => ubW9PIjb360v...
```

### Verify a signature
Check if a given signature is valid. This is exposed as a stateless function so that it can be used independently from any keypairs. You need to pass in the data that was signed, the signature, and the `DID` string of the public key used to create the signature.

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
This method uses async (RSA) encryption, so it should be used to encrypt AES keys only, not arbitrary data. You must pass in either a DID or a public key as the encryption target.

```ts
async function encryptKeyTo ({ key, publicKey, did }:{
    key:string|Uint8Array|CryptoKey;
    publicKey?:CryptoKey|Uint8Array|string;
    did?:DID
}):Promise<Uint8Array>
```

#### example
```js
const encrypted = await encryptKeyTo({
    content: myAesKey,
    publicKey: keys.publicEncryptKey
})

const encryptedTwo = await encryptKeyTo({
  content: aesKey,
  did: keys.DID
})
```

### Encrypt some arbitrary data

Take some arbitrary content and encrypt it. Will use either the given AES key, or will generate a new one if it is not passed in. The return value is the encrypted key and the given data. You must pass in either a DID or a public key to encrypt to.

```ts
export async function encryptTo (opts:{
    content:string|Uint8Array;
    publicKey?:CryptoKey|string;
    did?:DID;
}, aesKey?:SymmKey|Uint8Array|string):Promise<{
    content:Uint8Array;
    key:Uint8Array;
}>
```

#### example
```js
const encrypted = await encryptTo({
    key: 'hello encryption',
    publicKey: keys.publicEncryptKey
    // or pass in a DID
    // did: keys.DID
})

// => {
//   content:Uint8Array
//   key: Uint8Array  <-- the encrypted AES key
// }
```

### Decrypt a message
```ts
class Keys {
  async decrypt (msg:{
      content:string|Uint8Array;
      key:string|Uint8Array;
  }):Promise<Uint8Array>
}
```

```js
const decrypted = await keys.decrypt(encrypted)
// => Uint8Array
```

### `decryptToString`
Decrypt a message, and stringify the result.

```ts
class Keys {
  async decryptToString (msg:EncryptedMessage):Promise<string>
}
```

```js
const decrypted = await keys.decryptToString(encryptedMsg)
// => 'hello encryption'
```
