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
- [use](#use)
  * [example](#example)
  * [JS](#js)

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

### Verify a signature

```ts
```
