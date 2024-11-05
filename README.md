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

## use

### example

### JS
```js
import '@bicycle-codes/keys'
```
