# CA DMV DL/ID Verifier SDK _(cadmv-dlid-verifier-sdk)_

> A JavaScript library to verify CA DMV DL/IDs with PDF417 Verifiable
> Credential Barcodes data.

## Table of Contents

- [Features](#features)
- [Install](#install)
- [Usage](#usage)
- [API](#api)
- [Contribute](#contribute)
- [Commercial Support](#commercial-support)
- [License](#license)

## Features

This library provides an API for Web browsers and Node.js to verify CA DMV
DL/ID PDF417 [Verifiable Credential Barcodes][] data.

- Designed to handle the limited use case of the VCB data on current Drivers
  Licenses and IDs.
- Restricts the resources that can be loaded during verification to those
  hosted by CA DMV.

## Install

### NPM

```sh
npm install cadmv-dlid/verifier-sdk
```

### Git

To install locally for development:

```sh
git clone https://github.com/digitalbazaar/cadmv-dlid-verifier-sdk.git
cd cadmv-dlid-verifier-sdk
npm install
```

## Usage

Once PDF417 data has been scanned, the string or bytes can be sent to the
`verify` function. This function will check for [Verifiable Credential
Barcodes][] data and perform verification.

The main function of this library is `async verify(options)`.

Basic usage:

```js
import {verify} from 'cadmv-dlid-verifier-sdk';
const result = await verify({
  data: scannedPdf417Data
});
if(result.verified) {
  // data verified
} else {
  // not verified, handle result.error if needed
}
```

Force VCB data to be required:

```js
import {verify} from 'cadmv-dlid-verifier-sdk';
const result = await verify({
  data: scannedPdf417Data,
  requireVcb: true
});
```

Enable VCB revocation status verification:

```js
import {verify} from 'cadmv-dlid-verifier-sdk';
const result = await verify({
  data: scannedPdf417Data,
  verifyStatus: true
});
```

Available options:

- `{Uint8Array|string}` `options.data` - PDF417 bytes or string.
- `{Uint8Array|string} `[options.encoding='utf8']` - String encoding if `data`
  is a string.
- `{boolean}` `[options.requireVcb=false]` - `true` to require VCB data be
  present.
- `{boolean}` `[options.verifyStatus=false]` - `true` to check VCB revocation
  status.
- `{Function}` `[options.documentLoader=null]` - Override default
    `documentLoader`.
- `{string}` `[options.mode='prod']` - Target deployment: 'prod' or 'uat'.
- `{boolean}` `[options.debug=false]` - Return debug details.

Returns object with fields:

- `verified`: `true` if VCB data verified.
- `issuerValid`: `true` if AAMVA issuer data is valid.
- `vcbRequired`: `true` if AAMVA issuer data is valid and VCB data is required
  due to data or option.
- `vcbPresent`: `true` if AAMVA issuer data is valid and VCB data is present.
- `error`: Error if not verified.
- `debug`: Debug details object when requested.

## Contribute

Please follow the existing code style.

PRs accepted.

If editing the README, please conform to the
[standard-readme](https://github.com/RichardLitt/standard-readme) specification.

## Commercial Support

Commercial support for this library is available upon request from
Digital Bazaar: support@digitalbazaar.com

## License

[BSD-3-Clause](LICENSE) © Digital Bazaar

[Verifiable Credential Barcodes]: https://w3c-ccg.github.io/vc-barcodes/
