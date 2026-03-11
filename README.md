# Verify California Driver's Licenses and Identity Cards

> A JavaScript library to verify California Department of Motor Vehicle
> (CA DMV) Driver's Licenses and Identification Cards.

Press release: [DMV to Releases New California Driver’s License and Identification Card Design with Advanced Security Features](https://www.dmv.ca.gov/portal/news-and-media/dmv-to-release-new-california-drivers-license-and-identification-card-design-with-advanced-security-features/)

Public Website: [The California Driver's License Digital Signature](https://www.dmv.ca.gov/portal/driver-licenses-identification-cards/digital-signature/)

Documentation: [Verifying Digital Signatures on California DL/ID Documents](https://www.dmv.ca.gov/portal/file/verifying-digital-signatures-on-california-dlid-documents-pdf/)

## Table of Contents

- [Features](#features)
- [Install](#install)
- [Usage](#usage)
- [Contribute](#contribute)
- [Commercial Support](#commercial-support)
- [License](#license)

## Features

This library provides an API for Web browsers and Node.js to verify CA DMV
DL/ID PDF417 [Verifiable Credential Barcodes][] data.

- Designed to handle the VCB data on current California Drivers Licenses and IDs.
- Restricts the resources that can be loaded during verification to those hosted by CA DMV.

## Install

### NPM

```sh
npm install cadmv-dlid/verifier-sdk
```

### Git

To install locally for development:

```sh
git clone https://github.com/stateofca/cadmv-dlid-verifier-sdk.git
cd cadmv-dlid-verifier-sdk
npm install
```

## Usage

Once PDF417 data has been scanned (out of scope for this library, 
the string or bytes can be sent to the `verify` function. This 
function will check for [Verifiable Credential Barcodes][]
data and perform verification.

The main function of this library is `async verify(options)`.

Basic usage:

```js
import {verify} from 'cadmv-dlid-verifier-sdk';
const result = await verify({
  data: scannedPdf417Data
});
if(result.valid) {
  // data valid
} else {
  // not valid, handle result.error if needed
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
- `{boolean}` `[options.debug=false]` - `true` to return debug details.
  Properties are informative only and subject to change.

Returns object with fields:

- `valid`: `true` if data is valid.
- `error`: Error details if data is not valid.
- `debug`: Debug details object if requested.

## Contribute

Please follow the existing code style. Pull requests are accepted.

If editing the README, please conform to the
[standard-readme](https://github.com/RichardLitt/standard-readme) specification.

## Commercial Support

Commercial support for this library is available upon request from
Digital Bazaar: support@digitalbazaar.com

## License

[BSD-3-Clause](LICENSE) © Digital Bazaar

[Verifiable Credential Barcodes]: https://w3c-ccg.github.io/vc-barcodes/
