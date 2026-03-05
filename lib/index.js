/*!
 * Copyright 2024 - 2026 California Department of Motor Vehicles.
 * Copyright 2018 - 2026 Digital Bazaar, Inc.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
import * as vc from '@digitalbazaar/vc';
import {aamva} from '@digitalbazaar/pdf417-dl-canonicalizer';
import {
  checkStatus as bitstringStatusListCheckStatus/*,
  statusTypeMatches as bitstringStatusListStatusTypeMatches*/
} from '@digitalbazaar/vc-bitstring-status-list';
import {CachedResolver} from '@digitalbazaar/did-io';
import {
  createCryptosuite as createEcdsaXi2023Cryptosuite
} from '@digitalbazaar/ecdsa-xi-2023-cryptosuite';
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';
import {decode} from '@digitalbazaar/cborld';
import {DidWebDriver} from '@digitalbazaar/did-method-web';
import {
  cryptosuite as ecdsaRdfc2019Cryptosuite
} from '@digitalbazaar/ecdsa-rdfc-2019-cryptosuite';
import {httpClient} from '@digitalbazaar/http-client';
import {JsonLdDocumentLoader} from 'jsonld-document-loader';
import {contexts as vcbContexts} from '@digitalbazaar/vc-barcodes-context';
import {contexts as vcContexts} from '@digitalbazaar/credentials-context';

// 'TerseBitstringStatusListEntry' related constants
// always 2^26 = 67108864 per vc-barcodes spec
const TERSE_BITSTRING_STATUS_LIST_LENGTH = 67108864;
//const TERSE_STATUS_PURPOSES = ['revocation', 'suspension'];
const TERSE_STATUS_PURPOSE = 'revocation';

// run modes and options
// modes:
// - 'uat': testing
// - 'prod': production
// options:
// - documentLoader: document loader for did:web: and status checks
const _modes = {
  uat: {
    documentLoader: _buildLoader({
      allowedHosts: new Set([
        'uat-credentials.dmv.ca.gov',
        'api.uat-credentials.dmv.ca.gov'
      ])
    })
  },
  prod: {
    documentLoader: _buildLoader({
      allowedHosts: new Set([
        'credentials.dmv.ca.gov',
        'api.credentials.dmv.ca.gov'
      ])
    })
  }
};

// prepare CBOR-LD registry entry metadata for decoding
const contextTable = new Map([
  ['https://www.w3.org/ns/credentials/v2', 1],
  ['https://w3id.org/vc-barcodes/v1', 2]
]);

const cryptosuiteTable = new Map([
  ['ecdsa-xi-2023', 1]
]);

const urlTable = new Map([
  ['did:web:credentials.dmv.ca.gov', 1],
  ['https://api.credentials.dmv.ca.gov/status/dlid/1/status-lists', 2],
  ['https://api.credentials.dmv.ca.gov/status/dlid/2/status-lists', 3],
  ['https://api.credentials.dmv.ca.gov/status/dlid/3/status-lists', 4],
  ['did:web:credentials.dmv.ca.gov#vm-vcb-1', 5],
  ['did:web:credentials.dmv.ca.gov#vm-vcb-2', 6],
  ['did:web:credentials.dmv.ca.gov#vm-vcb-3', 7],
  ['did:web:credentials.dmv.ca.gov#vm-vcb-4', 8],
  ['did:web:credentials.dmv.ca.gov#vm-vcb-5', 9],
  ['did:web:credentials.dmv.ca.gov#vm-vcb-6', 10],
  ['did:web:credentials.dmv.ca.gov#vm-vcb-7', 11],
  ['did:web:credentials.dmv.ca.gov#vm-vcb-8', 12],
  ['did:web:credentials.dmv.ca.gov#vm-vcb-9', 13],
  ['did:web:credentials.dmv.ca.gov#vm-vcb-10', 14],
  ['did:web:credentials.dmv.ca.gov#vm-vcb-11', 15],
  ['did:web:credentials.dmv.ca.gov#vm-vcb-12', 16],
  ['did:web:credentials.dmv.ca.gov#vm-vcb-13', 17],
  ['did:web:credentials.dmv.ca.gov#vm-vcb-14', 18],
  ['did:web:credentials.dmv.ca.gov#vm-vcb-15', 19],
  ['did:web:uat-credentials.dmv.ca.gov', 20],
  ['https://api.uat-credentials.dmv.ca.gov/status/dlid/1/status-lists', 21],
  ['did:web:uat-credentials.dmv.ca.gov#vm-vcb-1', 22],
  ['did:web:uat-credentials.dmv.ca.gov#vm-vcb-2', 23],
  ['did:web:uat-credentials.dmv.ca.gov#vm-vcb-3', 24],
  ['did:web:uat-credentials.dmv.ca.gov#vm-vcb-4', 25],
  ['did:web:uat-credentials.dmv.ca.gov#vm-vcb-5', 26],
  ['https://api.uat-credentials.dmv.ca.gov/status/dlid/2/status-lists', 27],
  ['https://api.uat-credentials.dmv.ca.gov/status/dlid/3/status-lists', 28]
]);

const typeTable = new Map();
typeTable.set('https://w3id.org/security#cryptosuiteString', cryptosuiteTable);
typeTable.set('context', contextTable);
typeTable.set('url', urlTable);

// AAMVA CA info
const AAMVA_VCB_CA_INFO = {
  issuerIdentificationNumber: '636014',
  DAJ: 'CA',
  subfile: 'ZC',
  field: 'ZCE'
};

// require a digital signature for CA DL/ID at start of day in CA
const DIGITAL_SIGNATURE_REQUIRED_DATE = _dateFromMonthDayYear('09292025');

/**
 * Verify a PDF417 CA DMV DL VCB.
 *
 * @param {object} options - Verify options.
 * @param {Uint8Array|string} options.data - PDF417 bytes or string.
 * @param {Uint8Array|string} [options.encoding='utf8'] - String encoding if
 *   data is a string.
 * @param {boolean} [options.requireVcb=false] - `true` to require VCB data be
 *   present.
 * @param {string} [options.verifyStatus=false] - `true` to check VCB
 *   revocation status.
 * @param {Function} [options.documentLoader=null] - Override default
 *   documentLoader.
 * @param {string} [options.mode='prod'] - Target deployment: 'prod' or 'uat'.
 * @param {boolean} [options.debug=false] - `true` to return debug details.
 *   Properties are informative only and subject to change.
 * @param {object} [options._test={}] - Internal private flags for testing.
 *   See tests for usage.
 *
 * @returns {object} - Verification results:
 *   'valid': `true` if data is valid.
 *   'error': Error details if data is not valid.
 *   'debug': Debug details if requested.
 */
export async function verify({
  data,
  encoding = 'utf8',
  requireVcb = false,
  verifyStatus = false,
  documentLoader = null,
  mode = 'prod',
  debug = false,
  _test = {}
} = {}) {
  const result = {
    // all checks pass and VCB data verified
    valid: false
  };
  if(debug) {
    // Debug mode can return many values in the returned `debug` property.
    // Usage: `verify({..., debug: true})`.
    //
    // Properties are informative only and subject to change.
    //
    // Properties may be promoted to regular returned properties if needed.
    result.debug = {
      // decoded AAMVA data from PDF417 data
      aamva: null,
      // `true` if AAMVA issuer data is acceptable.
      // This includes issuer identifier and DAJ fields matching.
      issuerAccepted: false,
      // `true` if AAMVA issuer data is acceptable and VCB data is
      // required due to the input data or an option.
      vcbRequired: requireVcb,
      // decoded VCB field from base64 to CBOR-LD
      cborldBytes: null,
      // decoded CBOR-LD to credential
      credential: null,
      // `true` if AAMVA issuer data is valid and VCB data is present.
      vcbPresent: false,
      // AAMVA document
      aamvaDocument: null,
      // AAMVA document hash
      aamvaHash: null,
      // VC verification result
      verifyResult: null
    };
  }

  if(!documentLoader) {
    documentLoader = _modes[mode].documentLoader;
  }

  // decode AAMVA data from PDF417 data
  const decoded = await aamva.decode({data, encoding});
  if(debug) {
    result.debug.aamva = decoded;
  }

  // check issuer
  // issuerAccepted set after DAJ check later
  const issuerIdentificationNumber =
    _test.issuerId ?? decoded.issuerIdentificationNumber;
  if(issuerIdentificationNumber !==
    AAMVA_VCB_CA_INFO.issuerIdentificationNumber) {
    result.error = new Error('AAMVA CA issuer not found.');
    return result;
  }

  // get issuer data
  let issuedSelection;
  try {
    issuedSelection = await aamva.select({
      object: decoded,
      selector: {
        subfile: ['DL', 'ID'],
        // DAJ=issued state
        // DBD=issued date (MMDDCCYY)
        fields: ['DAJ', 'DBD']
      }
    });
  } catch(e) {
    result.error = new Error('Issuer and issued fields not found.', {
      cause: e
    });
    return result;
  }

  // check state
  const issuedState = _test.issuedState ?? issuedSelection.get('DAJ');
  if(issuedState !== AAMVA_VCB_CA_INFO.DAJ) {
    result.error = new Error(`Invalid DAJ field: "${issuedState}".`);
    return result;
  }
  if(debug) {
    // both identifier and DAJ match
    result.debug.issuerAccepted = true;
  }

  // get issued date
  const issuedDateField = _test.issuedDateField ?? issuedSelection.get('DBD');
  const issuedDate = _dateFromMonthDayYear(issuedDateField);

  // VCB required due to option or data date
  // only required for CA after certain issue date
  const vcbRequired = requireVcb ||
    issuedDate >= DIGITAL_SIGNATURE_REQUIRED_DATE;
  if(debug) {
    // update result field
    result.debug.vcbRequired = vcbRequired;
  }

  // find VCB
  let vcbSelection;
  try {
    vcbSelection = await aamva.select({
      object: decoded,
      selector: {
        subfile: [AAMVA_VCB_CA_INFO.subfile],
        fields: [AAMVA_VCB_CA_INFO.field]
      }
    });
  } catch(e) {
    if(vcbRequired) {
      result.error = new Error('VC Barcode field not found.', {
        cause: e
      });
      return result;
    }
  }

  // get VCB data
  let encodedVcb;
  if(vcbSelection) {
    encodedVcb = _test.vcb ?? vcbSelection.get(AAMVA_VCB_CA_INFO.field);
  }
  if(!encodedVcb) {
    if(vcbRequired) {
      result.error = new Error('VC Barcode data not found.');
    }
    // vcb not found and not required, no further checking
    return result;
  }

  // decode VCB credential
  let credential;
  try {
    // decode VCB field from base64 to CBOR-LD
    const cborldBytes = _fromBase64({base64String: encodedVcb});
    if(debug) {
      result.debug.cborldBytes = cborldBytes;
    }

    // decode VCB field from CBOR-LD to JSON-LD VC
    credential = await decode({
      cborldBytes,
      documentLoader,
      typeTableLoader: () => typeTable
    });
    if(debug) {
      result.debug.credential = credential;
    }
  } catch(e) {
    result.error = new Error('VC Barcode decode failed.', {
      cause: e
    });
    return result;
  }
  if(debug) {
    // VCB found and decoded
    result.debug.vcbPresent = true;
  }

  // get AAMVA DL or ID document
  const componentIndex = credential.credentialSubject?.protectedComponentIndex;
  const document = await aamva.select({
    object: decoded,
    selector: {
      subfile: ['DL', 'ID'],
      componentIndex
    }
  });
  if(debug) {
    result.debug.aamvaDocument = document;
  }

  // make hash for ecdsa-xi-2023 cryptosuite extra info
  const hash = await aamva.hash({document});
  if(debug) {
    result.debug.aamvaHash = hash;
  }

  const ecdsaXi2023VerifyingSuite = new DataIntegrityProof({
    cryptosuite: createEcdsaXi2023Cryptosuite({
      extraInformation: hash
    })
  });

  const verifyResult = await vc.verifyCredential({
    credential,
    suite: ecdsaXi2023VerifyingSuite,
    checkStatus: async ({credential, /*suite,*/ documentLoader}) => {
      return _checkStatus({
        credential,
        documentLoader,
        verifyStatus,
        _test
      });
    },
    documentLoader
  });
  if(debug) {
    result.debug.verifyResult = verifyResult;
  }

  result.valid = verifyResult.verified;
  if(!result.valid) {
    if(verifyResult.error) {
      result.error = new Error('Verify error', {
        cause: verifyResult.error
      });
    } else if(verifyResult.statusResult.error) {
      result.error = new Error('Status error', {
        cause: verifyResult.statusResult.error
      });
    } else {
      // another error
      result.error = new Error('Verify error');
    }
  }

  return result;
}

/**
 * Convert MMDDCCYY to Date in CA.
 *
 * Note that the TZ offset here is mostly informative. Dates are all converted
 * the same way so the offset cancels out of comparisons.
 *
 * @param {string} dateStr - Date string in MMDDCCYY format.
 * @returns {Date} String as a Date.
 */
function _dateFromMonthDayYear(dateStr) {
  const month = dateStr.slice(0, 2);
  const day = dateStr.slice(2, 4);
  const year = dateStr.slice(4);
  return new Date(`${year}-${month}-${day}T07:00:00.000Z`);
}

/**
 * Decode base64 string to bytes.
 *
 * @param {object} options - Options object.
 * @param {string} options.base64String - Base64 encoded string.
 * @returns {Uint8Array} Decoded bytes.
 */
function _fromBase64({base64String} = {}) {
  // Use modern API
  if(typeof Uint8Array.fromBase64 === 'function') {
    return Uint8Array.fromBase64(base64String);
  }

  // Fallback to atob
  const binaryString = atob(base64String);
  const bytes = new Uint8Array(binaryString.length);
  for(let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

/**
 * Build a document loader with restricted allowed hosts.
 *
 * @param {object} options - Function options.
 * @param {Set} options.allowedHosts - Set of allowed hosts.
 *
 * @returns {Function} - A document loader.
 */
function _buildLoader({allowedHosts}) {
  // setup statuc / did:web: document loader
  const jld = new JsonLdDocumentLoader();
  // static contexts
  jld.addDocuments({documents: vcContexts});
  jld.addDocuments({documents: vcbContexts});
  // did:web handler
  const resolver = new CachedResolver();
  const didWebDriver = new DidWebDriver({allowList: [...allowedHosts]});
  resolver.use(didWebDriver);
  jld.setDidResolver(resolver);

  const _documentLoader = jld.build();

  return async url => {
    // try static / did:web: loader
    try {
      return await _documentLoader(url);
    } catch {
      // fall through
    }
    // fall back to check hosts and fetch
    const _url = new URL(url);
    if(!allowedHosts.has(_url.host)) {
      throw new Error(`URL not allowed: URL="${url}".`);
    }
    const {data: document} = await httpClient.get(url);
    return {
      document,
      documentUrl: url
    };
  };
}

/**
 * Internal function to check status with vc API.
 *
 * @param {object} options - Function options.
 * @param {object} options.credential - The credential.
 * @param {Function} options.documentLoader - A documentLoader.
 * @param {boolean} options.verifyStatus - Control if status should be checked.
 * @param {object} options._test - Internal testing options.
 *
 * @returns {object} - Status check results.
 */
async function _checkStatus({
  credential,
  documentLoader,
  verifyStatus,
  _test
} = {}) {
  if(_test.checkStatusError) {
    return {
      verified: false,
      error: new Error('**TEST**: Status check failed.')
    };
  }

  // bypass status checks
  if(!verifyStatus) {
    return {verified: true};
  }

  const credentialStatus = credential.credentialStatus;

  // check if status exists
  if(!credentialStatus || _test.noCredentialStatus) {
    return {
      verified: false,
      error: new Error('"credentialStatus" property not found.')
    };
  }

  // only support one check
  if(Array.isArray(credentialStatus)) {
    return {
      verified: false,
      error: new Error('Only one credentialStatus supported.')
    };
  }

  // status must be TerseBitstringStatusListEntry
  if(credentialStatus.type !== 'TerseBitstringStatusListEntry') {
    return {
      verified: false,
      error: new Error('Only TerseBitstringStatusListEntry status supported.')
    };
  }

  // TODO: improve schema checks

  // convert terse check
  const {terseStatusListIndex, terseStatusListBaseUrl} = credentialStatus;
  const listIndex =
    Math.floor(terseStatusListIndex / TERSE_BITSTRING_STATUS_LIST_LENGTH);
  const statusListIndex =
    terseStatusListIndex % TERSE_BITSTRING_STATUS_LIST_LENGTH;
  const statusListCredential =
    `${terseStatusListBaseUrl}/${TERSE_STATUS_PURPOSE}/${listIndex}`;
  const _credentialStatus = {
    type: 'BitstringStatusListEntry',
    statusListCredential,
    statusListIndex: `${statusListIndex}`,
    statusPurpose: TERSE_STATUS_PURPOSE
  };

  const ecdsaRdfc2019VerifyingSuite = new DataIntegrityProof({
    cryptosuite: ecdsaRdfc2019Cryptosuite
  });

  const verifyingSuite = [
    ecdsaRdfc2019VerifyingSuite
    // can add more suites here if needed
  ];

  const _credential = structuredClone(credential);
  _credential.credentialStatus = _credentialStatus;

  const _result = await bitstringStatusListCheckStatus({
    credential: _credential,
    documentLoader,
    suite: verifyingSuite,
    verifyBitstringStatusListCredential: true,
    verifyMatchingIssuers: true
  });

  if(!_result.verified) {
    return {
      verified: false,
      error: new Error('"credentialStatus" property not found.')
    };
  }

  return {
    verified: true
  };
}
