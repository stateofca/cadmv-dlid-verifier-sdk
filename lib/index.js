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

// for debugging
//import {inspect} from 'node:util';
//function _inspect(...args) {
//  return inspect(...args, {colors: true, depth: 10});
//}

// 'TerseBitstringStatusListEntry' related constants
// always 2^26 = 67108864 per vc-barcodes spec
const TERSE_BITSTRING_STATUS_LIST_LENGTH = 67108864;
//const TERSE_STATUS_PURPOSES = ['revocation', 'suspension'];
const TERSE_STATUS_PURPOSE = 'revocation';

/**
 * Decode base64 string to bytes.
 *
 * @param {object} options - Options object.
 * @param {string} options.base64String - Base64 encoded string.
 * @returns {Uint8Array} Decoded bytes.
 */
function fromBase64({base64String} = {}) {
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
  subfile: 'ZC',
  field: 'ZCE'
};

// require a digital signature for CA DL/ID at start of day in CA
const REQUIRED_DIGITAL_SIGNATURE_DATE = '2025-08-01T08:00:00.000Z';

// add slashes to MMDDCCYY
function _formatMonthDayYear(dateStr) {
  const month = dateStr.slice(0, 2);
  const day = dateStr.slice(2, 4);
  const year = dateStr.slice(4);
  return month + '/' + day + '/' + year;
}

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
  if(verifyStatus === 'never') {
    return {verified: true};
  }

  const credentialStatus = credential.credentialStatus;

  // check if status exists
  if(!credentialStatus || _test.noCredentialStatus) {
    if(verifyStatus === 'present') {
      return {
        verified: true
      };
    }
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

/**
 * Verify a PDF417 CA DMV DL VCB.
 *
 * @param {object} options - Verify options.
 * @param {Uint8Array|string} options.data - PDF417 bytes or string.
 * @param {Uint8Array|string} [options.encoding='utf8'] - String encoding if
 *   data is a string.
 * @param {string} [options.verifyVcb='required'] - Mode for verifying VCB data.
 *   'always':  Always verify, even if not required.
 *   'present' Optional but always verify when present.
 *   'required' Only verify when present or required by state and issued date.
 * @param {string} [options.verifyStatus='always'] - Mode for verifying VCB
 *   status.
 *   'always':  Always verify, even if not required.
 *   'present' Optional but always verify when present.
 *   'never': Skip verification.
 * @param {Function} [options.documentLoader=null] - Override default
 *   documentLoader.
 * @param {string} [options.mode='prod'] - Target deployment: 'prod' or 'uat'.
 * @param {boolean} [options.debug=false] - Return debug details.
 * @param {object} [options._test={}] - Internal private flags for testing.
 *   See tests for usage.
 *
 * @returns {object} - Verification results. 'verified' field and 'error' field
 *   if not verified.
 */
export async function verify({
  data,
  encoding = 'utf8',
  verifyVcb = 'required',
  verifyStatus = 'always',
  documentLoader = null,
  mode = 'prod',
  debug = false,
  _test = {}
} = {}) {
  const result = {
    verified: false
  };
  if(debug) {
    result.debug = {};
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
  if(decoded.issuerIdentificationNumber !==
    AAMVA_VCB_CA_INFO.issuerIdentificationNumber) {
    result.error = new Error('AAMVA CA issuer not found.');
    return result;
  }

  let issuedSelection;
  try {
    issuedSelection = await aamva.select({
      object: decoded,
      selector: {
        subfile: ['DL', 'ID'],
        // DAJ=state
        // DBD=issued date (MMDDCCYY)
        fileds: ['DAJ', 'DBD']
      }
    });
  } catch(e) {
    result.error = new Error('Issuer and issued fields not found.', {
      cause: e
    });
    return result;
  }
  const issuedState = _test.issuedState ?? issuedSelection.get('DAJ');
  const issuedDateField = _test.issuedDateField ?? issuedSelection.get('DBD');
  const issuedDate = new Date(_formatMonthDayYear(issuedDateField));
  const cutoffDate = new Date(REQUIRED_DIGITAL_SIGNATURE_DATE);

  const requireDigitalSignature =
    issuedState === 'CA' && issuedDate >= cutoffDate;

  // only required for CA after certain issue date
  if(!requireDigitalSignature) {
    if(verifyVcb !== 'always') {
      result.verified = true;
      return result;
    }
  }

  // find VCB
  let selection;
  try {
    selection = await aamva.select({
      object: decoded,
      selector: {
        subfile: [AAMVA_VCB_CA_INFO.subfile],
        fileds: [AAMVA_VCB_CA_INFO.field]
      }
    });
  } catch(e) {
    if(verifyVcb === 'always' || verifyVcb === 'required') {
      result.error = new Error('VC Barcode field not found.', {
        cause: e
      });
      return result;
    }
  }

  let encoded;
  if(selection) {
    encoded = _test.vcb ?? selection.get(AAMVA_VCB_CA_INFO.field);
    if(!encoded) {
      if(verifyVcb === 'always' || verifyVcb === 'required') {
        result.error = new Error('VC Barcode data not found.');
        return result;
      }
      // only checking if present, and not found
      if(verifyVcb === 'present') {
        result.verified = true;
        return result;
      }
    }
  }

  // decode VCB field from base64 to CBOR-LD
  const cborldBytes = fromBase64({base64String: encoded});
  if(debug) {
    result.debug.cborldBytes = cborldBytes;
  }

  // decode VCB field from CBOR-LD to JSON-LD VC
  const credential = await decode({
    cborldBytes,
    documentLoader,
    typeTableLoader: () => typeTable
  });
  if(debug) {
    result.debug.credential = credential;
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

  result.verified = verifyResult.verified;
  if(!result.verified) {
    result.error = new Error('Verify error', {
      cause: verifyResult.error
    });
  }

  return result;
}
