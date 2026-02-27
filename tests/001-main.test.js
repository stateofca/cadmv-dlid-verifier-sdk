import {describe, expect, it} from 'vitest';

import {verify} from '../lib/index.js';

// Verifying Digital Signatures on California DL/ID Documents
// https://www.dmv.ca.gov/portal/file/verifying-digital-signatures-on-california-dlid-documents-pdf/
// Retrieved on 2026-02-13

// Example PDF417 with digital signature
// eslint-disable-next-line @stylistic/max-len
const validUatExample = '@\n\u001e\rANSI 636014100102DL00410287ZC03280220DLDAQI8887059\nDCSFIVENINE\nDDEU\nDACTOMTEST\nDDFU\nDADNONE\nDDGU\nDCABM1\nDCBL80\nDCDNONE\nDBD08052025\nDBB01011980\nDBA01012030\nDBC1\nDAU070 IN\nDAYBLU\nDAG2415 1ST AVE 051\nDAISACRAMENTO\nDAJCA\nDAK958180000  \nDCF08/05/2025298TL/TLFD/30\nDCGUSA\nDAZBLN\nDAW200\nDCUIV\nDCK25217I88870590401\nDDAN\nDDB05202024\rZCZCABLU\nZCBBLN\nZCC\nZCD\nZCE2csdghoB2QXApgGCAQIYnYIYdhikGK6jGJwYphjEQRUYxhrmdn0HGLCiGJwYoBioRHX/cGAYtEEUGLalGJwYbBjMARjWGNwY2FhBephqE+tbyDCJM7XgRUzmFAY41xQu1cBinSYoLAAx/k6284STfQ0g1arQCtDpTWsqa96BLDbWzvj0R4JIrk/K5AAY2kEW\r';

// Appendix B: Example PDF417 with revoked digital signature
// eslint-disable-next-line @stylistic/max-len
const invalidUatExample = '@\n\u001e\rANSI 636014100102DL00410281ZC03220220DLDAQI8889812\nDCSONETWO\nDDEU\nDACEERIETEST\nDDFU\nDADVON\nTWOMN\nDDGU\nDCAC\nDCBNONE\nDCDNONE\nDBD09042025\nDBB12121972\nDBA12122029\nDBC9\nDAU075\nIN\nDAYBLU\nDAG2415\n1ST\nAVE\nDAISACRAMENTO\nDAJCA\nDAK958180000  \nDCF09/04/2025796KP/12FD/29\nDCGUSA\nDAZBLN\nDAW159\nDCK25247I88898120401\nDDAN\nDDB05202024\rZCZCABLU\nZCBBLN\nZCC\nZCD\nZCE2csdghoB2QXApgGCAQIYnYIYdhikGK6jGJwYphjEQRUYxhrnDr7YGLCiGJwYoBioRHX/cGAYtEEUGLalGJwYbBjMARjWGNwY2FhBemJvZUdnBf+uJ1kK58r6AsaiKMDVR7OkfSWCdft/LTd9M0sgpUItYaZClwJUeX5s20C/bZJffuxHkFzcdUXRIXsY2kEW\r';

// as typed arrays
const encoder = new TextEncoder();
const validUatExampleBytes = encoder.encode(validUatExample);
const invalidUatExampleBytes = encoder.encode(invalidUatExample);

describe('main', () => {
  it('valid data, string, uat', async () => {
    const result = await verify({data: validUatExample, mode: 'uat'});
    expect(result).toHaveProperty('verified', true);
    expect(result).not.toHaveProperty('error');
  });
  it('valid data, bytes, uat', async () => {
    const result = await verify({data: validUatExampleBytes, mode: 'uat'});
    expect(result).toHaveProperty('verified', true);
    expect(result).not.toHaveProperty('error');
  });
  it('invalid data, string, uat', async () => {
    const result = await verify({data: invalidUatExample});
    expect(result).toHaveProperty('verified', false);
    // TODO: check error
  });
  it('invalid data, bytes, uat', async () => {
    const result = await verify({data: invalidUatExampleBytes, mode: 'uat'});
    expect(result).toHaveProperty('verified', false);
    // TODO: check error
  });
  it('no vcb', async () => {
    const result = await verify({data: validUatExample, mode: 'uat',
      _test: {
        vcb: false
      }
    });
    expect(result).toHaveProperty('verified', false);
    // TODO: check error
  });
  it('verifyVCB=required, old issue date', async () => {
    const result = await verify({data: validUatExample, mode: 'uat',
      verifyVCB: 'required',
      _test: {
        issuedDateField: '07012025'
      }
    });
    expect(result).toHaveProperty('verified', true);
    expect(result).not.toHaveProperty('error');
  });
  it('verifyVCB=always, old issue date', async () => {
    const result = await verify({data: validUatExample, mode: 'uat',
      verifyVCB: 'always',
      _test: {
        issuedDateField: '07012025'
      }
    });
    expect(result).toHaveProperty('verified', true);
    expect(result).not.toHaveProperty('error');
  });
  it('verifyVCB=required, no vcb, old issue date', async () => {
    const result = await verify({data: validUatExample, mode: 'uat',
      verifyVCB: 'required',
      _test: {
        issuedDateField: '07012025',
        vcb: false
      }
    });
    expect(result).toHaveProperty('verified', true);
    expect(result).not.toHaveProperty('error');
  });
  it('verifyVCB=always, no vcb, old issue date', async () => {
    const result = await verify({data: validUatExample, mode: 'uat',
      verifyVCB: 'always',
      _test: {
        issuedDateField: '07012025',
        vcb: false
      }
    });
    expect(result).toHaveProperty('verified', false);
    // TODO: check error
  });
  it('verifyVCB=always, no vcb, not ca', async () => {
    const result = await verify({data: validUatExample, mode: 'uat',
      verifyVCB: 'always',
      _test: {
        issuedState: 'VA',
        vcb: false
      }
    });
    expect(result).toHaveProperty('verified', false);
    // TODO: check error
  });
  it('no vcb, not ca', async () => {
    const result = await verify({data: validUatExample, mode: 'uat',
      _test: {
        issuedState: 'VA',
        vcb: false
      }
    });
    expect(result).toHaveProperty('verified', true);
    expect(result).not.toHaveProperty('error');
  });
  it('no credentialStatus', async () => {
    const result = await verify({data: validUatExample, mode: 'uat',
      _test: {
        noCredentialStatus: true
      }
    });
    expect(result).toHaveProperty('verified', false);
    // TODO: check error
  });
  it('revoked', async () => {
    const result = await verify({data: validUatExample, mode: 'uat',
      _test: {
        checkStatusError: true
      }
    });
    expect(result).toHaveProperty('verified', false);
    // TODO: check error
  });
  it('reject uat in prod mode', async () => {
    const result = await verify({data: validUatExample});
    expect(result).toHaveProperty('verified', false);
    // TODO: check error
  });
  // FIXME: needs test vector(s) with prod URLs
  it('reject prod in uat mode');
});
