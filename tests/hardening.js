const chai = require('chai');
const bs58check = require('bs58check').default;
const btcmessage = require('@runonflux/bitcoinjs-message');
const fluxsdk = require('../lib');

const { expect } = chai;
const { fluxnode } = fluxsdk;

const MAGIC = '\u0018Zelcash Signed Message:\n';
const OUT_HASH = 'a373395cc26af216ee9885282d2f7bf8317c4e6f02f1561d1d6f46ba9cc86a71';
const COLLATERAL_WIF = 'L17FU2CoD4joDmEp1xMbfuD6eQ8Yr8SEC2gjbcKktLs3DS3WCCxF';
const NODE_WIF = '5JF3aGCa6bkPvfSzqtzX7fXFjfjUG4qzp9hdtRujLRE9ZAMfhiF';
const DELEGATE_WIF = 'KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn';
const REDEEM_SCRIPT = '5221022180e3478446c3d8967bac969bc0a55ac094d28a479973bccc88c495fa576f9d2103abfa98505a1423498287e160a96163b6a1aa844fd7879c6263f1bd0e077e33f552ae';
const DELEGATE_KEY = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
const DELEGATE_KEY_2 = '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5';
const NOT_ON_CURVE = '0388eb0e87ceecd650faa4d6dc90083c651a561a20da2dd2ec23ad70b973c23259';
const TIMESTAMP = '1698522999';

function reverseHex(hex) {
  return Buffer.from(hex, 'hex').reverse().toString('hex');
}

// Signing is deterministic (RFC 6979): re-signing the txid that txidStart
// returns reproduces the signature inside the transaction only if that txid is
// exactly the message the builder signed.
function signatureFor(txid, wif) {
  const privateKey = Buffer.from(bs58check.decode(wif)).subarray(1, 33);
  return btcmessage.sign(txid, privateKey, true, MAGIC).toString('hex');
}

// What txidStart computed before 1.2.0: drop the last 66 bytes.
function legacyTxidStart(rawtx) {
  return reverseHex(fluxnode.doubleHash(rawtx.substr(0, rawtx.length - 132)));
}

describe('txidStart', () => {
  const layouts = [
    ['v5', () => fluxnode.startFluxNode(OUT_HASH, '0', COLLATERAL_WIF, NODE_WIF, TIMESTAMP), COLLATERAL_WIF],
    ['v6', () => fluxnode.startFluxNodev6(OUT_HASH, '0', COLLATERAL_WIF, NODE_WIF, TIMESTAMP), COLLATERAL_WIF],
    ['v6 P2SH', () => fluxnode.startFluxNodev6(OUT_HASH, '0', COLLATERAL_WIF, NODE_WIF, TIMESTAMP, true, false, REDEEM_SCRIPT), COLLATERAL_WIF],
    ['v6 adding delegates', () => fluxnode.startFluxNodeAddDelegate(OUT_HASH, '0', COLLATERAL_WIF, NODE_WIF, TIMESTAMP, [DELEGATE_KEY, DELEGATE_KEY_2]), COLLATERAL_WIF],
    ['v6 P2SH adding delegates', () => fluxnode.startFluxNodeAddDelegate(OUT_HASH, '0', COLLATERAL_WIF, NODE_WIF, TIMESTAMP, [DELEGATE_KEY], true, false, REDEEM_SCRIPT), COLLATERAL_WIF],
    ['v6 P2SH clearing delegates', () => fluxnode.startFluxNodev6(OUT_HASH, '0', COLLATERAL_WIF, NODE_WIF, TIMESTAMP, true, false, REDEEM_SCRIPT, { version: 1, type: 1, delegatePublicKeys: [] }), COLLATERAL_WIF],
    ['v6 signed by a delegate', () => fluxnode.startFluxNodeAsDelegate(OUT_HASH, '0', DELEGATE_WIF, NODE_WIF, TIMESTAMP), DELEGATE_WIF],
  ];

  layouts.forEach(([name, build, signerWif]) => {
    it(`returns the signed txid (${name})`, () => {
      const tx = build();
      const txid = fluxnode.txidStart(tx);
      expect(txid).to.match(/^[0-9a-f]{64}$/);
      expect(tx).to.include(`41${signatureFor(txid, signerWif)}`);
    });
  });

  it('matches the previous result when the signature is the last field', () => {
    layouts.slice(0, 3).forEach(([, build]) => {
      const tx = build();
      expect(fluxnode.txidStart(tx)).to.equal(legacyTxidStart(tx));
    });
  });

  it('differs from the previous (wrong) result when delegate data follows the signature', () => {
    const tx = layouts[3][1]();
    expect(fluxnode.txidStart(tx)).to.not.equal(legacyTxidStart(tx));
  });

  it('rejects malformed transactions', () => {
    const tx = layouts[4][1]();
    expect(() => fluxnode.txidStart(tx.slice(0, -2))).to.throw('truncated');
    expect(() => fluxnode.txidStart(`${tx}00`)).to.throw('trailing data');
    expect(() => fluxnode.txidStart(`${tx.slice(0, 8)}04${tx.slice(10)}`)).to.throw('Not a FluxNode start transaction');
    expect(() => fluxnode.txidStart(`07${tx.slice(2)}`)).to.throw('Unsupported FluxNode transaction version 7');
    expect(() => fluxnode.txidStart(`${tx}0`)).to.throw('Invalid rawtx');
  });
});

describe('start transaction input validation', () => {
  const build = (overrides = {}) => {
    const a = {
      outHash: OUT_HASH, outIndex: '0', timestamp: TIMESTAMP, redeemScript: REDEEM_SCRIPT, delegateData: null, ...overrides,
    };
    return fluxnode.startFluxNodev6(a.outHash, a.outIndex, COLLATERAL_WIF, NODE_WIF, a.timestamp, true, false, a.redeemScript, a.delegateData);
  };

  it('rejects a collateral hash that is not 32 bytes of hex', () => {
    [OUT_HASH.slice(0, 62), OUT_HASH.slice(0, 63), `${OUT_HASH}00`, `zz${OUT_HASH.slice(2)}`, `${OUT_HASH.slice(0, 62)}zz`, 42, null].forEach((outHash) => {
      expect(() => build({ outHash })).to.throw('Invalid collateralOutHash');
    });
  });

  it('treats hex case-insensitively', () => {
    expect(build({ outHash: OUT_HASH.toUpperCase() })).to.equal(build());
  });

  it('accepts numbers or decimal strings for the index and timestamp, nothing else', () => {
    expect(build({ outIndex: 0, timestamp: Number(TIMESTAMP) })).to.equal(build());
    [-1, 2 ** 32, 1.5, '1.5', '0x1', '-1', '', 'abc', null, undefined].forEach((bad) => {
      expect(() => build({ outIndex: bad })).to.throw('Invalid collateralOutIndex');
      expect(() => build({ timestamp: bad })).to.throw('Invalid timestamp');
    });
  });

  it('rejects a malformed redeem script', () => {
    expect(() => build({ redeemScript: REDEEM_SCRIPT.slice(0, -1) })).to.throw('Invalid redeemScript');
    expect(() => build({ redeemScript: `${REDEEM_SCRIPT.slice(0, -2)}zz` })).to.throw('Invalid redeemScript');
    expect(() => build({ redeemScript: '00'.repeat(521) })).to.throw('Invalid redeemScript');
  });

  it('rejects malformed delegate data', () => {
    const cases = [
      [[DELEGATE_KEY], 'expected an object'],
      [{ version: 2, type: 1, delegatePublicKeys: [DELEGATE_KEY] }, 'only version 1'],
      [{ version: 1, type: 3 }, 'Invalid delegateData.type'],
      [{ version: 1, type: '1', delegatePublicKeys: [DELEGATE_KEY] }, 'Invalid delegateData.type'],
      [{ version: 1, type: 2, delegatePublicKeys: [DELEGATE_KEY] }, 'only allowed with DELEGATE_TYPE_UPDATE'],
      [{ version: 1, type: 1 }, 'requires a delegatePublicKeys array'],
      [{ version: 1, type: 1, delegatePublicKeys: [DELEGATE_KEY, DELEGATE_KEY] }, 'duplicate delegate public keys'],
      [{ version: 1, type: 1, delegatePublicKeys: [NOT_ON_CURVE] }, 'not a valid secp256k1 public key'],
      [{ version: 1, type: 1, delegatePublicKeys: [fluxnode.getPublicKeyFromPrivateKey(DELEGATE_WIF, false)] }, '33-byte compressed'],
      [{ version: 1, type: 1, delegatePublicKeys: [`${DELEGATE_KEY.slice(0, -2)}zz`] }, 'Invalid delegate public key 0'],
      [{ version: 1, type: 1, delegatePublicKeys: [DELEGATE_KEY, DELEGATE_KEY_2, DELEGATE_KEY, DELEGATE_KEY_2, DELEGATE_KEY] }, 'Too many delegate public keys'],
    ];
    cases.forEach(([delegateData, message]) => {
      expect(() => build({ delegateData })).to.throw(message);
    });
  });

  it('rejects an invalid fluxnode public key in startFluxNodev6WithPubKey', () => {
    const nodePub = fluxnode.getFluxNodePublicKey(NODE_WIF, true);
    const withPubKey = (key) => fluxnode.startFluxNodev6WithPubKey(OUT_HASH, '0', COLLATERAL_WIF, key, TIMESTAMP, true, REDEEM_SCRIPT);
    expect(withPubKey(nodePub)).to.be.a('string');
    [NOT_ON_CURVE, nodePub.slice(0, 64), `05${nodePub.slice(2)}`, `${nodePub}00`, `${nodePub.slice(0, -2)}zz`, ''].forEach((key) => {
      expect(() => withPubKey(key)).to.throw('Invalid fluxnodePublicKey');
    });
  });

  it('keeps the call shape SSP uses working', () => {
    const nodePub = fluxnode.getFluxNodePublicKey(NODE_WIF, true);
    const tx = fluxnode.startFluxNodev6WithPubKey(OUT_HASH, 0, COLLATERAL_WIF, nodePub, TIMESTAMP, true, REDEEM_SCRIPT, { version: 1, type: 1, delegatePublicKeys: [DELEGATE_KEY] });
    expect(tx).to.include(`41${signatureFor(fluxnode.txidStart(tx), COLLATERAL_WIF)}`);
  });
});

describe('WIF decoding', () => {
  it('rejects base58check payloads that are not a private key', () => {
    const key = Buffer.alloc(32, 1);
    const encode = (...parts) => bs58check.encode(Buffer.concat(parts));
    const notCompressedFlag = encode(Buffer.from([0x80]), key, Buffer.from([0x02]));
    const tooShort = encode(Buffer.from([0x80]), key.subarray(0, 20));
    const tooLong = encode(Buffer.from([0x80]), key, Buffer.from([0x01, 0x01]));
    [notCompressedFlag, tooShort, tooLong].forEach((wif) => {
      expect(() => fluxnode.getCollateralPublicKey(wif)).to.throw('Invalid WIF private key');
    });
  });
});
