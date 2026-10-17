const secp256k1 = require('secp256k1');
const bs58check = require('bs58check').default;
const btcmessage = require('@runonflux/bitcoinjs-message');
const zcrypto = require('./crypto');

// FluxNode transaction version constants
// eslint-disable-next-line no-unused-vars
const FLUXNODE_TX_VERSION = 5;
// eslint-disable-next-line no-unused-vars
const FLUXNODE_TX_UPGRADEABLE_VERSION = 6;

// Legacy version constants for backward compatibility
const FLUXNODE_INTERNAL_NORMAL_TX_VERSION = 1;
const FLUXNODE_INTERNAL_P2SH_TX_VERSION = 2;

// Bit-based version system
// Bits 0-7: Transaction type
// eslint-disable-next-line no-unused-vars
const FLUXNODE_TX_TYPE_MASK = 0xFF;
const FLUXNODE_TX_TYPE_NORMAL_BIT = 0x01; // Bit 0
const FLUXNODE_TX_TYPE_P2SH_BIT = 0x02; // Bit 1

// Bits 8-15: Feature flags
// eslint-disable-next-line no-unused-vars
const FLUXNODE_TX_FEATURE_MASK = 0xFF00;
const FLUXNODE_TX_FEATURE_DELEGATES_BIT = 0x0100; // Bit 8

// Delegate type constants
const DELEGATE_TYPE_NONE = 0;
const DELEGATE_TYPE_UPDATE = 1;
const DELEGATE_TYPE_SIGNING = 2;

const DELEGATE_VERSION_INITIAL = 1;
const MAX_DELEGATE_PUBKEYS = 4;

const UINT32_MAX = 0xFFFFFFFF;
// A P2SH redeem script is pushed as one stack element, so it is limited to 520 bytes.
const MAX_REDEEM_SCRIPT_BYTES = 520;

// Input validation. Every field below ends up inside the signed message, so a
// malformed value must be rejected rather than silently decoded into something
// else (Buffer.from(hex) stops at the first invalid character and drops an odd
// trailing digit).

function assertHex(value, name) {
  if (typeof value !== 'string' || value.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(value)) {
    throw new Error(`Invalid ${name}: expected an even-length hex string`);
  }
  return value.toLowerCase();
}

// Accepts a number or a decimal string (existing callers pass strings).
function toUInt32(value, name) {
  const n = typeof value === 'string' && /^\d+$/.test(value) ? Number(value) : value;
  if (!Number.isSafeInteger(n) || n < 0 || n > UINT32_MAX) {
    throw new Error(`Invalid ${name}: expected an integer from 0 to ${UINT32_MAX}`);
  }
  return n;
}

function assertTxid(value, name) {
  const hex = assertHex(value, name);
  if (hex.length !== 64) {
    throw new Error(`Invalid ${name}: expected 32 bytes (64 hex characters)`);
  }
  return hex;
}

function assertPublicKey(value, name, compressedOnly = false) {
  const hex = assertHex(value, name);
  const length = hex.length / 2;
  if (compressedOnly ? length !== 33 : length !== 33 && length !== 65) {
    throw new Error(`Invalid ${name}: expected a ${compressedOnly ? '33-byte compressed' : '33- or 65-byte'} public key`);
  }
  if (!secp256k1.publicKeyVerify(Buffer.from(hex, 'hex'))) {
    throw new Error(`Invalid ${name}: not a valid secp256k1 public key`);
  }
  return hex;
}

function assertRedeemScript(value) {
  const hex = assertHex(value, 'redeemScript');
  if (hex.length === 0 || hex.length / 2 > MAX_REDEEM_SCRIPT_BYTES) {
    throw new Error(`Invalid redeemScript: expected 1 to ${MAX_REDEEM_SCRIPT_BYTES} bytes`);
  }
  return hex;
}

// Returns a validated copy of delegateData, in the form serializeDelegateData expects.
function normalizeDelegateData(delegateData) {
  if (typeof delegateData !== 'object' || delegateData === null || Array.isArray(delegateData)) {
    throw new Error('Invalid delegateData: expected an object');
  }
  const version = delegateData.version === undefined ? DELEGATE_VERSION_INITIAL : delegateData.version;
  if (version !== DELEGATE_VERSION_INITIAL) {
    throw new Error(`Invalid delegateData.version: only version ${DELEGATE_VERSION_INITIAL} is supported`);
  }
  const { type, delegatePublicKeys } = delegateData;
  if (type !== DELEGATE_TYPE_NONE && type !== DELEGATE_TYPE_UPDATE && type !== DELEGATE_TYPE_SIGNING) {
    throw new Error('Invalid delegateData.type: expected DELEGATE_TYPE_NONE, DELEGATE_TYPE_UPDATE or DELEGATE_TYPE_SIGNING');
  }
  if (type !== DELEGATE_TYPE_UPDATE) {
    if (delegatePublicKeys !== undefined && delegatePublicKeys !== null) {
      throw new Error('Invalid delegateData: delegatePublicKeys are only allowed with DELEGATE_TYPE_UPDATE');
    }
    return { version, type };
  }
  // An UPDATE always carries the key vector (an empty one clears the delegates).
  if (!Array.isArray(delegatePublicKeys)) {
    throw new Error('Invalid delegateData: DELEGATE_TYPE_UPDATE requires a delegatePublicKeys array');
  }
  if (delegatePublicKeys.length > MAX_DELEGATE_PUBKEYS) {
    throw new Error(`Too many delegate public keys. Maximum is ${MAX_DELEGATE_PUBKEYS}`);
  }
  const keys = delegatePublicKeys.map((key, i) => assertPublicKey(key, `delegate public key ${i}`, true));
  if (new Set(keys).size !== keys.length) {
    throw new Error('Invalid delegateData: duplicate delegate public keys');
  }
  return { version, type, delegatePublicKeys: keys };
}

function doubleHash(msg) {
  const bufMessage = Buffer.from(msg, 'hex');
  const message = zcrypto.sha256x2(bufMessage).toString('hex');
  return message;
}

function varintBufNum(n) {
  let buf;
  if (n < 253) {
    buf = Buffer.alloc(1);
    buf.writeUInt8(n, 0);
  } else if (n < 0x10000) {
    buf = Buffer.alloc(1 + 2);
    buf.writeUInt8(253, 0);
    buf.writeUInt16LE(n, 1);
  } else if (n < 0x100000000) {
    buf = Buffer.alloc(1 + 4);
    buf.writeUInt8(254, 0);
    buf.writeUInt32LE(n, 1);
  } else {
    buf = Buffer.alloc(1 + 8);
    buf.writeUInt8(255, 0);
    // eslint-disable-next-line no-bitwise
    buf.writeInt32LE(n & -1, 1);
    buf.writeUInt32LE(Math.floor(n / 0x100000000), 5);
  }
  return buf;
}

// reverse hex string byte order
function reverseHex(hex) {
  const buf = Buffer.from(hex, 'hex').reverse();
  return buf.toString('hex');
}

function WIFToPrivKey(wifPk) {
  const decoded = Buffer.from(bs58check.decode(wifPk));
  // version byte + 32-byte key, followed by 0x01 when the key is compressed
  if (!(decoded.length === 33 || (decoded.length === 34 && decoded[33] === 0x01))) {
    throw new Error('Invalid WIF private key');
  }
  return decoded.subarray(1, 33).toString('hex');
}

function signMessage(message, privKey, compressed = true, strMessageMagic = '\u0018Zelcash Signed Message:\n', options) {
  let adjPrivKey = privKey;
  if (adjPrivKey.length !== 64) {
    adjPrivKey = WIFToPrivKey(adjPrivKey);
  }
  const privateKey = Buffer.from(adjPrivKey, 'hex');
  const mysignature = btcmessage.sign(message, privateKey, compressed, strMessageMagic, options);
  return mysignature.toString('base64');
}

function signStartMessage(message, privKey, compressed = true) {
  let adjPrivKey = privKey;
  if (adjPrivKey.length !== 64) {
    adjPrivKey = WIFToPrivKey(adjPrivKey);
  }
  const privateKey = Buffer.from(adjPrivKey, 'hex');
  const strMessageMagic = '\u0018Zelcash Signed Message:\n';
  const hashofMessage = doubleHash(message);
  const txid = reverseHex(hashofMessage);
  const mysignature = btcmessage.sign(txid, privateKey, compressed, strMessageMagic);
  return mysignature.toString('hex');
}

function getFluxNodePublicKey(fluxnodePrivateKey, comprossed = false) {
  const og = WIFToPrivKey(fluxnodePrivateKey);

  const pkBuffer = Buffer.from(og, 'hex');
  const publicKey = Buffer.from(secp256k1.publicKeyCreate(pkBuffer, comprossed));
  return publicKey.toString('hex');
}

// well this is not ideal, but unless that address already spent some coins, we do not have other way to get the public key from it
function getCollateralPublicKey(collateralPrivateKey, compressed = true) {
  const og = WIFToPrivKey(collateralPrivateKey);

  const toCompressed = compressed;

  const pkBuffer = Buffer.from(og, 'hex');
  const publicKey = Buffer.from(secp256k1.publicKeyCreate(pkBuffer, toCompressed));
  return publicKey.toString('hex');
}

// Helper function to get public key from private key
function getPublicKeyFromPrivateKey(privateKey, compressed = true) {
  const og = WIFToPrivKey(privateKey);
  const pkBuffer = Buffer.from(og, 'hex');
  const publicKey = Buffer.from(secp256k1.publicKeyCreate(pkBuffer, compressed));
  return publicKey.toString('hex');
}

// Helper functions for version checking
function hasConflictingBits(version) {
  // eslint-disable-next-line no-bitwise
  return (version & FLUXNODE_TX_TYPE_NORMAL_BIT) !== 0 && (version & FLUXNODE_TX_TYPE_P2SH_BIT) !== 0;
}

function isFluxTxNormalType(version) {
  if (hasConflictingBits(version)) {
    return false;
  }
  // eslint-disable-next-line no-bitwise
  return (version & FLUXNODE_TX_TYPE_NORMAL_BIT) !== 0 || version === FLUXNODE_INTERNAL_NORMAL_TX_VERSION;
}

function isFluxTxP2SHType(version) {
  if (hasConflictingBits(version)) {
    return false;
  }
  // eslint-disable-next-line no-bitwise
  return (version & FLUXNODE_TX_TYPE_P2SH_BIT) !== 0 || version === FLUXNODE_INTERNAL_P2SH_TX_VERSION;
}

function hasFluxTxDelegatesFeature(version) {
  // eslint-disable-next-line no-bitwise
  return (version & FLUXNODE_TX_FEATURE_DELEGATES_BIT) !== 0;
}

// Serialize delegate data
function serializeDelegateData(delegateData) {
  let serialized = '';

  // nDelegateVersion (1 byte)
  const versionBuf = Buffer.alloc(1);
  versionBuf.writeUInt8(delegateData.version || DELEGATE_VERSION_INITIAL);
  serialized += versionBuf.toString('hex');

  // nType (1 byte)
  const typeBuf = Buffer.alloc(1);
  typeBuf.writeUInt8(delegateData.type);
  serialized += typeBuf.toString('hex');

  // If type is UPDATE, serialize the delegate public keys vector
  if (delegateData.type === DELEGATE_TYPE_UPDATE && delegateData.delegatePublicKeys) {
    // Number of keys (varint) - this is how std::vector is serialized
    const numKeys = delegateData.delegatePublicKeys.length;
    if (numKeys > MAX_DELEGATE_PUBKEYS) {
      throw new Error(`Too many delegate public keys. Maximum is ${MAX_DELEGATE_PUBKEYS}`);
    }

    const numKeysVarint = varintBufNum(numKeys);
    serialized += numKeysVarint.toString('hex');

    // Each CPubKey in the vector
    // eslint-disable-next-line no-restricted-syntax
    for (const pubKey of delegateData.delegatePublicKeys) {
      // CPubKey serialization uses CompactSize for length prefix
      const pubKeyLength = varintBufNum(pubKey.length / 2);
      serialized += pubKeyLength.toString('hex');
      serialized += pubKey;
    }
  }

  return serialized;
}

function startFluxNodev6(collateralOutHash, collateralOutIndex, collateralPrivateKey, fluxnodePrivateKey, timestamp, compressedCollateralPrivateKey = true, compressedFluxnodePrivateKey = false, redeemScript, delegateData = null) {
  const outHash = assertTxid(collateralOutHash, 'collateralOutHash');
  const outIndex = toUInt32(collateralOutIndex, 'collateralOutIndex');
  const time = toUInt32(timestamp, 'timestamp');
  const script = redeemScript ? assertRedeemScript(redeemScript) : null;
  const delegates = delegateData ? normalizeDelegateData(delegateData) : null;

  // it is up to wallet to find out collateral Public Key.
  const version = 6;
  const nType = 2;

  const FLUXNODE_NORMAL_TX_VERSION = 1;
  const FLUXNODE_P2SH_TX_VERSION = 2;

  let nFluxNodeTxVersion = FLUXNODE_NORMAL_TX_VERSION;
  if (script) {
    nFluxNodeTxVersion = FLUXNODE_P2SH_TX_VERSION;
  }

  // Add delegate feature bit if delegate data is provided
  if (delegates) {
    // eslint-disable-next-line no-bitwise
    nFluxNodeTxVersion |= FLUXNODE_TX_FEATURE_DELEGATES_BIT;
  }

  let serializedTx = '';

  // Version
  const buf32 = Buffer.alloc(4);
  buf32.writeUInt32LE(version);
  serializedTx += buf32.toString('hex');

  // nType
  const buf8 = Buffer.alloc(1);
  buf8.writeUInt8(nType);
  serializedTx += buf8.toString('hex');

  // nFluxNodeTxVersion
  const buf32A = Buffer.alloc(4);
  buf32A.writeUInt32LE(nFluxNodeTxVersion, 0);
  serializedTx += buf32A.toString('hex');

  // collateralOutHash
  serializedTx += reverseHex(outHash);

  // collateralOutIndex
  const buf32B = Buffer.alloc(4);
  buf32B.writeUInt32LE(outIndex, 0);
  serializedTx += buf32B.toString('hex');

  // Check if this is a normal tx (not P2SH)
  // eslint-disable-next-line no-bitwise
  const isNormalTx = isFluxTxNormalType(nFluxNodeTxVersion) && !(nFluxNodeTxVersion & FLUXNODE_TX_TYPE_P2SH_BIT);
  const isP2SHTx = isFluxTxP2SHType(nFluxNodeTxVersion);

  if (isNormalTx) {
    // get collateral public key
    const collateralPublicKey = getCollateralPublicKey(collateralPrivateKey, compressedCollateralPrivateKey);

    // collateralPublicKeyLength
    const pubKeyLength = varintBufNum(collateralPublicKey.length / 2);
    serializedTx += pubKeyLength.toString('hex');

    // collateralPublicKey
    serializedTx += collateralPublicKey;
  }

  // get public key from fluxnode private key;
  const fluxnodePublicKey = getFluxNodePublicKey(fluxnodePrivateKey, compressedFluxnodePrivateKey);

  // fluxnodePublicKeyLength
  const pubKeyLength = varintBufNum(fluxnodePublicKey.length / 2);
  serializedTx += pubKeyLength.toString('hex');

  // fluxnodePublicKey
  serializedTx += fluxnodePublicKey;

  if (isP2SHTx) {
    // redeemScriptLength
    const redeemScriptLength = varintBufNum(script.length / 2);
    serializedTx += redeemScriptLength.toString('hex');

    // redeemScript
    serializedTx += script;
  }

  // timestamp
  const buf32C = Buffer.alloc(4);
  buf32C.writeUInt32LE(time);
  serializedTx += buf32C.toString('hex');

  // Build transaction for signing (includes delegate data but not signature)
  let txForSigning = serializedTx;

  // Add delegate data to the transaction we're going to sign
  if (hasFluxTxDelegatesFeature(nFluxNodeTxVersion)) {
    // fUsingDelegates (1 byte boolean)
    const usingDelegates = delegates !== null;
    const delegateBoolBuf = Buffer.alloc(1);
    delegateBoolBuf.writeUInt8(usingDelegates ? 1 : 0);
    txForSigning += delegateBoolBuf.toString('hex');

    if (usingDelegates) {
      // Serialize the delegate data
      txForSigning += serializeDelegateData(delegates);
    }
  }

  // Sign the transaction (including delegate data)
  const signature = signStartMessage(txForSigning, collateralPrivateKey, compressedCollateralPrivateKey);

  // Now build the final transaction with signature in the right place
  // Add signature BEFORE delegate data (matches C++ serialization order)
  const sigLength = varintBufNum(signature.length / 2);
  serializedTx += sigLength.toString('hex');
  serializedTx += signature;

  // Then add delegate data after signature
  if (hasFluxTxDelegatesFeature(nFluxNodeTxVersion)) {
    // fUsingDelegates (1 byte boolean)
    const usingDelegates = delegates !== null;
    const delegateBoolBuf = Buffer.alloc(1);
    delegateBoolBuf.writeUInt8(usingDelegates ? 1 : 0);
    serializedTx += delegateBoolBuf.toString('hex');

    if (usingDelegates) {
      // Serialize the delegate data
      serializedTx += serializeDelegateData(delegates);
    }
  }

  return serializedTx;
}

// Same as startFluxNodev6 but accepts fluxnodePublicKey directly instead of deriving from private key.
// This avoids transmitting the identity private key — only the public key is needed since the identity key does not sign.
function startFluxNodev6WithPubKey(collateralOutHash, collateralOutIndex, collateralPrivateKey, fluxnodePublicKey, timestamp, compressedCollateralPrivateKey = true, redeemScript, delegateData = null) {
  const outHash = assertTxid(collateralOutHash, 'collateralOutHash');
  const outIndex = toUInt32(collateralOutIndex, 'collateralOutIndex');
  const nodePubKey = assertPublicKey(fluxnodePublicKey, 'fluxnodePublicKey');
  const time = toUInt32(timestamp, 'timestamp');
  const script = redeemScript ? assertRedeemScript(redeemScript) : null;
  const delegates = delegateData ? normalizeDelegateData(delegateData) : null;

  const version = 6;
  const nType = 2;

  const FLUXNODE_NORMAL_TX_VERSION = 1;
  const FLUXNODE_P2SH_TX_VERSION = 2;

  let nFluxNodeTxVersion = FLUXNODE_NORMAL_TX_VERSION;
  if (script) {
    nFluxNodeTxVersion = FLUXNODE_P2SH_TX_VERSION;
  }

  if (delegates) {
    // eslint-disable-next-line no-bitwise
    nFluxNodeTxVersion |= FLUXNODE_TX_FEATURE_DELEGATES_BIT;
  }

  let serializedTx = '';

  // Version
  const buf32 = Buffer.alloc(4);
  buf32.writeUInt32LE(version);
  serializedTx += buf32.toString('hex');

  // nType
  const buf8 = Buffer.alloc(1);
  buf8.writeUInt8(nType);
  serializedTx += buf8.toString('hex');

  // nFluxNodeTxVersion
  const buf32A = Buffer.alloc(4);
  buf32A.writeUInt32LE(nFluxNodeTxVersion, 0);
  serializedTx += buf32A.toString('hex');

  // collateralOutHash
  serializedTx += reverseHex(outHash);

  // collateralOutIndex
  const buf32B = Buffer.alloc(4);
  buf32B.writeUInt32LE(outIndex, 0);
  serializedTx += buf32B.toString('hex');

  // eslint-disable-next-line no-bitwise
  const isNormalTx = isFluxTxNormalType(nFluxNodeTxVersion) && !(nFluxNodeTxVersion & FLUXNODE_TX_TYPE_P2SH_BIT);
  const isP2SHTx = isFluxTxP2SHType(nFluxNodeTxVersion);

  if (isNormalTx) {
    const collateralPublicKey = getCollateralPublicKey(collateralPrivateKey, compressedCollateralPrivateKey);
    const cpkLength = varintBufNum(collateralPublicKey.length / 2);
    serializedTx += cpkLength.toString('hex');
    serializedTx += collateralPublicKey;
  }

  // fluxnodePublicKey — provided directly, no derivation needed
  const fnpkLength = varintBufNum(nodePubKey.length / 2);
  serializedTx += fnpkLength.toString('hex');
  serializedTx += nodePubKey;

  if (isP2SHTx) {
    const redeemScriptLength = varintBufNum(script.length / 2);
    serializedTx += redeemScriptLength.toString('hex');
    serializedTx += script;
  }

  // timestamp
  const buf32C = Buffer.alloc(4);
  buf32C.writeUInt32LE(time);
  serializedTx += buf32C.toString('hex');

  // Build transaction for signing (includes delegate data but not signature)
  let txForSigning = serializedTx;

  if (hasFluxTxDelegatesFeature(nFluxNodeTxVersion)) {
    const usingDelegates = delegates !== null;
    const delegateBoolBuf = Buffer.alloc(1);
    delegateBoolBuf.writeUInt8(usingDelegates ? 1 : 0);
    txForSigning += delegateBoolBuf.toString('hex');
    if (usingDelegates) {
      txForSigning += serializeDelegateData(delegates);
    }
  }

  // Sign with collateral key only
  const signature = signStartMessage(txForSigning, collateralPrivateKey, compressedCollateralPrivateKey);

  const sigLength = varintBufNum(signature.length / 2);
  serializedTx += sigLength.toString('hex');
  serializedTx += signature;

  if (hasFluxTxDelegatesFeature(nFluxNodeTxVersion)) {
    const usingDelegates = delegates !== null;
    const delegateBoolBuf = Buffer.alloc(1);
    delegateBoolBuf.writeUInt8(usingDelegates ? 1 : 0);
    serializedTx += delegateBoolBuf.toString('hex');
    if (usingDelegates) {
      serializedTx += serializeDelegateData(delegates);
    }
  }

  return serializedTx;
}

// fluxnodePrivateKey as WIF formate, collateralPrivateKey as WIF, timestamp in seconds
function startFluxNode(collateralOutHash, collateralOutIndex, collateralPrivateKey, fluxnodePrivateKey, timestamp, compressedCollateralPrivateKey = true, compressedFluxnodePrivateKey = false, redeemScript) {
  if (redeemScript) {
    // p2sh nodes, use v6
    const startFluxNodev6Result = startFluxNodev6(collateralOutHash, collateralOutIndex, collateralPrivateKey, fluxnodePrivateKey, timestamp, compressedCollateralPrivateKey, compressedFluxnodePrivateKey, redeemScript);
    return startFluxNodev6Result;
  }
  const outHash = assertTxid(collateralOutHash, 'collateralOutHash');
  const outIndex = toUInt32(collateralOutIndex, 'collateralOutIndex');
  const time = toUInt32(timestamp, 'timestamp');

  // it is up to wallet to find out collateral Public Key.
  const version = 5;
  const nType = 2;

  let serializedTx = '';

  // Version
  const buf32 = Buffer.alloc(4);
  buf32.writeUInt32LE(version);
  serializedTx += buf32.toString('hex');

  // nType
  const buf8 = Buffer.alloc(1);
  buf8.writeUInt8(nType);
  serializedTx += buf8.toString('hex');

  // collateralOutHash
  serializedTx += reverseHex(outHash);

  // collateralOutIndex
  const buf32B = Buffer.alloc(4);
  buf32B.writeUInt32LE(outIndex, 0);
  serializedTx += buf32B.toString('hex');

  // get collateral public key
  const collateralPublicKey = getCollateralPublicKey(collateralPrivateKey, compressedCollateralPrivateKey);

  // collateralPublicKeyLength
  const collateralPublicKeyLength = varintBufNum(collateralPublicKey.length / 2);
  serializedTx += collateralPublicKeyLength.toString('hex');

  // collateralPublicKey
  serializedTx += collateralPublicKey;

  // get public key from fluxnode private key;
  const fluxnodePublicKey = getFluxNodePublicKey(fluxnodePrivateKey, compressedFluxnodePrivateKey);

  // fluxnodePublicKeyLength
  const pubKeyLength = varintBufNum(fluxnodePublicKey.length / 2);
  serializedTx += pubKeyLength.toString('hex');

  // fluxnodePublicKey
  serializedTx += fluxnodePublicKey;

  // timestamp
  const buf32C = Buffer.alloc(4);
  buf32C.writeUInt32LE(time);
  serializedTx += buf32C.toString('hex');

  // Signing it
  const signature = signStartMessage(serializedTx, collateralPrivateKey, compressedCollateralPrivateKey);

  // signatureLength
  const sigLength = varintBufNum(signature.length / 2);
  serializedTx += sigLength.toString('hex');

  // fluxnodePublicKey
  serializedTx += signature;

  return serializedTx;
}

// Function to start FluxNode and add delegates (owner adding delegate permissions)
function startFluxNodeAddDelegate(collateralOutHash, collateralOutIndex, collateralPrivateKey, fluxnodePrivateKey, timestamp, delegatePublicKeys, compressedCollateralPrivateKey = true, compressedFluxnodePrivateKey = false, redeemScript = null) {
  // Validate delegate public keys
  if (!delegatePublicKeys || !Array.isArray(delegatePublicKeys)) {
    throw new Error('delegatePublicKeys array is required for startFluxNodeAddDelegate');
  }

  if (delegatePublicKeys.length === 0) {
    throw new Error('At least one delegate public key must be provided');
  }

  if (delegatePublicKeys.length > MAX_DELEGATE_PUBKEYS) {
    throw new Error(`Too many delegate public keys. Maximum is ${MAX_DELEGATE_PUBKEYS}`);
  }

  // Validate each public key
  // eslint-disable-next-line no-restricted-syntax
  for (const pubKey of delegatePublicKeys) {
    if (typeof pubKey !== 'string' || pubKey.length !== 66) {
      throw new Error('Invalid delegate public key format. Must be 33 bytes (66 hex chars) compressed public key');
    }
  }

  // Create delegate data for UPDATE type
  const delegateData = {
    version: DELEGATE_VERSION_INITIAL,
    type: DELEGATE_TYPE_UPDATE,
    delegatePublicKeys,
  };

  // Use v6 with delegate data
  return startFluxNodev6(
    collateralOutHash,
    collateralOutIndex,
    collateralPrivateKey,
    fluxnodePrivateKey,
    timestamp,
    compressedCollateralPrivateKey,
    compressedFluxnodePrivateKey,
    redeemScript,
    delegateData,
  );
}

// Function for delegates to start a FluxNode (delegate using their permission)
function startFluxNodeAsDelegate(collateralOutHash, collateralOutIndex, delegatePrivateKey, fluxnodePrivateKey, timestamp, compressedDelegatePrivateKey = true, compressedFluxnodePrivateKey = false, redeemScript = null) {
  // Create delegate data for SIGNING type
  const delegateData = {
    version: DELEGATE_VERSION_INITIAL,
    type: DELEGATE_TYPE_SIGNING,
  };

  // Note: When signing as a delegate, we use the delegate's private key instead of collateral private key
  // Use v6 with delegate data
  return startFluxNodev6(
    collateralOutHash,
    collateralOutIndex,
    delegatePrivateKey, // Using delegate's private key for signing
    fluxnodePrivateKey,
    timestamp,
    compressedDelegatePrivateKey, // Compression for delegate key
    compressedFluxnodePrivateKey,
    redeemScript,
    delegateData,
  );
}

// Helper function to create delegate data object for advanced use cases
function createDelegateData(type, delegatePublicKeys = null, delegatePrivateKeys = null) {
  const delegateData = {
    version: DELEGATE_VERSION_INITIAL,
    type,
  };

  if (type === DELEGATE_TYPE_UPDATE) {
    if (!delegatePublicKeys && delegatePrivateKeys) {
      // Convert private keys to public keys
      delegateData.delegatePublicKeys = delegatePrivateKeys.map((privKey) => getPublicKeyFromPrivateKey(privKey, true)); // Always use compressed keys for delegates
    } else if (delegatePublicKeys) {
      delegateData.delegatePublicKeys = delegatePublicKeys;
    } else {
      throw new Error('Either delegatePublicKeys or delegatePrivateKeys must be provided for UPDATE type');
    }
  }

  return delegateData;
}

// Helper to convert delegate private keys to public keys
function convertDelegatePrivateKeysToPublic(delegatePrivateKeys) {
  if (!delegatePrivateKeys || !Array.isArray(delegatePrivateKeys)) {
    throw new Error('delegatePrivateKeys must be an array');
  }

  return delegatePrivateKeys.map((privKey) => getPublicKeyFromPrivateKey(privKey, true)); // Always use compressed keys for delegates
}

// Byte range of the collateral signature (with its CompactSize length prefix) in
// a FluxNode start transaction, found by walking the same layout the functions
// above serialize. In v6 the delegate data follows the signature, so the
// signature is not always the last field.
function locateStartSignature(buf) {
  let offset = 0;
  const need = (n) => {
    if (offset + n > buf.length) throw new Error('Invalid FluxNode start transaction: truncated');
  };
  const skip = (n) => {
    need(n);
    offset += n;
  };
  const readCompactSize = () => {
    need(1);
    const first = buf[offset];
    if (first < 253) {
      offset += 1;
      return first;
    }
    if (first === 253) {
      need(3);
      const value = buf.readUInt16LE(offset + 1);
      offset += 3;
      return value;
    }
    if (first === 254) {
      need(5);
      const value = buf.readUInt32LE(offset + 1);
      offset += 5;
      return value;
    }
    throw new Error('Invalid FluxNode start transaction: unsupported CompactSize');
  };
  const skipVarBytes = () => skip(readCompactSize());

  need(5);
  const version = buf.readUInt32LE(0);
  const nType = buf.readUInt8(4);
  offset = 5;
  if (nType !== 2) throw new Error('Not a FluxNode start transaction');
  if (version !== 5 && version !== 6) throw new Error(`Unsupported FluxNode transaction version ${version}`);

  let nFluxNodeTxVersion = FLUXNODE_INTERNAL_NORMAL_TX_VERSION;
  if (version === 6) {
    need(4);
    nFluxNodeTxVersion = buf.readUInt32LE(offset);
    offset += 4;
  }
  skip(36); // collateral outpoint
  // eslint-disable-next-line no-bitwise
  if (isFluxTxNormalType(nFluxNodeTxVersion) && !(nFluxNodeTxVersion & FLUXNODE_TX_TYPE_P2SH_BIT)) {
    skipVarBytes(); // collateral public key
  }
  skipVarBytes(); // fluxnode public key
  if (isFluxTxP2SHType(nFluxNodeTxVersion)) {
    skipVarBytes(); // redeem script
  }
  skip(4); // timestamp
  const sigStart = offset;
  skipVarBytes(); // signature
  const sigEnd = offset;

  if (version === 6 && hasFluxTxDelegatesFeature(nFluxNodeTxVersion)) {
    need(1);
    const usingDelegates = buf[offset];
    offset += 1;
    if (usingDelegates > 1) throw new Error('Invalid FluxNode start transaction: bad delegate flag');
    if (usingDelegates === 1) {
      need(2);
      const type = buf[offset + 1];
      offset += 2;
      if (type === DELEGATE_TYPE_UPDATE) {
        const count = readCompactSize();
        for (let i = 0; i < count; i += 1) skipVarBytes();
      }
    }
  }
  if (offset !== buf.length) throw new Error('Invalid FluxNode start transaction: trailing data');
  return { sigStart, sigEnd };
}

// The txid of a FluxNode start transaction: the double SHA-256 of the
// transaction without its signature, which is also the message the collateral
// key signs.
function txidStart(rawtx) {
  const buf = Buffer.from(assertHex(rawtx, 'rawtx'), 'hex');
  const { sigStart, sigEnd } = locateStartSignature(buf);
  const unsigned = Buffer.concat([buf.subarray(0, sigStart), buf.subarray(sigEnd)]);
  return reverseHex(doubleHash(unsigned.toString('hex')));
}

function txidConfirm(rawtx) {
  // signature is 41 hex length in bytes, remove last 41 -> 65 in decimal. Remove last 65+1 byte (byte before states the signature size); There is also benchmark signature
  const adjustedRawTx = rawtx.substr(0, rawtx.length - 264);
  const hash = doubleHash(adjustedRawTx);
  const txid = reverseHex(hash);
  return txid;
}

module.exports = {
  startFluxNode,
  startFluxNodeAddDelegate,
  startFluxNodeAsDelegate,
  createDelegateData,
  convertDelegatePrivateKeysToPublic,
  getFluxNodePublicKey,
  getCollateralPublicKey,
  getPublicKeyFromPrivateKey,
  signMessage,
  doubleHash,
  signStartMessage,
  txidStart,
  txidConfirm,
  startFluxNodev6,
  startFluxNodev6WithPubKey,
  // Export constants for external use
  DELEGATE_TYPE_NONE,
  DELEGATE_TYPE_UPDATE,
  DELEGATE_TYPE_SIGNING,
  MAX_DELEGATE_PUBKEYS,
};
