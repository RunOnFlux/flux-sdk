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
  let og = Buffer.from(bs58check.decode(wifPk)).toString('hex');
  og = og.substr(2, og.length); // remove WIF format ('80')

  // remove the '01' at the end to 'compress it' during WIF conversion
  if (og.length > 64) {
    og = og.substr(0, 64);
  }

  return og;
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
  // it is up to wallet to find out collateral Public Key.
  const version = 6;
  const nType = 2;

  const FLUXNODE_NORMAL_TX_VERSION = 1;
  const FLUXNODE_P2SH_TX_VERSION = 2;

  let nFluxNodeTxVersion = FLUXNODE_NORMAL_TX_VERSION;
  if (redeemScript) {
    nFluxNodeTxVersion = FLUXNODE_P2SH_TX_VERSION;
  }

  // Add delegate feature bit if delegate data is provided
  if (delegateData) {
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
  serializedTx += reverseHex(collateralOutHash);

  // collateralOutIndex
  const buf32B = Buffer.alloc(4);
  buf32B.writeUInt32LE(collateralOutIndex, 0);
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
    const redeemScriptLength = varintBufNum(redeemScript.length / 2);
    serializedTx += redeemScriptLength.toString('hex');

    // redeemScript
    serializedTx += redeemScript;
  }

  // timestamp
  const buf32C = Buffer.alloc(4);
  buf32C.writeUInt32LE(timestamp);
  serializedTx += buf32C.toString('hex');

  // Build transaction for signing (includes delegate data but not signature)
  let txForSigning = serializedTx;

  // Add delegate data to the transaction we're going to sign
  if (hasFluxTxDelegatesFeature(nFluxNodeTxVersion)) {
    // fUsingDelegates (1 byte boolean)
    const usingDelegates = delegateData !== null;
    const delegateBoolBuf = Buffer.alloc(1);
    delegateBoolBuf.writeUInt8(usingDelegates ? 1 : 0);
    txForSigning += delegateBoolBuf.toString('hex');

    if (usingDelegates) {
      // Serialize the delegate data
      txForSigning += serializeDelegateData(delegateData);
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
    const usingDelegates = delegateData !== null;
    const delegateBoolBuf = Buffer.alloc(1);
    delegateBoolBuf.writeUInt8(usingDelegates ? 1 : 0);
    serializedTx += delegateBoolBuf.toString('hex');

    if (usingDelegates) {
      // Serialize the delegate data
      serializedTx += serializeDelegateData(delegateData);
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
  serializedTx += reverseHex(collateralOutHash);

  // collateralOutIndex
  const buf32B = Buffer.alloc(4);
  buf32B.writeUInt32LE(collateralOutIndex, 0);
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
  buf32C.writeUInt32LE(timestamp);
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

function txidStart(rawtx) {
  // signature is 41 hex length in bytes, remove last 41 -> 65 in decimal. Remove last 65+1 byte (byte before states the signature size);
  const adjustedRawTx = rawtx.substr(0, rawtx.length - 132);
  const hash = doubleHash(adjustedRawTx);
  const txid = reverseHex(hash);
  return txid;
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
  // Export constants for external use
  DELEGATE_TYPE_NONE,
  DELEGATE_TYPE_UPDATE,
  DELEGATE_TYPE_SIGNING,
  MAX_DELEGATE_PUBKEYS,
};
