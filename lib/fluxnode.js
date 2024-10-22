const secp256k1 = require('secp256k1');
const bs58check = require('bs58check').default;
const btcmessage = require('@runonflux/bitcoinjs-message');
const zcrypto = require('./crypto');

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

function startFluxNodev6(collateralOutHash, collateralOutIndex, collateralPrivateKey, fluxnodePrivateKey, timestamp, compressedCollateralPrivateKey = true, compressedFluxnodePrivateKey = false, redeemScript) {
  // it is up to wallet to find out collateral Public Key.
  const version = 6;
  const nType = 2;

  const FLUXNODE_NORMAL_TX_VERSION = 1;
  const FLUXNODE_P2SH_TX_VERSION = 2;

  let nFluxNodeTxVersion = FLUXNODE_NORMAL_TX_VERSION;
  if (redeemScript) {
    nFluxNodeTxVersion = FLUXNODE_P2SH_TX_VERSION;
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

  if (nFluxNodeTxVersion === FLUXNODE_NORMAL_TX_VERSION) {
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

  if (nFluxNodeTxVersion === FLUXNODE_P2SH_TX_VERSION) {
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

  // Signing it
  const signature = signStartMessage(serializedTx, collateralPrivateKey, compressedCollateralPrivateKey);

  // signatureLength
  const sigLength = varintBufNum(signature.length / 2);
  serializedTx += sigLength.toString('hex');

  // fluxnodePublicKey
  serializedTx += signature;

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
  getFluxNodePublicKey,
  getCollateralPublicKey,
  signMessage,
  doubleHash,
  signStartMessage,
  txidStart,
  txidConfirm,
  startFluxNodev6,
};
