# Changelog

## 1.2.0

Hardening release. Calls that built valid transactions before build the same
bytes now; malformed input that used to produce an invalid (or different)
signed transaction now throws instead.

### Fixed

- `txidStart` returns the correct txid for v6 start transactions with delegate
  data (`startFluxNodeAddDelegate`, `startFluxNodeAsDelegate`, or
  `delegateData` passed to `startFluxNodev6` / `startFluxNodev6WithPubKey`).
  It used to drop the last 66 bytes, but in those transactions the delegate
  data follows the signature. It now parses the transaction and removes the
  signature field wherever it is; for transactions whose signature is the last
  field (v5, v6 without delegates) the result is unchanged. It throws on input
  that is not a v5/v6 FluxNode start transaction instead of hashing it anyway.

### Security

- The start transaction builders validate every input before signing:
  - `collateralOutHash`: 32 bytes of hex (case-insensitive);
  - `collateralOutIndex` and `timestamp`: integers from 0 to 2^32 - 1, given as
    numbers or decimal strings;
  - `fluxnodePublicKey` (`startFluxNodev6WithPubKey`): a valid 33- or 65-byte
    secp256k1 public key;
  - `redeemScript`: 1 to 520 bytes of hex;
  - `delegateData`: version 1; type `DELEGATE_TYPE_NONE`, `DELEGATE_TYPE_UPDATE`
    or `DELEGATE_TYPE_SIGNING`; keys only with UPDATE, where the array is
    required (an empty array clears the delegates), holds at most 4 distinct,
    valid, compressed public keys.

  Previously a non-hex character or an odd trailing digit was silently dropped
  by the hex decoder, so the signed transaction could differ from the values a
  wallet displayed.
- WIF decoding checks the payload length (33 bytes, or 34 ending in 0x01)
  instead of truncating whatever it is given.

### Notes

- A start transaction signature is a Zelcash signed message over the 64-hex
  txid. Wallets must not sign a txid-shaped message for an untrusted party with
  a collateral key through a generic "sign message" flow; see the README.
- The lockfile resolves `@runonflux/bitcoinjs-message` 2.4.0 and patched
  transitive dependencies. The `^2.3.0` range is unchanged (only `sign` is used,
  which 2.4.0 did not change).
