# Flux SDK
Flux SDK - interact with Flux network
Start your FluxNode

npm i @runonflux/flux-sdk

## FluxNode start transactions

`fluxnode.startFluxNode`, `startFluxNodev6`, `startFluxNodev6WithPubKey`,
`startFluxNodeAddDelegate` and `startFluxNodeAsDelegate` build and sign a
FluxNode start transaction with the collateral (or delegate) key and return it
as hex. `fluxnode.txidStart(rawtx)` returns its txid.

Every input is validated before signing (see the CHANGELOG for the rules) and
an invalid value throws, so what is signed is exactly what the caller passed.

## Security notes

- The collateral key signs a start transaction as a Zelcash signed message
  over the transaction's 64-hex txid (`signStartMessage`). A signature made by
  `signMessage` over the same 64-hex string is the same thing. A wallet that
  lets untrusted parties request message signatures must not sign a message
  that is a 64-character hex string with a collateral key: whoever asked could
  attach that signature to a start transaction of their choosing (for example
  one that adds their delegate keys).
- Releases are published from CI with npm provenance; check it with
  `npm audit signatures`.
