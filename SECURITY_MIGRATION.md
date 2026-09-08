# Security migration to 0.8

Version 0.8 separates credential planning from cryptographic completion and
makes remote signatures prove possession of the exact prepared payload and
public key. Callers of `PreparedSDJWT::complete` must now supply the public
verification key associated with the remote KMS signature.

Role features are explicit: `issuer-planning` performs no verification,
`issuer-completion` binds KMS output, and `holder`/`verifier` install the
verification backend. Embedders that only need the maintained native/browser
verification provider may enable `crypto-provider`; it exposes no local
signing or private-key codecs. Native RSA verification uses AWS-LC. Browser
WebAssembly rejects RS*/PS* until a maintained browser backend is available.
