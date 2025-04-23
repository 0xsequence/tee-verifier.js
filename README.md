# tee-verifier

TypeScript/JavaScript library for verifying TEE (Trusted Execution Environment) enclave attestations. Currently, only AWS Nitro Enclaves is supported.

## Install

```
npm install @0xsequence/tee-verifier
```

## Usage

If you're verifying a Sequence enclave that responds with an `X-Attestation-Document` HTTP header, you can simply use `createAttestationVerifyingFetch` like so:

```typescript
import { createAttestationVerifyingFetch } from 'tee-verifier'

const verifyingFetch = createAttestationVerifyingFetch({ /* options */ })
try {
  const res = await verifyingFetch('https://waas.sequence.app/health')
  console.log('Success!')
} catch (error) {
  console.error('Verification unsuccessful:', error)
}
```

The following options are available:

- `rootCertFingerprint` - use a different root certificate fingerprint. By default, tee-verifier uses the AWS root certificate from https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html#validation-process
- `checkDate` - use a different Date to verify the certificates (current date by default)
- `expectedPCRs` - if provided, the PCRs from the attestation are compared against these
- `verifyRootOfTrust` - whether the certificate chain should be verified
- `verifySignature` - whether the attestation signature should be verified
- `verifyNonce` - whether the nonce in the attestation should be compared against the nonce sent in the request
- `verifyContentHash` - whether the hash in the attestation should be compared against the calculated hash of the request/response
- `logTiming` - whether the debug timing should be logged to the console

Otherwise, you can also verify it manually:

```typescript
const document = /* base64-encoded attestation returned by the NSM */
const attestation = SignedAttestation.fromDocument(document)
const isSignatureValid = await attestation.verifySignature()
const isRootOfTrustValid = await attestation.verifyRootOfTrust(new Date())
const isRootCertValid = (await attestation.rootCertFingerprint()) === expectedFingerprint
const isNonceValid = attestation.nonce === expectedNonce
const isUserDataValid = attestation.userData === expectedUserData
const isPCR0Valid = attestation.pcrs[0] === expectedPCR0
```
