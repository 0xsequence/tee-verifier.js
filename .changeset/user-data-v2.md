---
"@0xsequence/tee-verifier": minor
---

Support `Sequence/2` attestation user data, which also commits to the request's `Oms-Wallet-Signature` header, alongside `Sequence/1`.

- `verifyContentHash` now fails on any user data that is not `Sequence/1` or `Sequence/2`, instead of silently skipping the check for unknown prefixes.
- New `verifyUserData` export for verifying the user data hash of a request/response pair directly.
