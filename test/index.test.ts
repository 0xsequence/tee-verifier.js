import { createHash } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { verifyUserData } from '../src/index.js'

const req = {
  method: 'POST',
  path: '/rpc/WaasAuthenticator/RegisterSession',
  reqBody: '{"intent":{"data":"..."}}',
  resBody: '{"session":{"id":"0x1234"}}',
}
const sig = '0xdeadbeef'

const userData = (version: number, preimage: string) =>
  `Sequence/${version}:${createHash('sha256').update(preimage).digest('base64')}`

const v1 = userData(1, `${req.method} ${req.path}\n${req.reqBody}\n${req.resBody}`)
const v2 = userData(2, `${req.method} ${req.path}\n${sig}\n${req.reqBody}\n${req.resBody}`)
const v2NoSig = userData(2, `${req.method} ${req.path}\n\n${req.reqBody}\n${req.resBody}`)

describe('verifyUserData', () => {
  it('accepts Sequence/1', async () => {
    await expect(verifyUserData(v1, req)).resolves.toBeUndefined()
    await expect(verifyUserData(v1, { ...req, resBody: 'tampered' })).rejects.toThrow('Invalid user data hash')
  })

  it('accepts Sequence/2 with the Oms-Wallet-Signature header', async () => {
    await expect(verifyUserData(v2, { ...req, headers: { 'Oms-Wallet-Signature': sig } })).resolves.toBeUndefined()
    // header lookup is case-insensitive and accepts every HeadersInit shape
    await expect(verifyUserData(v2, { ...req, headers: { 'oms-wallet-signature': sig } })).resolves.toBeUndefined()
    await expect(verifyUserData(v2, { ...req, headers: [['Oms-Wallet-Signature', sig]] })).resolves.toBeUndefined()
    await expect(
      verifyUserData(v2, { ...req, headers: new Headers({ 'Oms-Wallet-Signature': sig }) }),
    ).resolves.toBeUndefined()
  })

  it('accepts Sequence/2 without the header (empty signature line)', async () => {
    await expect(verifyUserData(v2NoSig, req)).resolves.toBeUndefined()
    await expect(verifyUserData(v2NoSig, { ...req, headers: {} })).resolves.toBeUndefined()
  })

  it('rejects Sequence/2 when the header value was changed', async () => {
    await expect(verifyUserData(v2, { ...req, headers: { 'Oms-Wallet-Signature': '0xbad' } })).rejects.toThrow(
      'Invalid user data hash',
    )
    await expect(verifyUserData(v2, req)).rejects.toThrow('Invalid user data hash')
    // v1 hash presented as v2 (or vice versa) must not verify
    await expect(verifyUserData(v1.replace('Sequence/1:', 'Sequence/2:'), req)).rejects.toThrow(
      'Invalid user data hash',
    )
  })

  it('rejects unknown versions and malformed user data', async () => {
    await expect(verifyUserData(v1.replace('Sequence/1:', 'Sequence/3:'), req)).rejects.toThrow(
      'Unsupported user data version: Sequence/3',
    )
    await expect(verifyUserData(v1.replace('Sequence/1:', 'Sequence/01:'), req)).rejects.toThrow('Unsupported')
    await expect(verifyUserData('', req)).rejects.toThrow('Invalid user data')
    await expect(verifyUserData('Other/1:abc', req)).rejects.toThrow('Invalid user data')
    await expect(verifyUserData('Sequence/1', req)).rejects.toThrow('Invalid user data')
  })
})
