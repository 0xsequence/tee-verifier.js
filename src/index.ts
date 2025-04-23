import { decode as cborDecode, encode as cborEncode } from 'cbor2'
import { Certificate, CertificateChainValidationEngine } from 'pkijs'

export interface AttestationVerifyOptions {
  rootCertFingerprint?: string
  checkDate?: Date

  expectedPCRs?: Map<number, string | string[]>
  verifyRootOfTrust?: boolean
  verifySignature?: boolean
  verifyNonce?: boolean
  verifyContentHash?: boolean

  fetch?: typeof window.fetch
  logTiming?: boolean
}

export function createAttestationVerifyingFetch(
  options: AttestationVerifyOptions = {
    // From https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html#validation-process
    rootCertFingerprint: '641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b',
    verifyRootOfTrust: true,
    verifySignature: true,
    verifyNonce: true,
    verifyContentHash: true,
  },
): typeof window.fetch {
  return async (input: RequestInfo | URL, init: RequestInit = {}) => {
    let expectedNonce = ''
    if (options.verifyNonce) {
      const nonceArray = new Uint8Array(12)
      crypto.getRandomValues(nonceArray)
      expectedNonce = btoa(String.fromCharCode.apply(null, [...nonceArray]))
      init.headers = {
        ...init.headers,
        'x-attestation-nonce': expectedNonce,
      }
    }

    const fetch = options.fetch ?? window.fetch
    const res = await fetch(input, init)
    const attestationDoc = res.headers.get('x-attestation-document')
    if (!attestationDoc) {
      console.warn('No attestation document found in response')
      return res
    }

    const startTime = performance.now()

    const att = SignedAttestation.fromDocument(attestationDoc)

    if (options.verifyNonce && att.nonce !== expectedNonce) {
      throw new Error('Invalid nonce')
    }
    if (options.expectedPCRs) {
      for (const [pcr, expectedHash] of options.expectedPCRs.entries()) {
        const actualHash = att.pcrs.get(pcr)
        if (!actualHash) {
          throw new Error(`Missing PCR${pcr}`)
        }
        if (Array.isArray(expectedHash)) {
          if (!expectedHash.includes(actualHash)) {
            throw new Error(`Invalid PCR${pcr}: ${actualHash}`)
          }
        } else if (actualHash !== expectedHash) {
          throw new Error(`Invalid PCR${pcr}: ${actualHash}`)
        }
      }
    }
    if (options.verifyRootOfTrust) {
      const valid = await att.verifyRootOfTrust(options.checkDate)
      if (!valid) {
        throw new Error('Invalid root of trust')
      }
      const actualFingerprint = await att.rootCertFingerprint()
      if (options.rootCertFingerprint && actualFingerprint !== options.rootCertFingerprint) {
        throw new Error(`Invalid root certificate fingerprint: ${actualFingerprint}`)
      }
    }
    if (options.verifySignature) {
      const valid = await att.verifySignature()
      if (!valid) {
        throw new Error('Invalid signature')
      }
    }
    if (options.verifyContentHash && att.userData.startsWith('Sequence/1:')) {
      const attHash = att.userData.split(':')[1]
      const method = init.method ?? 'GET'

      let url: URL
      if (input instanceof URL) {
        url = input
      } else {
        const inputUrl = typeof input === 'string' ? input : input.url
        url = new URL(inputUrl, window.location.origin)
      }
      const path = url.pathname

      const reqBody = init.body ?? ''
      const resBody = await res.text()

      const buffer = new TextEncoder().encode(`${method} ${path}\n${reqBody}\n${resBody}`)
      const expectedHash = await crypto.subtle.digest('SHA-256', buffer)
      const expectedHashHex = Array.from(new Uint8Array(expectedHash))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('')

      if (attHash !== expectedHashHex) {
        throw new Error('Invalid user data hash')
      }
    }

    if (options.logTiming) {
      const endTime = performance.now()
      const timeTaken = endTime - startTime
      console.log(`Attestation verification took ${timeTaken.toFixed(2)}ms`)
    }

    return res
  }
}

export class Attestation {
  readonly cert: Certificate
  readonly intermediates: Certificate[]
  readonly rootCert: Certificate
  readonly pcrs: Map<number, string>

  constructor(private readonly raw: RawAttestation) {
    if (!raw.cabundle[0]) {
      throw new Error('Invalid attestation CA bundle')
    }

    this.cert = Certificate.fromBER(raw.certificate)
    this.rootCert = Certificate.fromBER(raw.cabundle[0])
    this.intermediates = raw.cabundle.slice(1).map((cert) => Certificate.fromBER(cert))
    this.pcrs = new Map(
      Array.from(raw.pcrs.entries()).map(([k, v]) => [
        Number(k),
        Array.from(new Uint8Array(v))
          .map((b) => b.toString(16).padStart(2, '0'))
          .join(''),
      ]),
    )
  }

  get nonce() {
    return new TextDecoder().decode(this.raw.nonce)
  }

  get userData() {
    return new TextDecoder().decode(this.raw.user_data)
  }

  async verifyRootOfTrust(checkDate?: Date) {
    const chainEngine = new CertificateChainValidationEngine({
      certs: [...this.intermediates, this.cert],
      trustedCerts: [this.rootCert],
      checkDate,
    })
    const chain = await chainEngine.verify()
    return chain.result
  }

  async rootCertFingerprint() {
    const hashBuffer = await window.crypto.subtle.digest('SHA-256', this.raw.cabundle[0]!)
    return Array.from(new Uint8Array(hashBuffer))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')
  }
}

type COSESign1 = Array<Uint8Array>

export class SignedAttestation extends Attestation {
  readonly sign1: COSESign1

  constructor(raw: RawAttestation, sign1: COSESign1) {
    if (sign1.length !== 4) {
      throw new Error('Invalid COSE Sign1')
    }

    super(raw)
    this.sign1 = sign1
  }

  static fromDocument(document: string) {
    const attestationBytes = base64ToBytes(document)
    const coseSign1: Array<any> = cborDecode(attestationBytes)
    if (coseSign1.length !== 4) {
      throw new Error('Invalid COSE Sign1')
    }
    const payload = cborDecode(coseSign1[2]) as RawAttestation
    return new SignedAttestation(payload, coseSign1)
  }

  async verifySignature() {
    const sigStructure = ['Signature1', this.sign1[0]!, new Uint8Array(), this.sign1[2]!]
    const sigStructureBytes = cborEncode(sigStructure)
    const sig = this.sign1[3]!
    const pubKey = await this.cert.getPublicKey()
    const verified = await crypto.subtle.verify(
      {
        name: 'ECDSA',
        hash: 'SHA-384',
      },
      pubKey,
      sig,
      sigStructureBytes,
    )
    return verified
  }
}

type RawAttestation = {
  cabundle: Uint8Array[]
  certificate: Uint8Array
  digest: string
  module_id: string
  nonce: Uint8Array
  pcrs: Map<number, Uint8Array>
  public_key: Uint8Array
  timestamp: number
  user_data: Uint8Array
}

function base64ToBytes(base64: string) {
  const binString = atob(base64)
  return Uint8Array.from(binString, (m) => m.codePointAt(0)!)
}
