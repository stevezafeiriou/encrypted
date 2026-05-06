import { getPublicKey } from '@noble/secp256k1'
import { ethers } from 'ethers'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import {
  decryptBlockchainPayload,
  deriveBlockchainPrivateKey,
  encryptBlockchainPayload,
  inspectBlockchainPackage,
  parseBlockchainProfile,
  type BlockchainPublicProfile,
  type BlockchainSession,
} from './blockchainCrypto'
import { stringifyJson } from './crypto'

const origin = 'https://encrypted.example'
const unlockMessage = 'Encrypted by Sapphire blockchain key v1'

function bytesToHex(bytes: Uint8Array) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')
}

async function createSession(privateKey: string): Promise<BlockchainSession> {
  const wallet = new ethers.Wallet(privateKey)
  const signature = await wallet.signMessage(unlockMessage)
  const encryptionPrivateKey = deriveBlockchainPrivateKey(
    wallet.address,
    signature,
    origin,
  )
  const encryptionPublicKey = bytesToHex(getPublicKey(encryptionPrivateKey, true))
  const unsignedProfile = {
    version: 'sapphire-blockchain-profile-v1',
    walletAddress: wallet.address,
    origin,
    encryptionPublicKey,
  } as const
  const publicProfile = {
    ...unsignedProfile,
    signature: await wallet.signMessage(stringifyJson(unsignedProfile)),
  } satisfies BlockchainPublicProfile

  return {
    address: wallet.address,
    shortAddress: `${wallet.address.slice(0, 6)}...${wallet.address.slice(-4)}`,
    signature,
    encryptionPrivateKey,
    encryptionPublicKey,
    publicProfile,
    networkName: 'Testnet',
  }
}

describe('blockchain crypto flow', () => {
  beforeEach(() => {
    vi.stubGlobal('window', { location: { origin } })
  })

  it('encrypts from one wallet profile and decrypts with the intended wallet', async () => {
    const sender = await createSession(
      '0x1000000000000000000000000000000000000000000000000000000000000001',
    )
    const recipient = await createSession(
      '0x2000000000000000000000000000000000000000000000000000000000000002',
    )

    const encrypted = await encryptBlockchainPayload({
      payload: {
        version: 'sapphire-payload-v1',
        kind: 'mixed',
        text: 'Private wallet note',
        attachments: [
          {
            id: 'file-1',
            name: 'note.txt',
            type: 'text/plain',
            size: 5,
            dataBase64: 'aGVsbG8=',
          },
        ],
      },
      recipientProfile: recipient.publicProfile,
      session: sender,
    })

    const inspection = await inspectBlockchainPackage(encrypted.packageText)
    const decrypted = await decryptBlockchainPayload(
      encrypted.packageText,
      recipient,
    )

    expect(inspection).toMatchObject({
      hashValid: true,
      profileValid: true,
      recipientWalletAddress: recipient.address,
      senderWalletAddress: sender.address,
      signatureValid: true,
    })
    expect(decrypted.senderAddress).toBe(sender.address)
    expect(decrypted.recipientAddress).toBe(recipient.address)
    expect(decrypted.payload.kind).toBe('mixed')
    expect(decrypted.payload.text).toBe('Private wallet note')
    expect(decrypted.payload.attachments[0]).toMatchObject({
      dataBase64: 'aGVsbG8=',
      name: 'note.txt',
    })
  })

  it('detects tampered blockchain package hashes before decrypting', async () => {
    const sender = await createSession(
      '0x3000000000000000000000000000000000000000000000000000000000000003',
    )
    const recipient = await createSession(
      '0x4000000000000000000000000000000000000000000000000000000000000004',
    )
    const encrypted = await encryptBlockchainPayload({
      payload: {
        version: 'sapphire-payload-v1',
        kind: 'text',
        text: 'Integrity protected',
        attachments: [],
      },
      recipientProfile: recipient.publicProfile,
      session: sender,
    })
    const tampered = JSON.parse(encrypted.packageText) as { ciphertext: string }
    tampered.ciphertext = `${tampered.ciphertext.slice(0, -1)}x`

    const packageText = stringifyJson(tampered)

    expect((await inspectBlockchainPackage(packageText)).hashValid).toBe(false)
    await expect(decryptBlockchainPayload(packageText, recipient)).rejects.toThrow(
      'integrity checks',
    )
  })

  it('rejects packages opened by the wrong wallet', async () => {
    const sender = await createSession(
      '0x5000000000000000000000000000000000000000000000000000000000000005',
    )
    const recipient = await createSession(
      '0x6000000000000000000000000000000000000000000000000000000000000006',
    )
    const wrongRecipient = await createSession(
      '0x7000000000000000000000000000000000000000000000000000000000000007',
    )
    const encrypted = await encryptBlockchainPayload({
      payload: {
        version: 'sapphire-payload-v1',
        kind: 'text',
        text: 'Wrong wallet fails',
        attachments: [],
      },
      recipientProfile: recipient.publicProfile,
      session: sender,
    })

    await expect(
      decryptBlockchainPayload(encrypted.packageText, wrongRecipient),
    ).rejects.toThrow('different connected wallet')
  })

  it('parses shareable recipient profiles', async () => {
    const recipient = await createSession(
      '0x8000000000000000000000000000000000000000000000000000000000000008',
    )

    expect(parseBlockchainProfile(stringifyJson(recipient.publicProfile))).toMatchObject({
      encryptionPublicKey: recipient.encryptionPublicKey,
      walletAddress: recipient.address,
    })
  })
})
