import { describe, expect, it } from 'vitest'

import {
  decryptMessage,
  decryptPayload,
  encryptMessage,
  encryptPayload,
  generateProtectedKeyPair,
  getPublicAddressFingerprint,
  inspectEncryptedPackage,
  parseProtectedPrivateKeyFile,
  stringifyJson,
} from './crypto'

describe('crypto flow', () => {
  it('encrypts from one key pair and decrypts with the intended recipient', async () => {
    const sender = await generateProtectedKeyPair('sender-password')
    const recipient = await generateProtectedKeyPair('recipient-password')

    const encrypted = await encryptMessage({
      plaintext: 'Private message',
      recipientAddress: recipient.publicAddress,
      senderKeyFile: sender.privateKeyFile,
      senderPassword: 'sender-password',
    })

    const decrypted = await decryptMessage({
      packageText: encrypted.packageText,
      recipientKeyFile: recipient.privateKeyFile,
      recipientPassword: 'recipient-password',
    })

    expect(decrypted.plaintext).toBe('Private message')
    expect(decrypted.senderAddress).toBe(sender.publicAddress)
    expect(decrypted.recipientAddress).toBe(recipient.publicAddress)
    expect(decrypted.signatureValid).toBe(true)
  })

  it('rejects wrong passwords and wrong recipient keys', async () => {
    const sender = await generateProtectedKeyPair('sender-password')
    const recipient = await generateProtectedKeyPair('recipient-password')
    const otherRecipient = await generateProtectedKeyPair('other-password')
    const encrypted = await encryptMessage({
      plaintext: 'Private message',
      recipientAddress: recipient.publicAddress,
      senderKeyFile: sender.privateKeyFile,
      senderPassword: 'sender-password',
    })

    await expect(
      decryptMessage({
        packageText: encrypted.packageText,
        recipientKeyFile: recipient.privateKeyFile,
        recipientPassword: 'wrong-password',
      }),
    ).rejects.toThrow('Could not unlock the private key')

    await expect(
      decryptMessage({
        packageText: encrypted.packageText,
        recipientKeyFile: otherRecipient.privateKeyFile,
        recipientPassword: 'other-password',
      }),
    ).rejects.toThrow('not the recipient')
  })

  it('detects tampered package hash and signature before decrypting', async () => {
    const sender = await generateProtectedKeyPair('sender-password')
    const recipient = await generateProtectedKeyPair('recipient-password')
    const encrypted = await encryptMessage({
      plaintext: 'Private message',
      recipientAddress: recipient.publicAddress,
      senderKeyFile: sender.privateKeyFile,
      senderPassword: 'sender-password',
    })
    const tampered = JSON.parse(encrypted.packageText) as {
      ciphertext: string
      messageHash: string
    }
    const replacement = tampered.ciphertext.endsWith('A') ? 'B' : 'A'
    tampered.ciphertext = `${tampered.ciphertext.slice(0, -1)}${replacement}`

    const inspection = inspectEncryptedPackage(stringifyJson(tampered))

    expect(inspection.hashValid).toBe(false)
    expect(inspection.signatureValid).toBe(true)

    await expect(
      decryptMessage({
        packageText: stringifyJson(tampered),
        recipientKeyFile: recipient.privateKeyFile,
        recipientPassword: 'recipient-password',
      }),
    ).rejects.toThrow('hash does not match')
  })

  it('detects tampered signatures', async () => {
    const sender = await generateProtectedKeyPair('sender-password')
    const recipient = await generateProtectedKeyPair('recipient-password')
    const encrypted = await encryptMessage({
      plaintext: 'Private message',
      recipientAddress: recipient.publicAddress,
      senderKeyFile: sender.privateKeyFile,
      senderPassword: 'sender-password',
    })
    const tampered = JSON.parse(encrypted.packageText) as { signature: string }
    const replacement = tampered.signature.endsWith('0') ? '1' : '0'
    tampered.signature = `${tampered.signature.slice(0, -1)}${replacement}`

    const inspection = inspectEncryptedPackage(stringifyJson(tampered))

    expect(inspection.hashValid).toBe(true)
    expect(inspection.signatureValid).toBe(false)
  })

  it('keeps legacy key versions compatible and parses legacy package versions', async () => {
    const sender = await generateProtectedKeyPair('sender-password')
    const recipient = await generateProtectedKeyPair('recipient-password')
    const legacySenderKey = {
      ...sender.privateKeyFile,
      version: 'saphire-key-v1',
    }
    const parsedLegacySenderKey = parseProtectedPrivateKeyFile(
      stringifyJson(legacySenderKey),
    )

    const legacyEncrypted = await encryptMessage({
      plaintext: 'Legacy compatible',
      recipientAddress: recipient.publicAddress,
      senderKeyFile: parsedLegacySenderKey,
      senderPassword: 'sender-password',
    })

    await expect(
      decryptMessage({
        packageText: legacyEncrypted.packageText,
        recipientKeyFile: recipient.privateKeyFile,
        recipientPassword: 'recipient-password',
      }),
    ).resolves.toMatchObject({ plaintext: 'Legacy compatible' })

    const legacyPackage = JSON.parse(legacyEncrypted.packageText) as {
      version: string
    }
    legacyPackage.version = 'saphire-message-v1'

    expect(inspectEncryptedPackage(stringifyJson(legacyPackage))).toMatchObject({
      hashValid: false,
      signatureValid: true,
      version: 'saphire-message-v1',
    })
  })

  it('creates stable public address fingerprints', async () => {
    const keyPair = await generateProtectedKeyPair('password')

    expect(getPublicAddressFingerprint(keyPair.publicAddress)).toMatch(
      /^[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}$/u,
    )
    expect(getPublicAddressFingerprint(keyPair.publicAddress)).toBe(
      getPublicAddressFingerprint(`0x${keyPair.publicAddress.toUpperCase()}`),
    )
  })

  it('encrypts and decrypts structured file payloads', async () => {
    const sender = await generateProtectedKeyPair('sender-password')
    const recipient = await generateProtectedKeyPair('recipient-password')
    const encrypted = await encryptPayload({
      payload: {
        version: 'sapphire-payload-v1',
        kind: 'files',
        attachments: [
          {
            id: 'file-1',
            name: 'hello.txt',
            type: 'text/plain',
            size: 5,
            dataBase64: 'aGVsbG8=',
          },
        ],
      },
      recipientAddress: recipient.publicAddress,
      senderKeyFile: sender.privateKeyFile,
      senderPassword: 'sender-password',
    })

    const decrypted = await decryptPayload({
      packageText: encrypted.packageText,
      recipientKeyFile: recipient.privateKeyFile,
      recipientPassword: 'recipient-password',
    })

    expect(decrypted.legacyText).toBe(false)
    expect(decrypted.payload.kind).toBe('files')
    expect(decrypted.payload.attachments[0]).toMatchObject({
      dataBase64: 'aGVsbG8=',
      name: 'hello.txt',
      type: 'text/plain',
    })
  })

  it('decrypts legacy text packages as payload text', async () => {
    const sender = await generateProtectedKeyPair('sender-password')
    const recipient = await generateProtectedKeyPair('recipient-password')
    const encrypted = await encryptMessage({
      plaintext: 'Legacy plaintext',
      recipientAddress: recipient.publicAddress,
      senderKeyFile: sender.privateKeyFile,
      senderPassword: 'sender-password',
    })

    const decrypted = await decryptPayload({
      packageText: encrypted.packageText,
      recipientKeyFile: recipient.privateKeyFile,
      recipientPassword: 'recipient-password',
    })

    expect(decrypted.legacyText).toBe(true)
    expect(decrypted.payload).toMatchObject({
      kind: 'text',
      text: 'Legacy plaintext',
      attachments: [],
    })
  })
})
