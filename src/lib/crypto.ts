import {
  etc,
  getPublicKey,
  getSharedSecret,
  signAsync,
  utils,
  verify,
  verifyAsync,
} from '@noble/secp256k1'
import { sha256 } from '@noble/hashes/sha2.js'

const KEY_VERSION = 'sapphire-labs-key-v1'
const LEGACY_KEY_VERSION = 'saphire-key-v1'
const MESSAGE_VERSION = 'sapphire-labs-message-v1'
const LEGACY_MESSAGE_VERSION = 'saphire-message-v1'
const KEY_DERIVE_ITERATIONS = 310_000
const AES_KEY_LENGTH = 256
const AES_GCM_IV_LENGTH = 12
const PBKDF2_SALT_LENGTH = 16
const HKDF_SALT_LENGTH = 32
const PRIVATE_KEY_HEX_LENGTH = 64

const encoder = new TextEncoder()
const decoder = new TextDecoder()

export interface ProtectedPrivateKeyFile {
  version: typeof KEY_VERSION
  publicAddress: string
  kdf: {
    name: 'PBKDF2-SHA256'
    iterations: number
    salt: string
  }
  cipher: {
    name: 'AES-GCM'
    iv: string
    ciphertext: string
  }
}

export interface EncryptedMessagePackage {
  version: typeof MESSAGE_VERSION | typeof LEGACY_MESSAGE_VERSION
  recipientAddress: string
  senderAddress: string
  ephemeralPublicKey: string
  salt: string
  iv: string
  ciphertext: string
  messageHash: string
  signature: string
}

export interface GeneratedKeyPair {
  publicAddress: string
  privateKeyFile: ProtectedPrivateKeyFile
  privateKeyFileName: string
}

export interface EncryptionResult {
  packageText: string
  encryptedPackage: EncryptedMessagePackage
  messageHash: string
}

export interface DecryptionResult {
  plaintext: string
  senderAddress: string
  recipientAddress: string
  messageHash: string
  signatureValid: boolean
}

export interface EncryptedAttachment {
  id: string
  name: string
  type: string
  size: number
  dataBase64: string
}

export interface EncryptedPlaintextPayload {
  version: 'sapphire-payload-v1'
  kind: 'text' | 'files' | 'voice' | 'mixed'
  text?: string
  attachments: EncryptedAttachment[]
}

export interface DecryptedPayloadResult extends DecryptionResult {
  payload: EncryptedPlaintextPayload
  legacyText: boolean
}

export interface PackageInspection {
  version: EncryptedMessagePackage['version']
  messageHash: string
  senderAddress: string
  senderFingerprint: string
  recipientAddress: string
  recipientFingerprint: string
  hashValid: boolean
  signatureValid: boolean
}

interface MessagePayload {
  version: typeof MESSAGE_VERSION | typeof LEGACY_MESSAGE_VERSION
  recipientAddress: string
  senderAddress: string
  ephemeralPublicKey: string
  salt: string
  iv: string
  ciphertext: string
}

export function isProtectedPrivateKeyFile(
  value: unknown,
): value is ProtectedPrivateKeyFile {
  if (!isRecord(value)) {
    return false
  }

  return (
    (value.version === KEY_VERSION || value.version === LEGACY_KEY_VERSION) &&
    typeof value.publicAddress === 'string' &&
    isRecord(value.kdf) &&
    value.kdf.name === 'PBKDF2-SHA256' &&
    typeof value.kdf.iterations === 'number' &&
    typeof value.kdf.salt === 'string' &&
    isRecord(value.cipher) &&
    value.cipher.name === 'AES-GCM' &&
    typeof value.cipher.iv === 'string' &&
    typeof value.cipher.ciphertext === 'string'
  )
}

export function parseProtectedPrivateKeyFile(
  text: string,
): ProtectedPrivateKeyFile {
  const parsed = parseJson(text, 'private key file')

  if (!isProtectedPrivateKeyFile(parsed)) {
    throw new Error('This is not a valid SapphireLabs private key file.')
  }

  assertPublicAddress(parsed.publicAddress, 'private key file public address')
  decodeBase64Url(parsed.kdf.salt, PBKDF2_SALT_LENGTH, 'key salt')
  decodeBase64Url(parsed.cipher.iv, AES_GCM_IV_LENGTH, 'key iv')
  decodeBase64Url(parsed.cipher.ciphertext, undefined, 'encrypted private key')

  return parsed
}

export function parseEncryptedMessagePackage(
  text: string,
): EncryptedMessagePackage {
  const parsed = parseJson(text, 'encrypted message package')

  if (!isRecord(parsed)) {
    throw new Error('This is not a valid encrypted message package.')
  }

  const encryptedPackage = {
    version: parsed.version,
    recipientAddress: parsed.recipientAddress,
    senderAddress: parsed.senderAddress,
    ephemeralPublicKey: parsed.ephemeralPublicKey,
    salt: parsed.salt,
    iv: parsed.iv,
    ciphertext: parsed.ciphertext,
    messageHash: parsed.messageHash,
    signature: parsed.signature,
  }

  if (!isEncryptedMessagePackage(encryptedPackage)) {
    throw new Error('This is not a valid encrypted message package.')
  }

  validateEncryptedPackage(encryptedPackage)

  return encryptedPackage
}

export function normalizePublicAddress(value: string): string {
  const address = normalizeAddress(value)
  assertPublicAddress(address, 'public address')
  return address
}

export function getPublicAddressFingerprint(address: string): string {
  const normalizedAddress = normalizePublicAddress(address)
  const fingerprint = bytesToHex(sha256(encoder.encode(normalizedAddress)))
    .slice(0, 12)
    .toUpperCase()

  return fingerprint.match(/.{1,4}/gu)?.join('-') ?? fingerprint
}

export function inspectEncryptedPackage(packageText: string): PackageInspection {
  const encryptedPackage = parseEncryptedMessagePackage(packageText)
  const payload = payloadFromPackage(encryptedPackage)
  const expectedHash = hashPayload(payload)
  const hashValid = expectedHash === encryptedPackage.messageHash
  const signatureValid = verify(
    hexToBytes(encryptedPackage.signature),
    hexToBytes(encryptedPackage.messageHash),
    hexToBytes(encryptedPackage.senderAddress),
    { prehash: false },
  )

  return {
    version: encryptedPackage.version,
    messageHash: encryptedPackage.messageHash,
    senderAddress: encryptedPackage.senderAddress,
    senderFingerprint: getPublicAddressFingerprint(encryptedPackage.senderAddress),
    recipientAddress: encryptedPackage.recipientAddress,
    recipientFingerprint: getPublicAddressFingerprint(encryptedPackage.recipientAddress),
    hashValid,
    signatureValid,
  }
}

export async function generateProtectedKeyPair(
  password: string,
): Promise<GeneratedKeyPair> {
  assertPassword(password)

  const privateKey = utils.randomSecretKey()
  const publicAddress = bytesToHex(getPublicKey(privateKey, true))
  const salt = crypto.getRandomValues(new Uint8Array(PBKDF2_SALT_LENGTH))
  const iv = crypto.getRandomValues(new Uint8Array(AES_GCM_IV_LENGTH))
  const aesKey = await derivePasswordKey(password, salt)
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: copyBytes(iv),
        additionalData: encoder.encode(publicAddress),
      },
      aesKey,
      copyBytes(privateKey),
    ),
  )

  const privateKeyFile = {
    version: KEY_VERSION,
    publicAddress,
    kdf: {
      name: 'PBKDF2-SHA256',
      iterations: KEY_DERIVE_ITERATIONS,
      salt: encodeBase64Url(salt),
    },
    cipher: {
      name: 'AES-GCM',
      iv: encodeBase64Url(iv),
      ciphertext: encodeBase64Url(ciphertext),
    },
  } satisfies ProtectedPrivateKeyFile

  return {
    publicAddress,
    privateKeyFile,
    privateKeyFileName: `sapphire-labs-${publicAddress}.json`,
  }
}

export async function validatePrivateKeyPassword(
  keyFile: ProtectedPrivateKeyFile,
  password: string,
): Promise<void> {
  const privateKey = await unlockPrivateKey(keyFile, password)
  const publicAddress = bytesToHex(getPublicKey(privateKey, true))

  if (publicAddress !== keyFile.publicAddress) {
    throw new Error('The private key file does not match its public address.')
  }
}

export async function encryptMessage(params: {
  plaintext: string
  recipientAddress: string
  senderKeyFile: ProtectedPrivateKeyFile
  senderPassword: string
}): Promise<EncryptionResult> {
  const plaintext = params.plaintext
  const recipientAddress = normalizeAddress(params.recipientAddress)

  if (!plaintext.trim()) {
    throw new Error('Enter a message to encrypt.')
  }

  assertPublicAddress(recipientAddress, 'recipient address')

  const senderPrivateKey = await unlockPrivateKey(
    params.senderKeyFile,
    params.senderPassword,
  )
  const senderAddress = bytesToHex(getPublicKey(senderPrivateKey, true))

  if (senderAddress !== params.senderKeyFile.publicAddress) {
    throw new Error('The private key file does not match its public address.')
  }

  const ephemeralPrivateKey = utils.randomSecretKey()
  const ephemeralPublicKey = bytesToHex(getPublicKey(ephemeralPrivateKey, true))
  const sharedSecret = getSharedSecret(
    ephemeralPrivateKey,
    hexToBytes(recipientAddress),
    true,
  )
  const salt = crypto.getRandomValues(new Uint8Array(HKDF_SALT_LENGTH))
  const iv = crypto.getRandomValues(new Uint8Array(AES_GCM_IV_LENGTH))
  const aesKey = await deriveMessageKey(sharedSecret, salt)
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: copyBytes(iv),
        additionalData: encoder.encode(`${MESSAGE_VERSION}:${recipientAddress}`),
      },
      aesKey,
      encoder.encode(plaintext),
    ),
  )

  const payload = {
    version: MESSAGE_VERSION,
    recipientAddress,
    senderAddress,
    ephemeralPublicKey,
    salt: encodeBase64Url(salt),
    iv: encodeBase64Url(iv),
    ciphertext: encodeBase64Url(ciphertext),
  } satisfies MessagePayload
  const messageHash = hashPayload(payload)
  const signature = bytesToHex(
    await signAsync(hexToBytes(messageHash), senderPrivateKey, {
      extraEntropy: true,
      prehash: false,
    }),
  )
  const encryptedPackage = {
    ...payload,
    messageHash,
    signature,
  } satisfies EncryptedMessagePackage

  return {
    encryptedPackage,
    messageHash,
    packageText: stringifyJson(encryptedPackage),
  }
}

export async function encryptPayload(params: {
  payload: EncryptedPlaintextPayload
  recipientAddress: string
  senderKeyFile: ProtectedPrivateKeyFile
  senderPassword: string
}): Promise<EncryptionResult> {
  validatePlaintextPayload(params.payload)

  return encryptMessage({
    plaintext: stringifyJson(params.payload),
    recipientAddress: params.recipientAddress,
    senderKeyFile: params.senderKeyFile,
    senderPassword: params.senderPassword,
  })
}

export async function decryptMessage(params: {
  packageText: string
  recipientKeyFile: ProtectedPrivateKeyFile
  recipientPassword: string
}): Promise<DecryptionResult> {
  const encryptedPackage = parseEncryptedMessagePackage(params.packageText)
  const recipientPrivateKey = await unlockPrivateKey(
    params.recipientKeyFile,
    params.recipientPassword,
  )
  const recipientAddress = bytesToHex(getPublicKey(recipientPrivateKey, true))

  if (recipientAddress !== params.recipientKeyFile.publicAddress) {
    throw new Error('The private key file does not match its public address.')
  }

  if (recipientAddress !== encryptedPackage.recipientAddress) {
    throw new Error('This private key is not the recipient for this package.')
  }

  const payload = payloadFromPackage(encryptedPackage)
  const expectedHash = hashPayload(payload)

  if (expectedHash !== encryptedPackage.messageHash) {
    throw new Error('The encrypted package hash does not match its contents.')
  }

  const signatureValid = await verifyAsync(
    hexToBytes(encryptedPackage.signature),
    hexToBytes(encryptedPackage.messageHash),
    hexToBytes(encryptedPackage.senderAddress),
    { prehash: false },
  )

  if (!signatureValid) {
    throw new Error('The package signature is invalid or the package was tampered with.')
  }

  const sharedSecret = getSharedSecret(
    recipientPrivateKey,
    hexToBytes(encryptedPackage.ephemeralPublicKey),
    true,
  )
  const salt = decodeBase64Url(encryptedPackage.salt, HKDF_SALT_LENGTH, 'message salt')
  const iv = decodeBase64Url(encryptedPackage.iv, AES_GCM_IV_LENGTH, 'message iv')
  const ciphertext = decodeBase64Url(
    encryptedPackage.ciphertext,
    undefined,
    'message ciphertext',
  )
  const aesKey = await deriveMessageKey(sharedSecret, salt)
  const plaintextBytes = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: copyBytes(iv),
      additionalData: encoder.encode(
        `${getPackageCryptoContext(encryptedPackage.version)}:${encryptedPackage.recipientAddress}`,
      ),
    },
    aesKey,
    copyBytes(ciphertext),
  )

  return {
    plaintext: decoder.decode(plaintextBytes),
    senderAddress: encryptedPackage.senderAddress,
    recipientAddress: encryptedPackage.recipientAddress,
    messageHash: encryptedPackage.messageHash,
    signatureValid,
  }
}

export async function decryptPayload(params: {
  packageText: string
  recipientKeyFile: ProtectedPrivateKeyFile
  recipientPassword: string
}): Promise<DecryptedPayloadResult> {
  const decrypted = await decryptMessage(params)
  const payload = parsePlaintextPayload(decrypted.plaintext)

  return {
    ...decrypted,
    payload,
    legacyText: !isStructuredPlaintextPayload(decrypted.plaintext),
  }
}

export async function readTextFile(file: File): Promise<string> {
  return file.text()
}

export function stringifyJson(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`
}

function isEncryptedMessagePackage(value: unknown): value is EncryptedMessagePackage {
  if (!isRecord(value)) {
    return false
  }

  return (
    (value.version === MESSAGE_VERSION ||
      value.version === LEGACY_MESSAGE_VERSION) &&
    typeof value.recipientAddress === 'string' &&
    typeof value.senderAddress === 'string' &&
    typeof value.ephemeralPublicKey === 'string' &&
    typeof value.salt === 'string' &&
    typeof value.iv === 'string' &&
    typeof value.ciphertext === 'string' &&
    typeof value.messageHash === 'string' &&
    typeof value.signature === 'string'
  )
}

function validateEncryptedPackage(encryptedPackage: EncryptedMessagePackage) {
  assertPublicAddress(encryptedPackage.recipientAddress, 'recipient address')
  assertPublicAddress(encryptedPackage.senderAddress, 'sender address')
  assertPublicAddress(encryptedPackage.ephemeralPublicKey, 'ephemeral public key')
  decodeBase64Url(encryptedPackage.salt, HKDF_SALT_LENGTH, 'message salt')
  decodeBase64Url(encryptedPackage.iv, AES_GCM_IV_LENGTH, 'message iv')
  decodeBase64Url(encryptedPackage.ciphertext, undefined, 'message ciphertext')

  if (!/^[0-9a-f]{64}$/u.test(encryptedPackage.messageHash)) {
    throw new Error('The message hash is not valid.')
  }

  if (!/^[0-9a-f]{128}$/u.test(encryptedPackage.signature)) {
    throw new Error('The package signature is not valid.')
  }
}

function getPackageCryptoContext(
  version: EncryptedMessagePackage['version'] | MessagePayload['version'],
) {
  return version === LEGACY_MESSAGE_VERSION ? LEGACY_MESSAGE_VERSION : MESSAGE_VERSION
}

async function unlockPrivateKey(
  keyFile: ProtectedPrivateKeyFile,
  password: string,
): Promise<Uint8Array> {
  assertPassword(password)
  assertPublicAddress(keyFile.publicAddress, 'private key file public address')

  const salt = decodeBase64Url(keyFile.kdf.salt, PBKDF2_SALT_LENGTH, 'key salt')
  const iv = decodeBase64Url(keyFile.cipher.iv, AES_GCM_IV_LENGTH, 'key iv')
  const ciphertext = decodeBase64Url(
    keyFile.cipher.ciphertext,
    undefined,
    'encrypted private key',
  )
  const aesKey = await derivePasswordKey(password, salt, keyFile.kdf.iterations)

  try {
    const privateKey = new Uint8Array(
      await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: copyBytes(iv),
          additionalData: encoder.encode(keyFile.publicAddress),
        },
        aesKey,
        copyBytes(ciphertext),
      ),
    )

    if (privateKey.byteLength !== PRIVATE_KEY_HEX_LENGTH / 2) {
      throw new Error('The decrypted private key has an invalid length.')
    }

    if (!utils.isValidSecretKey(privateKey)) {
      throw new Error('The decrypted private key is not valid.')
    }

    return privateKey
  } catch (error) {
    if (error instanceof Error && error.message.includes('private key')) {
      throw error
    }

    throw new Error('Could not unlock the private key. Check the file and password.', {
      cause: error,
    })
  }
}

async function derivePasswordKey(
  password: string,
  salt: Uint8Array,
  iterations = KEY_DERIVE_ITERATIONS,
): Promise<CryptoKey> {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveKey'],
  )

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      hash: 'SHA-256',
      iterations,
      salt: copyBytes(salt),
    },
    keyMaterial,
    {
      name: 'AES-GCM',
      length: AES_KEY_LENGTH,
    },
    false,
    ['encrypt', 'decrypt'],
  )
}

async function deriveMessageKey(
  sharedSecret: Uint8Array,
  salt: Uint8Array,
): Promise<CryptoKey> {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    copyBytes(sharedSecret),
    'HKDF',
    false,
    ['deriveKey'],
  )

  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: copyBytes(salt),
      info: encoder.encode(getPackageCryptoContext(MESSAGE_VERSION)),
    },
    keyMaterial,
    {
      name: 'AES-GCM',
      length: AES_KEY_LENGTH,
    },
    false,
    ['encrypt', 'decrypt'],
  )
}

function payloadFromPackage(encryptedPackage: EncryptedMessagePackage): MessagePayload {
  return {
    version: encryptedPackage.version,
    recipientAddress: encryptedPackage.recipientAddress,
    senderAddress: encryptedPackage.senderAddress,
    ephemeralPublicKey: encryptedPackage.ephemeralPublicKey,
    salt: encryptedPackage.salt,
    iv: encryptedPackage.iv,
    ciphertext: encryptedPackage.ciphertext,
  }
}

function parsePlaintextPayload(plaintext: string): EncryptedPlaintextPayload {
  try {
    const parsed = JSON.parse(plaintext) as unknown

    if (isPlaintextPayload(parsed)) {
      return parsed
    }
  } catch {
    // Legacy text-only messages are intentionally supported.
  }

  return {
    version: 'sapphire-payload-v1',
    kind: 'text',
    text: plaintext,
    attachments: [],
  }
}

function isStructuredPlaintextPayload(plaintext: string): boolean {
  try {
    return isPlaintextPayload(JSON.parse(plaintext) as unknown)
  } catch {
    return false
  }
}

function validatePlaintextPayload(payload: EncryptedPlaintextPayload) {
  if (!isPlaintextPayload(payload)) {
    throw new Error('This is not a valid encrypted payload.')
  }

  const hasText = Boolean(payload.text?.trim())
  const hasAttachments = payload.attachments.length > 0

  if (!hasText && !hasAttachments) {
    throw new Error('Enter text or attach a file to encrypt.')
  }
}

function isPlaintextPayload(value: unknown): value is EncryptedPlaintextPayload {
  if (!isRecord(value)) {
    return false
  }

  if (
    value.version !== 'sapphire-payload-v1' ||
    !['text', 'files', 'voice', 'mixed'].includes(String(value.kind)) ||
    !Array.isArray(value.attachments)
  ) {
    return false
  }

  if (value.text !== undefined && typeof value.text !== 'string') {
    return false
  }

  return value.attachments.every((attachment) => {
    if (!isRecord(attachment)) {
      return false
    }

    return (
      typeof attachment.id === 'string' &&
      typeof attachment.name === 'string' &&
      typeof attachment.type === 'string' &&
      typeof attachment.size === 'number' &&
      typeof attachment.dataBase64 === 'string'
    )
  })
}

function hashPayload(payload: MessagePayload): string {
  return bytesToHex(sha256(encoder.encode(serializePayload(payload))))
}

function serializePayload(payload: MessagePayload): string {
  return JSON.stringify({
    version: payload.version,
    recipientAddress: payload.recipientAddress,
    senderAddress: payload.senderAddress,
    ephemeralPublicKey: payload.ephemeralPublicKey,
    salt: payload.salt,
    iv: payload.iv,
    ciphertext: payload.ciphertext,
  })
}

function normalizeAddress(value: string): string {
  return value.trim().toLowerCase().replace(/^0x/u, '')
}

function assertPublicAddress(value: string, label: string): void {
  const address = normalizeAddress(value)

  if (!/^(02|03)[0-9a-f]{64}$/u.test(address)) {
    throw new Error(`The ${label} must be a compressed secp256k1 public key.`)
  }

  if (!utils.isValidPublicKey(hexToBytes(address), true)) {
    throw new Error(`The ${label} is not a valid secp256k1 public key.`)
  }
}

function assertPassword(password: string): void {
  if (!password) {
    throw new Error('Enter the private key password.')
  }
}

function parseJson(text: string, label: string): unknown {
  try {
    return JSON.parse(text)
  } catch {
    throw new Error(`The ${label} is not valid JSON.`)
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null
}

function bytesToHex(bytes: Uint8Array): string {
  return etc.bytesToHex(bytes)
}

function hexToBytes(hex: string): Uint8Array {
  const normalized = normalizeAddress(hex)

  if (!/^(?:[0-9a-f]{2})+$/u.test(normalized)) {
    throw new Error('Invalid hex value.')
  }

  return etc.hexToBytes(normalized)
}

function copyBytes(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  const copy = new Uint8Array(bytes.byteLength)
  copy.set(bytes)
  return copy
}

function encodeBase64Url(bytes: Uint8Array): string {
  let binary = ''

  for (const byte of bytes) {
    binary += String.fromCharCode(byte)
  }

  return btoa(binary).replace(/\+/gu, '-').replace(/\//gu, '_').replace(/=+$/u, '')
}

function decodeBase64Url(
  value: string,
  expectedLength: number | undefined,
  label: string,
): Uint8Array {
  try {
    const base64 = value.replace(/-/gu, '+').replace(/_/gu, '/')
    const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), '=')
    const binary = atob(padded)
    const bytes = new Uint8Array(binary.length)

    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index)
    }

    if (expectedLength !== undefined && bytes.byteLength !== expectedLength) {
      throw new Error('Invalid length.')
    }

    return bytes
  } catch {
    throw new Error(`The ${label} is not valid.`)
  }
}
