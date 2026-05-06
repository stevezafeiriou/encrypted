import { sha256 } from '@noble/hashes/sha2.js'
import {
  getPublicKey,
  getSharedSecret,
  signAsync,
  utils,
  verifyAsync,
} from '@noble/secp256k1'
import { ethers } from 'ethers'

import {
  stringifyJson,
  type DecryptedPayloadResult,
  type EncryptedMessagePackage,
  type EncryptedPlaintextPayload,
  type EncryptionResult,
} from './crypto'

const BLOCKCHAIN_MESSAGE_VERSION = 'sapphire-blockchain-message-v1'
const BLOCKCHAIN_PROFILE_VERSION = 'sapphire-blockchain-profile-v1'
const BLOCKCHAIN_PAYLOAD_VERSION = 'sapphire-payload-v1'
const SIGNATURE_MESSAGE = 'Encrypted by Sapphire blockchain key v1'
const AES_GCM_IV_LENGTH = 12
const HKDF_SALT_LENGTH = 32

const encoder = new TextEncoder()
const decoder = new TextDecoder()

export interface BlockchainPublicProfile {
  version: typeof BLOCKCHAIN_PROFILE_VERSION
  walletAddress: string
  origin: string
  encryptionPublicKey: string
  signature: string
}

export interface BlockchainMessagePackage {
  version: typeof BLOCKCHAIN_MESSAGE_VERSION
  senderWalletAddress: string
  recipientWalletAddress: string
  origin: string
  senderEncryptionPublicKey: string
  recipientEncryptionPublicKey: string
  senderProfile: BlockchainPublicProfile
  ephemeralPublicKey: string
  salt: string
  iv: string
  ciphertext: string
  messageHash: string
  signature: string
  createdAt: string
}

export interface BlockchainSession {
  address: string
  shortAddress: string
  signature: string
  encryptionPrivateKey: Uint8Array
  encryptionPublicKey: string
  publicProfile: BlockchainPublicProfile
  networkName: string
}

export interface BlockchainInspection {
  version: typeof BLOCKCHAIN_MESSAGE_VERSION
  senderWalletAddress: string
  recipientWalletAddress: string
  origin: string
  messageHash: string
  hashValid: boolean
  profileValid: boolean
  signatureValid: boolean
  createdAt: string
}

export interface BlockchainDecryptionResult extends DecryptedPayloadResult {
  walletAddress: string
  origin: string
}

declare global {
  interface Window {
    ethereum?: ethers.Eip1193Provider
  }
}

export async function connectWallet(): Promise<BlockchainSession> {
  if (!window.ethereum) {
    throw new Error('MetaMask is not available in this browser.')
  }

  const provider = new ethers.BrowserProvider(window.ethereum)
  await provider.send('eth_requestAccounts', [])
  const signer = await provider.getSigner()
  const address = await signer.getAddress()
  const network = await provider.getNetwork()
  const signature = await signer.signMessage(SIGNATURE_MESSAGE)
  const origin = window.location.origin
  const encryptionPrivateKey = deriveBlockchainPrivateKey(address, signature, origin)
  const encryptionPublicKey = bytesToHex(getPublicKey(encryptionPrivateKey, true))
  const unsignedProfile = {
    version: BLOCKCHAIN_PROFILE_VERSION,
    walletAddress: address,
    origin,
    encryptionPublicKey,
  } as const
  const profileSignature = await signer.signMessage(stringifyJson(unsignedProfile))
  const publicProfile = {
    ...unsignedProfile,
    signature: profileSignature,
  } satisfies BlockchainPublicProfile

  return {
    address,
    shortAddress: shortenEthAddress(address),
    signature,
    encryptionPrivateKey,
    encryptionPublicKey,
    publicProfile,
    networkName: network.name === 'unknown' ? `Chain ${network.chainId}` : network.name,
  }
}

export function deriveBlockchainPrivateKey(
  address: string,
  signature: string,
  origin: string,
): Uint8Array {
  let counter = 0

  while (counter < 8) {
    const material = `${BLOCKCHAIN_MESSAGE_VERSION}:${origin}:${address.toLowerCase()}:${signature}:${counter}`
    const candidate = sha256(encoder.encode(material))

    if (utils.isValidSecretKey(candidate)) {
      return candidate
    }

    counter += 1
  }

  throw new Error('Could not derive a valid wallet encryption key.')
}

export async function encryptBlockchainPayload(
  params: {
    payload: EncryptedPlaintextPayload
    recipientProfile: BlockchainPublicProfile
    session: BlockchainSession
  },
): Promise<EncryptionResult> {
  validatePayload(params.payload)
  assertValidProfile(params.recipientProfile)

  if (params.recipientProfile.origin !== window.location.origin) {
    throw new Error('This recipient profile was created for a different site origin.')
  }

  const ephemeralPrivateKey = utils.randomSecretKey()
  const ephemeralPublicKey = bytesToHex(getPublicKey(ephemeralPrivateKey, true))
  const sharedSecret = getSharedSecret(
    ephemeralPrivateKey,
    hexToBytes(params.recipientProfile.encryptionPublicKey),
    true,
  )
  const salt = crypto.getRandomValues(new Uint8Array(HKDF_SALT_LENGTH))
  const iv = crypto.getRandomValues(new Uint8Array(AES_GCM_IV_LENGTH))
  const aesKey = await deriveMessageKey(sharedSecret, salt)
  const plaintext = encoder.encode(stringifyJson(params.payload))
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: copyBytes(iv),
        additionalData: encoder.encode(
          `${BLOCKCHAIN_MESSAGE_VERSION}:${params.recipientProfile.walletAddress.toLowerCase()}`,
        ),
      },
      aesKey,
      copyBytes(plaintext),
    ),
  )
  const unsignedPackage = {
    version: BLOCKCHAIN_MESSAGE_VERSION,
    senderWalletAddress: params.session.address,
    recipientWalletAddress: params.recipientProfile.walletAddress,
    origin: window.location.origin,
    senderEncryptionPublicKey: params.session.encryptionPublicKey,
    recipientEncryptionPublicKey: params.recipientProfile.encryptionPublicKey,
    senderProfile: params.session.publicProfile,
    ephemeralPublicKey,
    salt: bytesToBase64Url(salt),
    iv: bytesToBase64Url(iv),
    ciphertext: bytesToBase64Url(ciphertext),
    createdAt: new Date().toISOString(),
  } as const
  const messageHash = hashBlockchainPackage(unsignedPackage)
  const signature = bytesToHex(
    await signAsync(hexToBytes(messageHash), params.session.encryptionPrivateKey, {
      extraEntropy: true,
      prehash: false,
    }),
  )
  const encryptedPackage = {
    ...unsignedPackage,
    messageHash,
    signature,
  } satisfies BlockchainMessagePackage

  return {
    encryptedPackage: encryptedPackage as unknown as EncryptedMessagePackage,
    messageHash,
    packageText: stringifyJson(encryptedPackage),
  }
}

export async function decryptBlockchainPayload(
  packageText: string,
  session: BlockchainSession,
): Promise<BlockchainDecryptionResult> {
  const encryptedPackage = parseBlockchainPackage(packageText)
  const inspection = await inspectBlockchainPackage(packageText)

  if (!inspection.hashValid) {
    throw new Error('This blockchain package failed integrity checks.')
  }

  if (!inspection.profileValid || !inspection.signatureValid) {
    throw new Error('This blockchain package signature is invalid.')
  }

  if (
    encryptedPackage.recipientWalletAddress.toLowerCase() !==
    session.address.toLowerCase()
  ) {
    throw new Error('This package belongs to a different connected wallet.')
  }

  if (encryptedPackage.recipientEncryptionPublicKey !== session.encryptionPublicKey) {
    throw new Error('This package was encrypted for a different wallet encryption profile.')
  }

  if (encryptedPackage.origin !== window.location.origin) {
    throw new Error('This package was created for a different site origin.')
  }

  const sharedSecret = getSharedSecret(
    session.encryptionPrivateKey,
    hexToBytes(encryptedPackage.ephemeralPublicKey),
    true,
  )
  const aesKey = await deriveMessageKey(
    sharedSecret,
    base64UrlToBytes(encryptedPackage.salt),
  )
  const plaintextBytes = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: copyBytes(base64UrlToBytes(encryptedPackage.iv)),
      additionalData: encoder.encode(
        `${BLOCKCHAIN_MESSAGE_VERSION}:${encryptedPackage.recipientWalletAddress.toLowerCase()}`,
      ),
    },
    aesKey,
    copyBytes(base64UrlToBytes(encryptedPackage.ciphertext)),
  )
  const plaintext = decoder.decode(plaintextBytes)
  const payload = parsePayload(plaintext)

  return {
    plaintext: payload.text ?? '',
    senderAddress: encryptedPackage.senderWalletAddress,
    recipientAddress: encryptedPackage.recipientWalletAddress,
    messageHash: encryptedPackage.messageHash,
    signatureValid: true,
    payload,
    legacyText: false,
    walletAddress: encryptedPackage.recipientWalletAddress,
    origin: encryptedPackage.origin,
  }
}

export async function inspectBlockchainPackage(
  packageText: string,
): Promise<BlockchainInspection> {
  const encryptedPackage = parseBlockchainPackage(packageText)
  const unsignedPackage = packagePayload(encryptedPackage)
  const hashValid =
    hashBlockchainPackage(unsignedPackage) === encryptedPackage.messageHash
  const profileValid = await verifyProfile(encryptedPackage.senderProfile)
  const signatureValid = await verifyAsync(
    hexToBytes(encryptedPackage.signature),
    hexToBytes(encryptedPackage.messageHash),
    hexToBytes(encryptedPackage.senderEncryptionPublicKey),
    { prehash: false },
  )

  return {
    version: encryptedPackage.version,
    senderWalletAddress: encryptedPackage.senderWalletAddress,
    recipientWalletAddress: encryptedPackage.recipientWalletAddress,
    origin: encryptedPackage.origin,
    messageHash: encryptedPackage.messageHash,
    createdAt: encryptedPackage.createdAt,
    hashValid,
    profileValid:
      profileValid &&
      encryptedPackage.senderProfile.encryptionPublicKey ===
        encryptedPackage.senderEncryptionPublicKey &&
      encryptedPackage.senderProfile.walletAddress.toLowerCase() ===
        encryptedPackage.senderWalletAddress.toLowerCase(),
    signatureValid,
  }
}

export function parseBlockchainProfile(text: string): BlockchainPublicProfile {
  const parsed = JSON.parse(text) as unknown

  if (!isBlockchainProfile(parsed)) {
    throw new Error('This is not a valid Sapphire blockchain public profile.')
  }

  assertValidProfile(parsed)
  return parsed
}

export function parseBlockchainPackage(text: string): BlockchainMessagePackage {
  const parsed = JSON.parse(text) as unknown

  if (!isBlockchainPackage(parsed)) {
    throw new Error('This is not a valid blockchain encrypted package.')
  }

  return parsed
}

async function verifyProfile(profile: BlockchainPublicProfile) {
  try {
    assertValidProfile(profile)
    const recovered = ethers.verifyMessage(
      stringifyJson({
        version: profile.version,
        walletAddress: profile.walletAddress,
        origin: profile.origin,
        encryptionPublicKey: profile.encryptionPublicKey,
      }),
      profile.signature,
    )

    return recovered.toLowerCase() === profile.walletAddress.toLowerCase()
  } catch {
    return false
  }
}

function assertValidProfile(profile: BlockchainPublicProfile) {
  if (!isBlockchainProfile(profile)) {
    throw new Error('This is not a valid Sapphire blockchain public profile.')
  }

  if (!ethers.isAddress(profile.walletAddress)) {
    throw new Error('The blockchain profile wallet address is invalid.')
  }

  assertPublicEncryptionKey(profile.encryptionPublicKey)
}

function hashBlockchainPackage(
  encryptedPackage: ReturnType<typeof packagePayload>,
) {
  return bytesToHex(sha256(encoder.encode(JSON.stringify(encryptedPackage))))
}

function packagePayload(encryptedPackage: BlockchainMessagePackage) {
  return {
    version: encryptedPackage.version,
    senderWalletAddress: encryptedPackage.senderWalletAddress,
    recipientWalletAddress: encryptedPackage.recipientWalletAddress,
    origin: encryptedPackage.origin,
    senderEncryptionPublicKey: encryptedPackage.senderEncryptionPublicKey,
    recipientEncryptionPublicKey: encryptedPackage.recipientEncryptionPublicKey,
    senderProfile: encryptedPackage.senderProfile,
    ephemeralPublicKey: encryptedPackage.ephemeralPublicKey,
    salt: encryptedPackage.salt,
    iv: encryptedPackage.iv,
    ciphertext: encryptedPackage.ciphertext,
    createdAt: encryptedPackage.createdAt,
  }
}

function validatePayload(payload: EncryptedPlaintextPayload) {
  if (
    payload.version !== BLOCKCHAIN_PAYLOAD_VERSION ||
    !['text', 'files', 'voice', 'mixed'].includes(payload.kind) ||
    !Array.isArray(payload.attachments)
  ) {
    throw new Error('This is not a valid encryption payload.')
  }

  if (!payload.text?.trim() && payload.attachments.length === 0) {
    throw new Error('Enter text or attach a file to encrypt.')
  }
}

function parsePayload(plaintext: string): EncryptedPlaintextPayload {
  try {
    const parsed = JSON.parse(plaintext) as unknown
    if (
      isRecord(parsed) &&
      parsed.version === BLOCKCHAIN_PAYLOAD_VERSION &&
      typeof parsed.kind === 'string' &&
      Array.isArray(parsed.attachments)
    ) {
      return parsed as unknown as EncryptedPlaintextPayload
    }
  } catch {
    // Legacy plaintext fallback.
  }

  return {
    version: BLOCKCHAIN_PAYLOAD_VERSION,
    kind: 'text',
    text: plaintext,
    attachments: [],
  }
}

function isBlockchainPackage(value: unknown): value is BlockchainMessagePackage {
  return (
    isRecord(value) &&
    value.version === BLOCKCHAIN_MESSAGE_VERSION &&
    typeof value.senderWalletAddress === 'string' &&
    ethers.isAddress(value.senderWalletAddress) &&
    typeof value.recipientWalletAddress === 'string' &&
    ethers.isAddress(value.recipientWalletAddress) &&
    typeof value.origin === 'string' &&
    typeof value.senderEncryptionPublicKey === 'string' &&
    typeof value.recipientEncryptionPublicKey === 'string' &&
    isBlockchainProfile(value.senderProfile) &&
    typeof value.ephemeralPublicKey === 'string' &&
    typeof value.salt === 'string' &&
    typeof value.iv === 'string' &&
    typeof value.ciphertext === 'string' &&
    typeof value.messageHash === 'string' &&
    typeof value.signature === 'string' &&
    typeof value.createdAt === 'string' &&
    /^[0-9a-f]{64}$/u.test(value.messageHash) &&
    /^[0-9a-f]{128}$/u.test(value.signature) &&
    isBase64Url(value.salt) &&
    isBase64Url(value.iv) &&
    isBase64Url(value.ciphertext) &&
    assertPublicEncryptionKey(value.senderEncryptionPublicKey) &&
    assertPublicEncryptionKey(value.recipientEncryptionPublicKey) &&
    assertPublicEncryptionKey(value.ephemeralPublicKey)
  )
}

function isBlockchainProfile(value: unknown): value is BlockchainPublicProfile {
  return (
    isRecord(value) &&
    value.version === BLOCKCHAIN_PROFILE_VERSION &&
    typeof value.walletAddress === 'string' &&
    typeof value.origin === 'string' &&
    typeof value.encryptionPublicKey === 'string' &&
    typeof value.signature === 'string'
  )
}

function assertPublicEncryptionKey(value: string) {
  if (!/^0[23][0-9a-f]{64}$/u.test(value)) {
    throw new Error('The encryption public key is invalid.')
  }

  return true
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value)
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
      info: encoder.encode(BLOCKCHAIN_MESSAGE_VERSION),
    },
    keyMaterial,
    {
      name: 'AES-GCM',
      length: 256,
    },
    false,
    ['encrypt', 'decrypt'],
  )
}

function bytesToBase64Url(bytes: Uint8Array) {
  const binary = Array.from(bytes, (byte) => String.fromCharCode(byte)).join('')
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '')
}

function copyBytes(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  return new Uint8Array(bytes)
}

function base64UrlToBytes(value: string) {
  const padded = `${value.replaceAll('-', '+').replaceAll('_', '/')}${'='.repeat(
    (4 - (value.length % 4)) % 4,
  )}`
  const binary = atob(padded)
  return Uint8Array.from(binary, (char) => char.charCodeAt(0))
}

function isBase64Url(value: string) {
  return /^[A-Za-z0-9_-]+$/u.test(value)
}

function hexToBytes(hex: string) {
  if (!/^[0-9a-f]+$/iu.test(hex) || hex.length % 2 !== 0) {
    throw new Error('Invalid hexadecimal value.')
  }

  return Uint8Array.from(hex.match(/.{2}/gu) ?? [], (byte) => Number.parseInt(byte, 16))
}

function bytesToHex(bytes: Uint8Array) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')
}

function shortenEthAddress(address: string) {
  return `${address.slice(0, 6)}...${address.slice(-4)}`
}
