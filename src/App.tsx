import { AnimatePresence, motion } from "motion/react";
import {
	useCallback,
	useEffect,
	useMemo,
	useRef,
	useState,
	type ChangeEvent,
	type DragEvent,
	type ReactNode,
} from "react";
import {
	BookOpen,
	BookUser,
	Check,
	ChevronDown,
	ChevronUp,
	CircleAlert,
	CircleCheck,
	Copy,
	Download,
	Edit3,
	Eraser,
	FileJson,
	FileText,
	KeyRound,
	Mic,
	Paperclip,
	Plus,
	Search,
	Send,
	Trash2,
	Unlock,
	Upload,
	UserPlus,
	X,
} from "lucide-react";
import { Route, Routes } from "react-router-dom";

import sapphireLogo from "./assets/sapphire_logo.png";
import {
	decryptPayload,
	encryptPayload,
	generateProtectedKeyPair,
	getPublicAddressFingerprint,
	inspectEncryptedPackage,
	normalizePublicAddress,
	parseProtectedPrivateKeyFile,
	readTextFile,
	stringifyJson,
	validatePrivateKeyPassword,
	type DecryptedPayloadResult,
	type EncryptedAttachment,
	type EncryptedPlaintextPayload,
	type EncryptionResult,
	type GeneratedKeyPair,
	type PackageInspection,
	type ProtectedPrivateKeyFile,
} from "./lib/crypto";

type NoticeTone = "success" | "error" | "info";
type TrustStatus = "unverified" | "verified" | "blocked";
type ChatMode = "locked" | "create-key" | "load-key" | "encrypt" | "decrypt";

interface Notice {
	tone: NoticeTone;
	message: string;
}

interface AddressBookEntry {
	address: string;
	createdAt: number;
	emoji: string;
	id: string;
	name: string;
	trustStatus: TrustStatus;
}

interface PasswordStrength {
	className: string;
	label: string;
	score: 1 | 2 | 3 | 4;
}

interface SessionKeyState {
	fileName: string;
	fingerprint: string;
	keyFile: ProtectedPrivateKeyFile;
	password: string;
	publicAddress: string;
}

interface ChatMessage {
	id: string;
	notice?: Notice;
	recipientAddress?: string;
	recipientFingerprint?: string;
	result?: DecryptedPayloadResult | EncryptionResult;
	role: "assistant" | "system" | "user";
	senderAddress?: string;
	senderFingerprint?: string;
	text?: string;
	type:
		| "decrypted"
		| "encrypted"
		| "guide"
		| "notice"
		| "text"
		| "typing"
		| "welcome";
}

type EncryptedChatMessage = ChatMessage & {
	recipientAddress: string;
	recipientFingerprint: string;
	result: EncryptionResult;
	senderAddress: string;
	senderFingerprint: string;
	type: "encrypted";
};

type DecryptedChatMessage = ChatMessage & {
	result: DecryptedPayloadResult;
	type: "decrypted";
};

interface AttachmentDraft extends EncryptedAttachment {
	objectUrl?: string;
}

const addressBookStorageKey = "sapphirelabs-address-book-v1";
const maxAttachmentBytes = 10 * 1024 * 1024;
const addressBookEmojiOptions = ["😀", "🧠", "🔐", "🚀", "📡", "🫶", "💼", "⭐"];
const trustStatusOptions = ["unverified", "verified", "blocked"] as const;
const chatPlaceholders = [
	"Unlock the chat with your private key",
	"Encrypt a message for a public address",
	"Decrypt a Sapphire message package",
	"Use your address book to select a recipient",
];
const voiceBars = [5, 10, 7, 13, 8, 15, 6, 12, 9, 14, 7, 11];
const guideMessage = `How Encrypted by Sapphire works

1. Create or upload your private key
Start by creating a new key pair or uploading an existing Sapphire private key JSON file. The private key file is password-protected and is required whenever you sign, encrypt, or decrypt. The app keeps it in browser memory only for this session.

2. Public address and private key
Your public address is a full secp256k1 public key that other people can use as the recipient address. Your private key must stay secret. Anyone can know your public address, but only the matching private key can decrypt messages sent to it.

3. Technology used
The app uses secp256k1 asymmetric key pairs, similar to Ethereum-style public/private key identity. It uses ECDH to derive a shared secret between sender and recipient, Web Crypto AES-GCM for authenticated encryption, SHA-256 for message hashes and fingerprints, and digital signatures so the recipient can verify the sender and detect tampering.

4. Encrypting text, files, or voice
Choose Encrypt, paste or load the recipient public address, then type a message, attach files, or record voice. The app packages your text/files/voice into a private payload, encrypts it for the recipient address, signs it with your private key, and returns a JSON package that you can copy or download.

5. Decrypting a package
Choose Decrypt, paste the encrypted JSON or upload the package file. The app inspects the package first, verifies the hash and signature, then uses your unlocked private key to decrypt it. If the package was edited or sent to another address, decryption is blocked.

6. Address Book
The Address Book saves public addresses, names, emojis, and trust status locally in this browser. It never stores private keys. Use fingerprints to compare identities before trusting an address.

7. Security rules
Do not share your private key file or password. Losing either means Sapphire cannot recover your messages. Only decrypt files from people you trust, and always confirm the recipient address or fingerprint before sending sensitive information.`;

function HomePage() {
	const chatEndRef = useRef<HTMLDivElement>(null);
	const mediaRecorderRef = useRef<MediaRecorder | null>(null);
	const mediaStreamRef = useRef<MediaStream | null>(null);
	const audioChunksRef = useRef<BlobPart[]>([]);
	const keepRecordingRef = useRef(false);
	const [mode, setMode] = useState<ChatMode>("locked");
	const [sessionKey, setSessionKey] = useState<SessionKeyState | null>(null);
	const [messages, setMessages] = useState<ChatMessage[]>([]);
	const [inputValue, setInputValue] = useState("");
	const [notice, setNotice] = useState<Notice | null>(null);

	const [keyPassword, setKeyPassword] = useState("");
	const [keyPasswordConfirm, setKeyPasswordConfirm] = useState("");
	const [generatedKey, setGeneratedKey] = useState<GeneratedKeyPair | null>(
		null,
	);
	const [isGenerating, setIsGenerating] = useState(false);

	const [loadKeyFile, setLoadKeyFile] =
		useState<ProtectedPrivateKeyFile | null>(null);
	const [loadKeyFileName, setLoadKeyFileName] = useState("");
	const [loadKeyPassword, setLoadKeyPassword] = useState("");
	const [isValidatingKey, setIsValidatingKey] = useState(false);

	const [recipientAddress, setRecipientAddress] = useState("");
	const [packageText, setPackageText] = useState("");
	const [packageFileName, setPackageFileName] = useState("");
	const [packageInspection, setPackageInspection] =
		useState<PackageInspection | null>(null);
	const [isProcessing, setIsProcessing] = useState(false);
	const [attachments, setAttachments] = useState<AttachmentDraft[]>([]);
	const [isRecording, setIsRecording] = useState(false);
	const [recordingSeconds, setRecordingSeconds] = useState(0);
	const attachmentsRef = useRef<AttachmentDraft[]>([]);

	const [addressBook, setAddressBook] = useState<AddressBookEntry[]>(() =>
		loadAddressBook(),
	);
	const [addressBookAddress, setAddressBookAddress] = useState("");
	const [addressBookName, setAddressBookName] = useState("");
	const [addressBookEmoji, setAddressBookEmoji] = useState(
		addressBookEmojiOptions[0],
	);
	const [addressBookTrustStatus, setAddressBookTrustStatus] =
		useState<TrustStatus>("unverified");
	const [addressBookNotice, setAddressBookNotice] = useState<Notice | null>(
		null,
	);
	const [addressBookModalOpen, setAddressBookModalOpen] = useState(false);
	const [editingAddressId, setEditingAddressId] = useState<string | null>(null);

	const passwordStrength = useMemo(
		() => getPasswordStrength(keyPassword),
		[keyPassword],
	);
	const recipientFingerprint = useMemo(
		() => getOptionalFingerprint(recipientAddress),
		[recipientAddress],
	);
	const totalAttachmentBytes = useMemo(
		() => attachments.reduce((total, attachment) => total + attachment.size, 0),
		[attachments],
	);
	const showIntroPopup =
		!sessionKey && messages.length === 0 && mode === "locked";
	const chatUnlocked = sessionKey !== null;
	const composerReady =
		chatUnlocked &&
		((mode === "encrypt" && recipientFingerprint.length > 0) ||
			mode === "decrypt");
	const canSend =
		!isProcessing &&
		chatUnlocked &&
		((mode === "encrypt" &&
			(inputValue.trim().length > 0 || attachments.length > 0) &&
			recipientFingerprint.length > 0) ||
			(mode === "decrypt" && inputValue.trim().length > 0));

	useEffect(() => {
		saveAddressBook(addressBook);
	}, [addressBook]);

	useEffect(() => {
		chatEndRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
	}, [messages, mode]);

	useEffect(() => {
		if (!isRecording) {
			return;
		}

		const interval = window.setInterval(() => {
			setRecordingSeconds((current) => current + 1);
		}, 1000);

		return () => window.clearInterval(interval);
	}, [isRecording]);

	useEffect(() => {
		attachmentsRef.current = attachments;
	}, [attachments]);

	useEffect(() => {
		return () => {
			attachmentsRef.current.forEach((attachment) => {
				if (attachment.objectUrl) {
					URL.revokeObjectURL(attachment.objectUrl);
				}
			});
			mediaStreamRef.current?.getTracks().forEach((track) => track.stop());
		};
	}, []);

	function pushMessage(message: Omit<ChatMessage, "id">) {
		setMessages((current) => [
			...current,
			{ ...message, id: crypto.randomUUID() } as ChatMessage,
		]);
	}

	function replaceTyping(message: Omit<ChatMessage, "id">) {
		setMessages((current) => [
			...current.filter((item) => item.type !== "typing"),
			{ ...message, id: crypto.randomUUID() } as ChatMessage,
		]);
	}

	function activateSession(
		keyFile: ProtectedPrivateKeyFile,
		password: string,
		fileName: string,
	) {
		const publicAddress = keyFile.publicAddress;
		setSessionKey({
			fileName,
			fingerprint: getPublicAddressFingerprint(publicAddress),
			keyFile,
			password,
			publicAddress,
		});
		setMode("encrypt");
		setNotice({
			tone: "success",
			message: "Private key ready. Choose encrypt or decrypt.",
		});
		pushMessage({
			role: "system",
			type: "notice",
			notice: {
				tone: "success",
				message: "Chat unlocked. Your private key is held in memory only.",
			},
		});
	}

	async function handleGenerateKey() {
		setNotice(null);
		setIsGenerating(true);

		try {
			if (keyPassword !== keyPasswordConfirm) {
				throw new Error("The private key passwords do not match.");
			}

			const keyPair = await generateProtectedKeyPair(keyPassword);
			setGeneratedKey(keyPair);
			activateSession(
				keyPair.privateKeyFile,
				keyPassword,
				keyPair.privateKeyFileName,
			);
		} catch (error) {
			setNotice(toNotice(error, "Could not create the key pair."));
		} finally {
			setIsGenerating(false);
		}
	}

	async function handleLoadKeyConfirm() {
		setNotice(null);
		setIsValidatingKey(true);

		try {
			if (!loadKeyFile) {
				throw new Error("Upload a private key JSON file.");
			}

			await validatePrivateKeyPassword(loadKeyFile, loadKeyPassword);
			activateSession(loadKeyFile, loadKeyPassword, loadKeyFileName);
		} catch (error) {
			setNotice(toNotice(error, "Could not unlock this private key."));
		} finally {
			setIsValidatingKey(false);
		}
	}

	async function handlePrivateKeyUpload(file: File) {
		setNotice(null);

		try {
			const text = await readTextFile(file);
			const keyFile = parseProtectedPrivateKeyFile(text);
			setLoadKeyFile(keyFile);
			setLoadKeyFileName(file.name);
			setNotice(null);
		} catch (error) {
			setNotice(toNotice(error, "Could not read the private key file."));
		}
	}

	async function handlePackageUpload(file: File) {
		setNotice(null);

		try {
			const text = await readTextFile(file);
			setPackageFileName(file.name);
			updatePackageText(text);

			if (sessionKey && mode === "decrypt") {
				await decryptPackage(text, `Decrypt package: ${file.name}`);
				return;
			}

			setInputValue(text);
			setNotice({
				tone: "success",
				message: "Encrypted package loaded into the chat input.",
			});
		} catch (error) {
			setNotice(toNotice(error, "Could not read the encrypted package."));
		}
	}

	function updatePackageText(value: string) {
		setPackageText(value);

		if (!value.trim()) {
			setPackageInspection(null);
			return;
		}

		try {
			setPackageInspection(inspectEncryptedPackage(value));
		} catch {
			setPackageInspection(null);
		}
	}

	async function handleAttachmentUpload(file: File) {
		setNotice(null);

		try {
			const nextTotal = totalAttachmentBytes + file.size;

			if (nextTotal > maxAttachmentBytes) {
				throw new Error(
					`Attachments can be up to ${formatFileSize(
						maxAttachmentBytes,
					)} total.`,
				);
			}

			const attachment = await fileToBase64Payload(file);
			setAttachments((current) => [...current, attachment]);
		} catch (error) {
			setNotice(toNotice(error, "Could not attach this file."));
		}
	}

	function removeAttachment(id: string) {
		setAttachments((current) => {
			const removed = current.find((attachment) => attachment.id === id);
			if (removed?.objectUrl) {
				URL.revokeObjectURL(removed.objectUrl);
			}

			return current.filter((attachment) => attachment.id !== id);
		});
	}

	function getCurrentPayload(): EncryptedPlaintextPayload {
		const text = inputValue.trim() ? inputValue : undefined;
		const hasText = Boolean(text);
		const hasAttachments = attachments.length > 0;
		const hasVoice = attachments.some((attachment) =>
			attachment.type.startsWith("audio/"),
		);
		const kind =
			hasText && hasAttachments
				? "mixed"
				: hasVoice
				? "voice"
				: hasAttachments
				? "files"
				: "text";

		return {
			version: "sapphire-payload-v1",
			kind,
			text,
			attachments: attachments.map(stripAttachmentDraft),
		};
	}

	async function toggleRecording() {
		if (isRecording) {
			keepRecordingRef.current = true;
			mediaRecorderRef.current?.stop();
			return;
		}

		setNotice(null);

		try {
			if (!navigator.mediaDevices?.getUserMedia || !window.MediaRecorder) {
				throw new Error("Voice recording is not supported in this browser.");
			}

			const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
			const recorder = new MediaRecorder(stream);
			audioChunksRef.current = [];
			keepRecordingRef.current = true;
			mediaStreamRef.current = stream;
			mediaRecorderRef.current = recorder;

			recorder.ondataavailable = (event) => {
				if (event.data.size > 0) {
					audioChunksRef.current.push(event.data);
				}
			};

			recorder.onstop = () => {
				const chunks = audioChunksRef.current;
				const shouldAttach = keepRecordingRef.current;
				stream.getTracks().forEach((track) => track.stop());
				setIsRecording(false);
				setRecordingSeconds(0);

				if (!shouldAttach || chunks.length === 0) {
					return;
				}

				const blob = new Blob(chunks, {
					type: recorder.mimeType || "audio/webm",
				});
				const file = new File([blob], "voice-message.webm", {
					type: blob.type || "audio/webm",
				});
				void handleAttachmentUpload(file);
			};

			recorder.start();
			setRecordingSeconds(0);
			setIsRecording(true);
		} catch (error) {
			setNotice(toNotice(error, "Could not start voice recording."));
		}
	}

	function cancelRecording() {
		keepRecordingRef.current = false;
		mediaRecorderRef.current?.stop();
	}

	async function decryptPackage(packageJson: string, userLabel: string) {
		if (!sessionKey) {
			return;
		}

		setNotice(null);
		setIsProcessing(true);
		pushMessage({ role: "user", type: "text", text: userLabel });
		pushMessage({ role: "assistant", type: "typing" });

		try {
			const inspection = inspectEncryptedPackage(packageJson);

			if (!inspection.hashValid || !inspection.signatureValid) {
				throw new Error(
					"This encrypted package failed integrity checks and cannot be decrypted.",
				);
			}

			const result = await decryptPayload({
				packageText: packageJson,
				recipientKeyFile: sessionKey.keyFile,
				recipientPassword: sessionKey.password,
			});
			setPackageText(packageJson);
			setPackageInspection(inspection);
			setInputValue("");
			replaceTyping({ role: "assistant", type: "decrypted", result });
		} catch (error) {
			replaceTyping({
				role: "system",
				type: "notice",
				notice: toNotice(error, "The action failed."),
			});
		} finally {
			setIsProcessing(false);
		}
	}

	async function handleSend() {
		if (!sessionKey || !canSend) {
			return;
		}

		if (mode === "decrypt") {
			await decryptPackage(inputValue, "Decrypt pasted package");
			return;
		}

		setNotice(null);
		setIsProcessing(true);
		pushMessage({
			role: "user",
			type: "text",
			text:
				attachments.length > 0
					? [
							inputValue || "Encrypt attached file",
							...attachments.map(
								(attachment) =>
									`${attachment.name} (${formatFileSize(attachment.size)})`,
							),
					  ].join("\n")
					: inputValue,
		});
		pushMessage({ role: "assistant", type: "typing" });

		try {
			const normalizedRecipient = normalizePublicAddress(recipientAddress);
			const result = await encryptPayload({
				payload: getCurrentPayload(),
				recipientAddress: normalizedRecipient,
				senderKeyFile: sessionKey.keyFile,
				senderPassword: sessionKey.password,
			});

			replaceTyping({
				role: "assistant",
				type: "encrypted",
				result,
				recipientAddress: normalizedRecipient,
				recipientFingerprint: getPublicAddressFingerprint(normalizedRecipient),
				senderAddress: sessionKey.publicAddress,
				senderFingerprint: sessionKey.fingerprint,
			});
			setInputValue("");
			setAttachments([]);
		} catch (error) {
			replaceTyping({
				role: "system",
				type: "notice",
				notice: toNotice(error, "The action failed."),
			});
		} finally {
			setIsProcessing(false);
		}
	}

	function handleSaveAddress() {
		setAddressBookNotice(null);

		try {
			const address = normalizePublicAddress(addressBookAddress);
			const name = safeString(addressBookName).trim();
			const emoji = sanitizeEmoji(addressBookEmoji);
			const trustStatus = sanitizeTrustStatus(addressBookTrustStatus);
			const existingEntry = addressBook.find((entry) =>
				editingAddressId
					? entry.id !== editingAddressId && entry.address === address
					: entry.address === address,
			);

			if (existingEntry) {
				throw new Error("This public address is already saved.");
			}

			if (editingAddressId) {
				setAddressBook((entries) =>
					entries.map((entry) =>
						entry.id === editingAddressId
							? { ...entry, address, emoji, name, trustStatus }
							: entry,
					),
				);
				setAddressBookNotice({ tone: "success", message: "Address updated." });
			} else {
				setAddressBook((entries) => [
					{
						address,
						createdAt: Date.now(),
						emoji,
						id: crypto.randomUUID(),
						name,
						trustStatus,
					},
					...entries,
				]);
				setAddressBookNotice({
					tone: "success",
					message: "Address saved locally in this browser.",
				});
			}

			clearAddressBookForm();
		} catch (error) {
			setAddressBookNotice(toNotice(error, "Could not save this address."));
		}
	}

	function clearAddressBookForm() {
		setAddressBookAddress("");
		setAddressBookName("");
		setAddressBookEmoji(addressBookEmojiOptions[0]);
		setAddressBookTrustStatus("unverified");
		setEditingAddressId(null);
	}

	function handleUseSavedAddress(address: string) {
		setRecipientAddress(address);
		setAddressBookModalOpen(false);
		setMode("encrypt");
		setAddressBookNotice({
			tone: "success",
			message: "Recipient address filled from the address book.",
		});
	}

	function handleEditSavedAddress(entry: AddressBookEntry) {
		setAddressBookAddress(safeString(entry.address));
		setAddressBookName(safeString(entry.name));
		setAddressBookEmoji(sanitizeEmoji(entry.emoji));
		setAddressBookTrustStatus(sanitizeTrustStatus(entry.trustStatus));
		setEditingAddressId(entry.id);
		setAddressBookNotice(null);
	}

	function handleDeleteSavedAddress(id: string) {
		setAddressBook((entries) => entries.filter((entry) => entry.id !== id));
		if (editingAddressId === id) {
			clearAddressBookForm();
		}
		setAddressBookNotice({
			tone: "info",
			message: "Address removed from this browser.",
		});
	}

	function handleAddressTrustChange(id: string, trustStatus: TrustStatus) {
		setAddressBook((entries) =>
			entries.map((entry) =>
				entry.id === id ? { ...entry, trustStatus } : entry,
			),
		);
	}

	async function handleImportAddressBook(file: File | undefined) {
		if (!file) {
			return;
		}

		setAddressBookNotice(null);

		try {
			const text = await readTextFile(file);
			const importedEntries = parseAddressBookImport(file.name, text);
			setAddressBook((entries) =>
				mergeAddressBookEntries(entries, importedEntries),
			);
			setAddressBookNotice({
				tone: "success",
				message: `${importedEntries.length} contact${
					importedEntries.length === 1 ? "" : "s"
				} loaded into this browser.`,
			});
		} catch (error) {
			setAddressBookNotice(
				toNotice(error, "Could not import the contacts file."),
			);
		}
	}

	function clearChat() {
		setMessages([]);
		setNotice(null);
	}

	return (
		<main className="min-h-svh bg-background text-foreground">
			<section className="mx-auto flex min-h-svh w-full max-w-7xl flex-col px-4 py-4 sm:px-6">
				<header className="flex shrink-0 items-center justify-between gap-4 py-2">
					<a
						className="flex min-w-0 items-center gap-3 rounded-md focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-foreground"
						href="https://sapphirelabs.org"
						rel="noreferrer"
						target="_blank"
					>
						<img
							src={sapphireLogo}
							className="size-10 rounded-md object-contain"
							alt="SapphireLabs logo"
						/>
						{/* <p className="truncate text-base font-semibold">
              ENCRYPTED BY SAPPHIRE
            </p> */}
					</a>
					<div className="flex items-center gap-3">
						<button
							className="text-button"
							type="button"
							onClick={() =>
								pushMessage({
									role: "system",
									type: "guide",
									text: guideMessage,
								})
							}
						>
							<BookOpen className="size-4" aria-hidden="true" />
							Guide
						</button>
						<button
							className="button button-pill min-h-10 px-4"
							type="button"
							onClick={() => {
								setEditingAddressId(null);
								setAddressBookModalOpen(true);
							}}
						>
							<BookUser className="size-4" aria-hidden="true" />
							Address Book
						</button>
					</div>
				</header>

				{showIntroPopup ? <IntroInfoPopup /> : null}

				<div className="mx-auto flex min-h-0 w-full max-w-5xl flex-1 flex-col">
					<section className="min-h-0 flex-1 overflow-y-auto py-4">
						<div className="grid gap-4">
							<AnimatePresence initial={false}>
								{messages.map((message) => (
									<ChatMessageView
										key={message.id}
										message={message}
										onCopyNotice={setNotice}
									/>
								))}
							</AnimatePresence>
							<div ref={chatEndRef} />
						</div>
					</section>

					<ChatComposer
						canSend={canSend}
						composerReady={composerReady}
						attachments={attachments}
						generatedKey={generatedKey}
						inputValue={inputValue}
						isGenerating={isGenerating}
						isProcessing={isProcessing}
						isRecording={isRecording}
						isValidatingKey={isValidatingKey}
						keyPassword={keyPassword}
						keyPasswordConfirm={keyPasswordConfirm}
						loadKeyFile={loadKeyFile}
						loadKeyFileName={loadKeyFileName}
						loadKeyPassword={loadKeyPassword}
						mode={mode}
						notice={notice}
						packageFileName={packageFileName}
						packageInspection={packageInspection}
						packageText={packageText}
						passwordStrength={passwordStrength}
						recordingSeconds={recordingSeconds}
						recipientAddress={recipientAddress}
						recipientFingerprint={recipientFingerprint}
						sessionKey={sessionKey}
						onAddressBook={() => setAddressBookModalOpen(true)}
						onAttachmentUpload={handleAttachmentUpload}
						onCancelRecording={cancelRecording}
						onClearChat={clearChat}
						onGenerate={handleGenerateKey}
						onInputChange={setInputValue}
						onKeyPasswordChange={setKeyPassword}
						onKeyPasswordConfirmChange={setKeyPasswordConfirm}
						onLoadKeyConfirm={handleLoadKeyConfirm}
						onLoadKeyPasswordChange={setLoadKeyPassword}
						onModeChange={setMode}
						onPackageTextChange={updatePackageText}
						onPackageUpload={handlePackageUpload}
						onPrivateKeyUpload={handlePrivateKeyUpload}
						onRecipientAddressChange={setRecipientAddress}
						onRemoveAttachment={removeAttachment}
						onSend={() => void handleSend()}
						onToggleRecording={() => void toggleRecording()}
					/>
				</div>

				<footer className="mx-auto w-full max-w-5xl shrink-0 py-4 text-center text-xs leading-5 text-muted-foreground">
					Sapphire Labs Encrypted uses public-key encryption. Each user has a
					public address they can share and a private key file they must keep
					secret. Messages are encrypted for a recipient's public address, so
					only the matching private key can open them. Each encrypted message is
					also signed, so the recipient can verify who sent it and confirm it
					was not tampered with.
				</footer>
			</section>

			<AddressBookModal
				address={addressBookAddress}
				emoji={addressBookEmoji}
				editingAddressId={editingAddressId}
				entries={addressBook}
				name={addressBookName}
				notice={addressBookNotice}
				open={addressBookModalOpen}
				trustStatus={addressBookTrustStatus}
				onAddressChange={setAddressBookAddress}
				onCancelEdit={() => {
					clearAddressBookForm();
					setAddressBookNotice(null);
				}}
				onClose={() => {
					setAddressBookModalOpen(false);
					clearAddressBookForm();
					setAddressBookNotice(null);
				}}
				onCopy={(value) =>
					void copyText(value, (copyNotice) => setAddressBookNotice(copyNotice))
				}
				onDelete={handleDeleteSavedAddress}
				onEdit={handleEditSavedAddress}
				onEmojiChange={setAddressBookEmoji}
				onImport={handleImportAddressBook}
				onNameChange={setAddressBookName}
				onSave={handleSaveAddress}
				onTrustChange={handleAddressTrustChange}
				onTrustStatusChange={setAddressBookTrustStatus}
				onUse={handleUseSavedAddress}
			/>
		</main>
	);
}

function ChatComposer({
	attachments,
	canSend,
	composerReady,
	generatedKey,
	inputValue,
	isGenerating,
	isProcessing,
	isRecording,
	isValidatingKey,
	keyPassword,
	keyPasswordConfirm,
	loadKeyFile,
	loadKeyFileName,
	loadKeyPassword,
	mode,
	notice,
	onAddressBook,
	onAttachmentUpload,
	onCancelRecording,
	onClearChat,
	onGenerate,
	onInputChange,
	onKeyPasswordChange,
	onKeyPasswordConfirmChange,
	onLoadKeyConfirm,
	onLoadKeyPasswordChange,
	onModeChange,
	onPackageTextChange,
	onPackageUpload,
	onPrivateKeyUpload,
	onRecipientAddressChange,
	onRemoveAttachment,
	onSend,
	onToggleRecording,
	packageFileName,
	packageInspection,
	packageText,
	passwordStrength,
	recordingSeconds,
	recipientAddress,
	recipientFingerprint,
	sessionKey,
}: {
	attachments: AttachmentDraft[];
	canSend: boolean;
	composerReady: boolean;
	generatedKey: GeneratedKeyPair | null;
	inputValue: string;
	isGenerating: boolean;
	isProcessing: boolean;
	isRecording: boolean;
	isValidatingKey: boolean;
	keyPassword: string;
	keyPasswordConfirm: string;
	loadKeyFile: ProtectedPrivateKeyFile | null;
	loadKeyFileName: string;
	loadKeyPassword: string;
	mode: ChatMode;
	notice: Notice | null;
	onAddressBook: () => void;
	onAttachmentUpload: (file: File) => Promise<void>;
	onCancelRecording: () => void;
	onClearChat: () => void;
	onGenerate: () => void;
	onInputChange: (value: string) => void;
	onKeyPasswordChange: (value: string) => void;
	onKeyPasswordConfirmChange: (value: string) => void;
	onLoadKeyConfirm: () => void;
	onLoadKeyPasswordChange: (value: string) => void;
	onModeChange: (mode: ChatMode) => void;
	onPackageTextChange: (value: string) => void;
	onPackageUpload: (file: File) => Promise<void>;
	onPrivateKeyUpload: (file: File) => Promise<void>;
	onRecipientAddressChange: (value: string) => void;
	onRemoveAttachment: (id: string) => void;
	onSend: () => void;
	onToggleRecording: () => void;
	packageFileName: string;
	packageInspection: PackageInspection | null;
	packageText: string;
	passwordStrength: PasswordStrength;
	recordingSeconds: number;
	recipientAddress: string;
	recipientFingerprint: string;
	sessionKey: SessionKeyState | null;
}) {
	const [placeholderIndex, setPlaceholderIndex] = useState(0);
	const [showPlaceholder, setShowPlaceholder] = useState(true);
	const wrapperRef = useRef<HTMLDivElement>(null);
	const packageInputRef = useRef<HTMLInputElement>(null);
	const attachmentInputRef = useRef<HTMLInputElement>(null);
	const locked = sessionKey === null;
	const expanded = locked || !composerReady;

	useEffect(() => {
		if (inputValue) {
			return;
		}

		const interval = window.setInterval(() => {
			setShowPlaceholder(false);
			window.setTimeout(() => {
				setPlaceholderIndex(
					(current) => (current + 1) % chatPlaceholders.length,
				);
				setShowPlaceholder(true);
			}, 360);
		}, 2800);

		return () => window.clearInterval(interval);
	}, [inputValue]);

	const composerHeight = locked
		? mode === "create-key"
			? generatedKey
				? 448
				: 390
			: mode === "load-key"
			? loadKeyFile
				? 360
				: 268
			: 122
		: composerReady
		? mode === "encrypt" && (attachments.length > 0 || isRecording)
			? 130
			: 68
		: mode === "encrypt"
		? 258
		: 68;

	return (
		<div className="shrink-0 pb-3">
			<motion.div
				ref={wrapperRef}
				className="w-full border border-border bg-white"
				animate={{
					height: composerHeight,
					boxShadow: expanded
						? "0 12px 38px rgba(0,0,0,0.13)"
						: "0 2px 8px rgba(0,0,0,0.08)",
				}}
				initial={false}
				transition={{ type: "spring", stiffness: 120, damping: 18 }}
				style={{ overflow: "hidden", borderRadius: 32 }}
			>
				<div className="flex h-full flex-col">
					<div className="flex w-full items-center gap-2 p-3">
						<button
							className="rounded-full p-3 transition hover:bg-muted"
							title="Attach JSON"
							type="button"
							onClick={() => {
								if (locked) {
									onModeChange("load-key");
									return;
								}

								if (mode === "decrypt") {
									packageInputRef.current?.click();
									return;
								}

								if (mode === "encrypt") {
									attachmentInputRef.current?.click();
								}
							}}
						>
							<Paperclip className="size-5" />
						</button>
						<input
							ref={packageInputRef}
							className="sr-only"
							type="file"
							accept="application/json,.json"
							onChange={(event) => {
								const file = event.currentTarget.files?.[0];
								if (file) {
									void onPackageUpload(file);
								}
								event.currentTarget.value = "";
							}}
						/>
						<input
							ref={attachmentInputRef}
							className="sr-only"
							type="file"
							multiple
							onChange={(event) => {
								Array.from(event.currentTarget.files ?? []).forEach((file) => {
									void onAttachmentUpload(file);
								});
								event.currentTarget.value = "";
							}}
						/>

						{!locked ? (
							<div className="hidden shrink-0 items-center gap-1 sm:flex">
								<button
									className={`rounded-full px-3 py-1 text-xs font-semibold transition ${
										mode === "encrypt"
											? "bg-black text-white"
											: "bg-muted text-muted-foreground hover:text-foreground"
									}`}
									type="button"
									onClick={() => onModeChange("encrypt")}
								>
									Encrypt
								</button>
								<button
									className={`rounded-full px-3 py-1 text-xs font-semibold transition ${
										mode === "decrypt"
											? "bg-black text-white"
											: "bg-muted text-muted-foreground hover:text-foreground"
									}`}
									type="button"
									onClick={() => onModeChange("decrypt")}
								>
									Decrypt
								</button>
								{mode === "encrypt" && composerReady ? (
									<button
										className="rounded-full bg-muted p-1.5 text-muted-foreground transition hover:text-foreground"
										title="Change recipient"
										type="button"
										onClick={() => onRecipientAddressChange("")}
									>
										<BookUser className="size-3.5" />
									</button>
								) : null}
							</div>
						) : null}

						<div className="relative min-w-0 flex-1">
							<input
								className="relative z-10 w-full border-0 bg-transparent py-2 text-base outline-0 disabled:cursor-not-allowed disabled:text-muted-foreground"
								disabled={locked}
								type="text"
								value={inputValue}
								onChange={(event) => onInputChange(event.target.value)}
								onKeyDown={(event) => {
									if (event.key === "Enter") {
										onSend();
									}
								}}
							/>
							<div className="pointer-events-none absolute inset-0 flex items-center">
								<AnimatePresence mode="wait">
									{showPlaceholder && !inputValue ? (
										<motion.span
											key={placeholderIndex}
											className="absolute left-0 top-1/2 max-w-full -translate-y-1/2 truncate text-muted-foreground"
											variants={{
												initial: {},
												animate: { transition: { staggerChildren: 0.025 } },
												exit: {
													transition: {
														staggerChildren: 0.015,
														staggerDirection: -1,
													},
												},
											}}
											initial="initial"
											animate="animate"
											exit="exit"
										>
											{(locked
												? "Upload or create a key to unlock chat"
												: mode === "decrypt"
												? "Paste encrypted JSON or attach a file"
												: chatPlaceholders[placeholderIndex]
											)
												.split("")
												.map((character, index) => (
													<motion.span
														key={`${character}-${index}`}
														style={{ display: "inline-block" }}
														variants={{
															initial: {
																opacity: 0,
																filter: "blur(12px)",
																y: 10,
															},
															animate: {
																opacity: 1,
																filter: "blur(0px)",
																y: 0,
																transition: {
																	opacity: { duration: 0.25 },
																	filter: { duration: 0.4 },
																	y: {
																		type: "spring",
																		stiffness: 80,
																		damping: 20,
																	},
																},
															},
															exit: {
																opacity: 0,
																filter: "blur(12px)",
																y: -10,
																transition: {
																	opacity: { duration: 0.2 },
																	filter: { duration: 0.3 },
																	y: {
																		type: "spring",
																		stiffness: 80,
																		damping: 20,
																	},
																},
															},
														}}
													>
														{character === " " ? "\u00A0" : character}
													</motion.span>
												))}
										</motion.span>
									) : null}
								</AnimatePresence>
							</div>
						</div>

						<button
							className="inline-flex size-11 items-center justify-center rounded-full bg-black text-white transition hover:bg-zinc-700 disabled:cursor-not-allowed disabled:opacity-40"
							title="Send"
							type="button"
							disabled={!canSend}
							onClick={onSend}
						>
							{isProcessing ? (
								<TypingDots compact />
							) : (
								<Send className="size-5" />
							)}
						</button>
						{!locked && mode === "encrypt" ? (
							<VoiceRecorderButton
								isRecording={isRecording}
								recordingSeconds={recordingSeconds}
								onToggle={onToggleRecording}
							/>
						) : null}
					</div>

					{composerReady &&
					mode === "encrypt" &&
					(attachments.length > 0 || isRecording) ? (
						<div className="border-t border-border px-4 pb-3">
							<AttachmentStrip
								attachments={attachments}
								isRecording={isRecording}
								recordingSeconds={recordingSeconds}
								onCancelRecording={onCancelRecording}
								onRemoveAttachment={onRemoveAttachment}
							/>
						</div>
					) : null}

					{!composerReady ? (
						<div className="min-h-0 flex-1 overflow-y-auto px-4 pb-3">
							{locked ? (
								<LockedComposerPanel
									generatedKey={generatedKey}
									isGenerating={isGenerating}
									isValidatingKey={isValidatingKey}
									keyPassword={keyPassword}
									keyPasswordConfirm={keyPasswordConfirm}
									loadKeyFile={loadKeyFile}
									loadKeyFileName={loadKeyFileName}
									loadKeyPassword={loadKeyPassword}
									mode={mode}
									notice={notice}
									passwordStrength={passwordStrength}
									onGenerate={onGenerate}
									onKeyPasswordChange={onKeyPasswordChange}
									onKeyPasswordConfirmChange={onKeyPasswordConfirmChange}
									onLoadKeyConfirm={onLoadKeyConfirm}
									onLoadKeyPasswordChange={onLoadKeyPasswordChange}
									onModeChange={onModeChange}
									onPrivateKeyUpload={onPrivateKeyUpload}
								/>
							) : (
								<UnlockedComposerPanel
									attachments={attachments}
									isRecording={isRecording}
									mode={mode}
									notice={notice}
									onAddressBook={onAddressBook}
									onClearChat={onClearChat}
									onPackageTextChange={onPackageTextChange}
									onPackageUpload={onPackageUpload}
									onRecipientAddressChange={onRecipientAddressChange}
									packageFileName={packageFileName}
									packageInspection={packageInspection}
									packageText={packageText}
									recipientAddress={recipientAddress}
									recipientFingerprint={recipientFingerprint}
									sessionKey={sessionKey}
									recordingSeconds={recordingSeconds}
									onCancelRecording={onCancelRecording}
									onRemoveAttachment={onRemoveAttachment}
								/>
							)}
						</div>
					) : null}
				</div>
			</motion.div>
		</div>
	);
}

function IntroInfoPopup() {
	return (
		<motion.aside
			className="pointer-events-none fixed left-1/2 top-[20%] z-10 w-[calc(100%-2rem)] max-w-xl -translate-x-1/2 rounded-[2rem] bg-[#fff2e3] px-6 py-5 text-center text-[#3b2415] shadow-[0_18px_60px_rgba(59,36,21,0.12)]"
			initial={{ opacity: 0, y: 12 }}
			animate={{ opacity: 1, y: 0 }}
			transition={{ duration: 0.24 }}
		>
			<p className="text-xs font-bold uppercase tracking-wide text-[#8a4d22]">
				Encrypted by Sapphire Labs.
			</p>
			<h1 className="mt-2 text-xl font-semibold">
				Private encryption in your browser
			</h1>
			<p className="mt-2 text-sm leading-6 text-[#6f4a31]">
				Create or upload your private key to unlock a local chat workspace for
				encrypting messages, files, and voice notes. Private keys stay in this
				browser session only, and encrypted packages can be copied or downloaded
				for secure sharing.
			</p>
			<p className="mt-3 text-sm font-semibold">
				developed by{" "}
				<a
					className="pointer-events-auto underline decoration-[#8a4d22]/40 underline-offset-4 transition hover:text-black"
					href="https://sapphirelabs.org"
					rel="noreferrer"
					target="_blank"
				>
					sapphirelabs.org
				</a>
			</p>
		</motion.aside>
	);
}

function VoiceRecorderButton({
	isRecording,
	onToggle,
	recordingSeconds,
}: {
	isRecording: boolean;
	onToggle: () => void;
	recordingSeconds: number;
}) {
	return (
		<motion.button
			className={`flex min-h-11 shrink-0 cursor-pointer items-center justify-center rounded-full p-3 transition ${
				isRecording
					? "bg-[#fff2e3] text-[#3b2415] hover:bg-[#f7dfc4]"
					: "text-foreground hover:bg-muted"
			}`}
			layout
			title={isRecording ? "Stop recording" : "Record voice"}
			type="button"
			transition={{
				layout: {
					duration: 0.4,
				},
			}}
			onClick={onToggle}
		>
			<div className="flex size-5 items-center justify-center">
				{isRecording ? (
					<motion.div
						className="size-3.5 rounded-sm bg-[#3b2415]"
						animate={{ rotate: [0, 180, 360] }}
						transition={{
							duration: 2,
							ease: "easeInOut",
							repeat: Number.POSITIVE_INFINITY,
						}}
					/>
				) : (
					<Mic className="size-5" />
				)}
			</div>
			<AnimatePresence mode="wait">
				{isRecording ? (
					<motion.div
						className="flex items-center justify-center gap-2 overflow-hidden"
						initial={{ opacity: 0, width: 0, marginLeft: 0 }}
						animate={{ opacity: 1, width: "auto", marginLeft: 8 }}
						exit={{ opacity: 0, width: 0, marginLeft: 0 }}
						transition={{ duration: 0.4 }}
					>
						<div className="flex items-center justify-center gap-0.5">
							{voiceBars.map((height, index) => (
								<motion.div
									className="w-0.5 rounded-full bg-[#3b2415]"
									key={`${height}-${index}`}
									initial={{ height: 2 }}
									animate={{
										height: [2, height, Math.max(4, height - 3), 2],
									}}
									transition={{
										delay: index * 0.05,
										duration: 1,
										ease: "easeInOut",
										repeat: Number.POSITIVE_INFINITY,
									}}
								/>
							))}
						</div>
						<div className="w-10 text-center text-xs font-semibold text-[#6f4a31]">
							{formatDuration(recordingSeconds)}
						</div>
					</motion.div>
				) : null}
			</AnimatePresence>
		</motion.button>
	);
}

function LockedComposerPanel({
	generatedKey,
	isGenerating,
	isValidatingKey,
	keyPassword,
	keyPasswordConfirm,
	loadKeyFile,
	loadKeyFileName,
	loadKeyPassword,
	mode,
	notice,
	onGenerate,
	onKeyPasswordChange,
	onKeyPasswordConfirmChange,
	onLoadKeyConfirm,
	onLoadKeyPasswordChange,
	onModeChange,
	onPrivateKeyUpload,
	passwordStrength,
}: {
	generatedKey: GeneratedKeyPair | null;
	isGenerating: boolean;
	isValidatingKey: boolean;
	keyPassword: string;
	keyPasswordConfirm: string;
	loadKeyFile: ProtectedPrivateKeyFile | null;
	loadKeyFileName: string;
	loadKeyPassword: string;
	mode: ChatMode;
	notice: Notice | null;
	onGenerate: () => void;
	onKeyPasswordChange: (value: string) => void;
	onKeyPasswordConfirmChange: (value: string) => void;
	onLoadKeyConfirm: () => void;
	onLoadKeyPasswordChange: (value: string) => void;
	onModeChange: (mode: ChatMode) => void;
	onPrivateKeyUpload: (file: File) => Promise<void>;
	passwordStrength: PasswordStrength;
}) {
	return (
		<div className="grid gap-2">
			<div className="grid gap-2 sm:grid-cols-2">
				<button
					className={`button button-pill ${
						mode === "load-key" ? "button-pill-active" : ""
					}`}
					type="button"
					onClick={() => onModeChange("load-key")}
				>
					<Upload className="size-4" />
					Upload key JSON
				</button>
				<button
					className={`button button-pill ${
						mode === "create-key" ? "button-pill-active" : ""
					}`}
					type="button"
					onClick={() => onModeChange("create-key")}
				>
					<KeyRound className="size-4" />
					Create key
				</button>
			</div>

			{mode === "create-key" ? (
				<motion.div
					className="grid gap-2 rounded-2xl border border-border bg-muted/30 p-3"
					initial={{ opacity: 0, y: 12 }}
					animate={{ opacity: 1, y: 0 }}
				>
					<Field label="Private key password">
						<input
							className="field"
							type="password"
							value={keyPassword}
							autoComplete="new-password"
							placeholder="Choose a strong password"
							onChange={(event) => onKeyPasswordChange(event.target.value)}
						/>
						{keyPassword ? (
							<PasswordStrengthMeter strength={passwordStrength} />
						) : null}
					</Field>
					<Field label="Confirm private key password">
						<input
							className="field"
							type="password"
							value={keyPasswordConfirm}
							autoComplete="new-password"
							placeholder="Repeat the same password"
							onChange={(event) =>
								onKeyPasswordConfirmChange(event.target.value)
							}
						/>
					</Field>
					<p className="rounded-xl bg-amber-50 px-3 py-2 text-xs font-medium leading-5 text-amber-800">
						Save the key file and password. They cannot be recovered.
					</p>
					<button
						className="button button-primary"
						type="button"
						disabled={isGenerating}
						onClick={onGenerate}
					>
						<KeyRound className="size-4" />
						{isGenerating ? "Generating..." : "Generate and unlock chat"}
					</button>
					{generatedKey ? (
						<button
							className="button button-download"
							type="button"
							onClick={() =>
								downloadText(
									generatedKey.privateKeyFileName,
									stringifyJson(generatedKey.privateKeyFile),
									"application/json",
								)
							}
						>
							<Download className="size-4" />
							Download private key
						</button>
					) : null}
				</motion.div>
			) : null}

			{mode === "load-key" ? (
				<motion.div
					className="grid gap-2 rounded-2xl border border-border bg-muted/30 p-3"
					initial={{ opacity: 0, y: 12 }}
					animate={{ opacity: 1, y: 0 }}
				>
					<JsonDropzone
						acceptLabel="Private key JSON"
						fileName={loadKeyFileName}
						onUpload={onPrivateKeyUpload}
					/>
					{loadKeyFile ? (
						<p className="truncate rounded-full bg-white px-3 py-1.5 text-xs font-mono text-muted-foreground">
							{getPublicAddressFingerprint(loadKeyFile.publicAddress)}
						</p>
					) : null}
					<Field label="Private key password">
						<input
							className="field"
							type="password"
							value={loadKeyPassword}
							autoComplete="current-password"
							placeholder="Password for this private key"
							onChange={(event) => onLoadKeyPasswordChange(event.target.value)}
						/>
					</Field>
					<button
						className="button button-primary"
						type="button"
						disabled={isValidatingKey}
						onClick={onLoadKeyConfirm}
					>
						<Unlock className="size-4" />
						{isValidatingKey ? "Unlocking..." : "Unlock chat"}
					</button>
				</motion.div>
			) : null}
			<NoticeBox notice={notice} />
		</div>
	);
}

function AttachmentStrip({
	attachments,
	isRecording,
	onCancelRecording,
	onRemoveAttachment,
	recordingSeconds,
}: {
	attachments: AttachmentDraft[];
	isRecording: boolean;
	onCancelRecording: () => void;
	onRemoveAttachment: (id: string) => void;
	recordingSeconds: number;
}) {
	return (
		<div className="flex flex-wrap items-center gap-2 pt-3">
			{attachments.map((attachment) => (
				<span
					className="inline-flex max-w-full items-center gap-2 rounded-full bg-muted px-3 py-1 text-xs font-semibold"
					key={attachment.id}
				>
					<FileText className="size-3 shrink-0" />
					<span className="max-w-48 truncate">{attachment.name}</span>
					<span className="text-muted-foreground">
						{formatFileSize(attachment.size)}
					</span>
					<button
						className="text-muted-foreground hover:text-foreground"
						type="button"
						title="Remove attachment"
						onClick={() => onRemoveAttachment(attachment.id)}
					>
						<X className="size-3" />
					</button>
				</span>
			))}
			{isRecording ? (
				<span className="inline-flex items-center gap-2 rounded-full border border-red-200 bg-red-50 px-3 py-1 text-xs font-semibold text-red-700">
					<span className="size-2 rounded-full bg-red-600" />
					Recording {formatDuration(recordingSeconds)}
					<button type="button" onClick={onCancelRecording}>
						Cancel
					</button>
				</span>
			) : null}
		</div>
	);
}

function UnlockedComposerPanel({
	attachments,
	isRecording,
	mode,
	notice,
	onAddressBook,
	onClearChat,
	onPackageTextChange,
	onPackageUpload,
	onRecipientAddressChange,
	packageFileName,
	packageInspection,
	packageText,
	recipientAddress,
	recipientFingerprint,
	recordingSeconds,
	sessionKey,
	onCancelRecording,
	onRemoveAttachment,
}: {
	attachments: AttachmentDraft[];
	isRecording: boolean;
	mode: ChatMode;
	notice: Notice | null;
	onAddressBook: () => void;
	onClearChat: () => void;
	onPackageTextChange: (value: string) => void;
	onPackageUpload: (file: File) => Promise<void>;
	onRecipientAddressChange: (value: string) => void;
	packageFileName: string;
	packageInspection: PackageInspection | null;
	packageText: string;
	recipientAddress: string;
	recipientFingerprint: string;
	recordingSeconds: number;
	sessionKey: SessionKeyState;
	onCancelRecording: () => void;
	onRemoveAttachment: (id: string) => void;
}) {
	return (
		<div className="grid gap-2">
			<div className="flex items-center justify-between gap-3">
				<span className="inline-flex min-w-0 items-center gap-2 rounded-full bg-muted px-3 py-1.5 text-xs font-semibold text-foreground">
					Key ready
					<span className="font-mono text-muted-foreground">
						{sessionKey.fingerprint}
					</span>
				</span>
				<button
					className="icon-button"
					title="Clear chat"
					type="button"
					onClick={onClearChat}
				>
					<Eraser className="size-4" />
				</button>
			</div>

			{mode === "encrypt" ? (
				<div className="grid gap-2">
					<Field label="Recipient public address">
						<div className="flex items-center gap-2 rounded-full bg-muted p-1">
							<input
								className="min-w-0 flex-1 rounded-full border-0 bg-white px-4 py-3 font-mono text-xs text-foreground outline-none transition focus:ring-2 focus:ring-black/10"
								value={recipientAddress}
								placeholder="Paste recipient public address"
								onChange={(event) =>
									onRecipientAddressChange(event.target.value)
								}
							/>
							<button
								className="icon-button shrink-0 bg-white text-muted-foreground hover:bg-[#fff2e3] hover:text-[#3b2415]"
								title="Load from address book"
								type="button"
								onClick={onAddressBook}
							>
								<BookUser className="size-4" />
							</button>
						</div>
						{recipientFingerprint ? (
							<span className="inline-flex w-fit rounded-full bg-[#fff2e3] px-3 py-1.5 font-mono text-xs font-semibold text-[#6f4a31]">
								{recipientFingerprint}
							</span>
						) : null}
					</Field>
					{attachments.length > 0 || isRecording ? (
						<AttachmentStrip
							attachments={attachments}
							isRecording={isRecording}
							recordingSeconds={recordingSeconds}
							onCancelRecording={onCancelRecording}
							onRemoveAttachment={onRemoveAttachment}
						/>
					) : null}
				</div>
			) : null}

			{mode === "decrypt" ? (
				<div className="grid gap-3">
					<JsonDropzone
						acceptLabel="Drop encrypted package JSON here"
						fileName={packageFileName}
						onUpload={onPackageUpload}
					/>
					<Field label="Encrypted package JSON">
						<textarea
							className="field min-h-32 resize-y font-mono text-xs"
							value={packageText}
							placeholder="Paste encrypted package JSON"
							onChange={(event) => onPackageTextChange(event.target.value)}
						/>
					</Field>
					<PackageInspectionPanel inspection={packageInspection} />
				</div>
			) : null}

			<NoticeBox notice={notice} />
		</div>
	);
}

function ChatMessageView({
	message,
	onCopyNotice,
}: {
	message: ChatMessage;
	onCopyNotice: (notice: Notice) => void;
}) {
	const isUser = message.role === "user";
	const motionProps = {
		initial: { opacity: 0, y: 12 },
		animate: { opacity: 1, y: 0 },
		exit: { opacity: 0, y: -8 },
		transition: { duration: 0.22 },
	};

	if (message.type === "notice") {
		return (
			<motion.div className="flex justify-start" {...motionProps}>
				<div className="max-w-[min(100%,52rem)]">
					<NoticeBox notice={message.notice ?? null} />
				</div>
			</motion.div>
		);
	}

	if (message.type === "encrypted") {
		return (
			<motion.div className="flex justify-start" {...motionProps}>
				<PackageResultCard
					message={message as EncryptedChatMessage}
					onCopyNotice={onCopyNotice}
				/>
			</motion.div>
		);
	}

	if (message.type === "decrypted") {
		return (
			<motion.div className="flex justify-start" {...motionProps}>
				<DecryptionResultCard
					message={message as DecryptedChatMessage}
					onCopyNotice={onCopyNotice}
				/>
			</motion.div>
		);
	}

	return (
		<motion.div
			className={`flex ${isUser ? "justify-end" : "justify-start"}`}
			{...motionProps}
		>
			<div
				className={`max-w-[min(100%,52rem)] rounded-[1.75rem] px-4 py-3 ${
					isUser ? "bg-black text-white" : "bg-[#fff2e3] text-[#3b2415]"
				}`}
			>
				{message.type === "guide" ? (
					<p className="whitespace-pre-wrap text-sm leading-6 text-[#3b2415]">
						{message.text ?? ""}
					</p>
				) : null}

				{message.type === "text" ? (
					<p className="whitespace-pre-wrap text-sm leading-6">
						{message.text ?? ""}
					</p>
				) : null}

				{message.type === "typing" ? <TypingDots /> : null}
			</div>
		</motion.div>
	);
}

function PackageResultCard({
	message,
}: {
	message: EncryptedChatMessage;
	onCopyNotice: (notice: Notice) => void;
}) {
	return (
		<div className="grid w-full max-w-[min(100%,52rem)] gap-3">
			<CodeSnippet text={message.result.packageText} />
			<button
				className="button button-download justify-self-start"
				type="button"
				onClick={() =>
					downloadText(
						`sapphire-message-${message.result.messageHash.slice(0, 12)}.json`,
						message.result.packageText,
						"application/json",
					)
				}
			>
				<Download className="size-4" />
				Download JSON
			</button>
		</div>
	);
}

function DecryptionResultCard({
	message,
}: {
	message: DecryptedChatMessage;
	onCopyNotice: (notice: Notice) => void;
}) {
	const text = message.result.payload.text ?? "";

	return (
		<div className="grid w-full max-w-[min(100%,52rem)] gap-3">
			{text ? <CodeSnippet text={text} /> : null}
			{message.result.payload.attachments.length > 0 ? (
				<DecryptedAttachmentList
					attachments={message.result.payload.attachments}
				/>
			) : null}
			<CopySnippet
				text={[
					`Sender: ${getPublicAddressFingerprint(
						message.result.senderAddress,
					)}`,
					`Hash: ${message.result.messageHash}`,
				]}
				prompt={false}
			/>
		</div>
	);
}

function CodeSnippet({ text }: { text: string }) {
	const [copied, setCopied] = useState(false);

	async function handleCopy() {
		await navigator.clipboard.writeText(text);
		setCopied(true);
		window.setTimeout(() => setCopied(false), 1600);
	}

	return (
		<div className="relative overflow-hidden rounded-[1.75rem] bg-[#fff2e3] text-[#3b2415]">
			<button
				className="absolute right-2 top-2 z-10 inline-flex size-9 items-center justify-center rounded-full bg-[#3b2415] text-[#fff2e3] transition hover:bg-black"
				type="button"
				title="Copy"
				onClick={() => void handleCopy()}
			>
				{copied ? <Check className="size-4" /> : <Copy className="size-4" />}
			</button>
			<pre className="max-h-80 overflow-auto whitespace-pre-wrap break-words p-4 pr-14 font-mono text-xs leading-5 text-[#3b2415]">
				<code>{text}</code>
			</pre>
		</div>
	);
}

function DecryptedAttachmentList({
	attachments,
}: {
	attachments: EncryptedAttachment[];
}) {
	return (
		<div className="grid gap-2">
			{attachments.map((attachment) => {
				const isAudio = attachment.type.startsWith("audio/");
				const previewUrl = `data:${
					attachment.type || "application/octet-stream"
				};base64,${attachment.dataBase64}`;

				return (
					<div
						className="grid gap-2 rounded-[1.75rem] bg-[#fff2e3] p-3 text-[#3b2415]"
						key={attachment.id}
					>
						<div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
							<div className="min-w-0">
								<p className="truncate text-sm font-semibold">
									{attachment.name}
								</p>
								<p className="text-xs text-muted-foreground">
									{attachment.type || "application/octet-stream"} ·{" "}
									{formatFileSize(attachment.size)}
								</p>
							</div>
							<button
								className="button button-download shrink-0"
								type="button"
								onClick={() => {
									const url = URL.createObjectURL(
										base64PayloadToBlob(attachment),
									);
									downloadUrl(url, attachment.name);
									window.setTimeout(() => URL.revokeObjectURL(url), 0);
								}}
							>
								<Download className="size-4" />
								Download
							</button>
						</div>
						{isAudio ? (
							<audio className="w-full" controls src={previewUrl}>
								<track kind="captions" />
							</audio>
						) : null}
					</div>
				);
			})}
		</div>
	);
}

function JsonDropzone({
	acceptLabel,
	fileName,
	onUpload,
}: {
	acceptLabel: string;
	fileName: string;
	onUpload: (file: File) => Promise<void>;
}) {
	const fileInputRef = useRef<HTMLInputElement>(null);
	const [dragging, setDragging] = useState(false);

	const handleFile = useCallback(
		(file: File | undefined) => {
			if (!file) {
				return;
			}

			void onUpload(file);
		},
		[onUpload],
	);

	function handleDrop(event: DragEvent<HTMLDivElement>) {
		event.preventDefault();
		setDragging(false);
		handleFile(event.dataTransfer.files[0]);
	}

	if (fileName) {
		return (
			<div
				className={`flex cursor-pointer items-center justify-between gap-3 rounded-2xl border px-3 py-2 transition ${
					dragging
						? "border-primary bg-muted"
						: "border-border bg-white hover:bg-muted/45"
				}`}
				role="button"
				tabIndex={0}
				onClick={() => fileInputRef.current?.click()}
				onDragLeave={() => setDragging(false)}
				onDragOver={(event) => {
					event.preventDefault();
					setDragging(true);
				}}
				onDrop={handleDrop}
				onKeyDown={(event) => {
					if (event.key === "Enter" || event.key === " ") {
						fileInputRef.current?.click();
					}
				}}
			>
				<input
					ref={fileInputRef}
					className="sr-only"
					type="file"
					accept="application/json,.json"
					onChange={(event: ChangeEvent<HTMLInputElement>) => {
						handleFile(event.target.files?.[0]);
						event.currentTarget.value = "";
					}}
				/>
				<span className="inline-flex min-w-0 items-center gap-2 text-sm font-semibold">
					<CircleCheck className="size-4 shrink-0 text-emerald-600" />
					<span className="truncate">{fileName}</span>
				</span>
				<span className="shrink-0 rounded-full bg-muted px-3 py-1 text-xs font-semibold text-muted-foreground">
					Replace
				</span>
			</div>
		);
	}

	return (
		<div
			className={`flex cursor-pointer items-center justify-between gap-3 rounded-2xl border px-3 py-3 transition ${
				dragging
					? "border-primary bg-muted"
					: "border-border bg-white hover:bg-muted/45"
			}`}
			role="button"
			tabIndex={0}
			onClick={() => fileInputRef.current?.click()}
			onDragLeave={() => setDragging(false)}
			onDragOver={(event) => {
				event.preventDefault();
				setDragging(true);
			}}
			onDrop={handleDrop}
			onKeyDown={(event) => {
				if (event.key === "Enter" || event.key === " ") {
					fileInputRef.current?.click();
				}
			}}
		>
			<input
				ref={fileInputRef}
				className="sr-only"
				type="file"
				accept="application/json,.json"
				onChange={(event: ChangeEvent<HTMLInputElement>) => {
					handleFile(event.target.files?.[0]);
					event.currentTarget.value = "";
				}}
			/>
			<span className="inline-flex min-w-0 items-center gap-2 text-sm font-semibold">
				<FileJson className="size-4 shrink-0 text-muted-foreground" />
				<span>{acceptLabel}</span>
			</span>
			<span className="shrink-0 rounded-full bg-muted px-3 py-1 text-xs font-semibold text-muted-foreground">
				Browse
			</span>
		</div>
	);
}

function CopySnippet({
	prompt = true,
	text,
}: {
	prompt?: boolean;
	text: string | string[];
}) {
	const [copied, setCopied] = useState(false);
	const values = Array.isArray(text) ? text : [text];

	async function handleCopy() {
		await navigator.clipboard.writeText(values.join("\n"));
		setCopied(true);
		window.setTimeout(() => setCopied(false), 1600);
	}

	return (
		<div className="flex gap-3 rounded-[1.75rem] bg-[#fff2e3] px-3 py-2.5 text-[#3b2415]">
			<div className="min-w-0 flex-1">
				{values.map((item) => (
					<div
						className="break-all font-mono text-[13px] leading-5 text-[#3b2415]"
						key={item}
					>
						{prompt ? "$ " : ""}
						{item}
					</div>
				))}
			</div>
			<button
				className="icon-button shrink-0"
				type="button"
				title="Copy"
				onClick={() => void handleCopy()}
			>
				{copied ? <Check className="size-4" /> : <Copy className="size-4" />}
			</button>
		</div>
	);
}

function TypingDots({ compact = false }: { compact?: boolean }) {
	return (
		<span
			className={`inline-flex items-center gap-1 ${compact ? "" : "px-1 py-2"}`}
			aria-label="Loading"
		>
			{[0, 1, 2].map((item) => (
				<motion.span
					className={`rounded-full bg-current ${compact ? "size-1" : "size-2"}`}
					key={item}
					animate={{ opacity: [0.25, 1, 0.25], y: [0, -3, 0] }}
					transition={{ duration: 0.9, repeat: Infinity, delay: item * 0.12 }}
				/>
			))}
		</span>
	);
}

function Field({ children, label }: { children: ReactNode; label: string }) {
	return (
		<label className="grid gap-2 text-sm font-semibold">
			<span>{label}</span>
			{children}
		</label>
	);
}

function PasswordStrengthMeter({ strength }: { strength: PasswordStrength }) {
	return (
		<div className="grid gap-1.5">
			<div className="grid grid-cols-4 gap-1">
				{Array.from({ length: 4 }).map((_, index) => (
					<span
						className={`h-1.5 rounded-full ${
							index < strength.score ? strength.className : "bg-muted"
						}`}
						key={index}
					/>
				))}
			</div>
			<span className="text-xs font-semibold text-muted-foreground">
				Password strength: {strength.label}
			</span>
		</div>
	);
}

function PackageInspectionPanel({
	inspection,
}: {
	inspection: PackageInspection | null;
}) {
	if (!inspection) {
		return (
			<div className="rounded-md border border-dashed border-border bg-white px-3 py-3 text-sm text-muted-foreground">
				Paste or upload a package to inspect hash, sender, and recipient before
				decrypting.
			</div>
		);
	}

	const safe = inspection.hashValid && inspection.signatureValid;

	return (
		<div
			className={`grid gap-2 rounded-md border px-3 py-3 text-sm ${
				safe ? "border-emerald-200 bg-emerald-50" : "border-red-200 bg-red-50"
			}`}
		>
			<div className="flex items-center gap-2 font-semibold">
				{safe ? (
					<CircleCheck className="size-4 text-emerald-700" />
				) : (
					<CircleAlert className="size-4 text-red-700" />
				)}
				{safe ? "Package checks passed" : "Package failed checks"}
			</div>
			<CopySnippet text={`Hash: ${inspection.messageHash}`} prompt={false} />
			<CopySnippet
				text={[
					`Sender: ${inspection.senderFingerprint}`,
					`Recipient: ${inspection.recipientFingerprint}`,
				]}
				prompt={false}
			/>
		</div>
	);
}

function AddressBookModal({
	address,
	emoji,
	editingAddressId,
	entries,
	name,
	notice,
	onAddressChange,
	onCancelEdit,
	onClose,
	onCopy,
	onDelete,
	onEdit,
	onEmojiChange,
	onImport,
	onNameChange,
	onSave,
	onTrustChange,
	onTrustStatusChange,
	onUse,
	open,
	trustStatus,
}: {
	address: string;
	emoji: string;
	editingAddressId: string | null;
	entries: AddressBookEntry[];
	name: string;
	notice: Notice | null;
	onAddressChange: (value: string) => void;
	onCancelEdit: () => void;
	onClose: () => void;
	onCopy: (value: string) => void;
	onDelete: (id: string) => void;
	onEdit: (entry: AddressBookEntry) => void;
	onEmojiChange: (value: string) => void;
	onImport: (file: File | undefined) => Promise<void>;
	onNameChange: (value: string) => void;
	onSave: () => void;
	onTrustChange: (id: string, trustStatus: TrustStatus) => void;
	onTrustStatusChange: (value: TrustStatus) => void;
	onUse: (address: string) => void;
	open: boolean;
	trustStatus: TrustStatus;
}) {
	const [activeTab, setActiveTab] = useState<"list" | "save">("list");
	const [columnFilters, setColumnFilters] = useState({
		address: "",
		id: "",
		name: "",
		trustStatus: "",
	});
	const [sortConfig, setSortConfig] = useState<{
		key: "id" | "name" | "address";
		direction: "asc" | "desc";
	}>({ key: "id", direction: "asc" });
	const [page, setPage] = useState(1);

	const filteredEntries = useMemo(() => {
		return entries.filter((entry) => {
			const matchesId = columnFilters.id
				? entry.id.toLowerCase().includes(columnFilters.id.toLowerCase())
				: true;
			const matchesName = columnFilters.name
				? entry.name.toLowerCase().includes(columnFilters.name.toLowerCase())
				: true;
			const matchesAddress = columnFilters.address
				? entry.address
						.toLowerCase()
						.includes(columnFilters.address.toLowerCase())
				: true;
			const matchesTrustStatus = columnFilters.trustStatus
				? entry.trustStatus
						.toLowerCase()
						.includes(columnFilters.trustStatus.toLowerCase())
				: true;

			return matchesId && matchesName && matchesAddress && matchesTrustStatus;
		});
	}, [columnFilters, entries]);

	const sortedEntries = useMemo(() => {
		return [...filteredEntries].sort((left, right) => {
			const leftValue =
				sortConfig.key === "id"
					? left.id
					: sortConfig.key === "name"
					? left.name || ""
					: left.address;
			const rightValue =
				sortConfig.key === "id"
					? right.id
					: sortConfig.key === "name"
					? right.name || ""
					: right.address;

			return sortConfig.direction === "asc"
				? leftValue.localeCompare(rightValue)
				: rightValue.localeCompare(leftValue);
		});
	}, [filteredEntries, sortConfig]);

	const itemsPerPage = 6;
	const totalPages = Math.max(
		1,
		Math.ceil(sortedEntries.length / itemsPerPage),
	);
	const currentPage = Math.min(page, totalPages);
	const paginatedEntries = useMemo(() => {
		const start = (currentPage - 1) * itemsPerPage;
		return sortedEntries.slice(start, start + itemsPerPage);
	}, [currentPage, sortedEntries]);

	if (!open) {
		return null;
	}

	const setColumnFilter = (
		key: "id" | "name" | "address" | "trustStatus",
		value: string,
	) => {
		setPage(1);
		setColumnFilters((current) => ({ ...current, [key]: value }));
	};

	const toggleSort = (key: "id" | "name" | "address") => {
		setSortConfig((current) => ({
			key,
			direction:
				current.key === key && current.direction === "asc" ? "desc" : "asc",
		}));
	};

	const handleClose = () => {
		setActiveTab("list");
		setColumnFilters({ address: "", id: "", name: "", trustStatus: "" });
		setPage(1);
		onClose();
	};

	return (
		<div className="fixed inset-0 z-[120] overflow-y-auto bg-black/25 p-2 sm:p-3">
			<section
				aria-labelledby="address-book-title"
				aria-modal="true"
				className="mx-auto flex h-[calc(100svh-1rem)] w-full max-w-7xl flex-col gap-3 overflow-hidden rounded-[2rem] bg-background p-3 shadow-[0_24px_80px_rgba(0,0,0,0.16)] sm:h-[calc(100svh-1.5rem)] sm:p-4"
				role="dialog"
			>
				<div className="flex shrink-0 flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
					<div className="min-w-0">
						<p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
							Local only
						</p>
						<h2 id="address-book-title" className="mt-1 text-xl font-semibold">
							Address Book
						</h2>
						<p className="mt-1.5 max-w-2xl text-sm leading-6 text-muted-foreground">
							Save public addresses in this browser with a name and emoji for
							easier recognition. This never stores private keys.
						</p>
					</div>
					<button
						className="button button-pill shrink-0"
						type="button"
						onClick={handleClose}
					>
						<X className="size-4" />
						Close
					</button>
				</div>

				<div className="step-tabs grid w-full shrink-0 grid-cols-2">
					<button
						className={`step-tab ${
							activeTab === "list" ? "step-tab-active" : ""
						}`}
						type="button"
						onClick={() => setActiveTab("list")}
					>
						<BookOpen className="size-4 shrink-0" />
						<span className="step-tab-label">Address list</span>
					</button>
					<button
						className={`step-tab ${
							activeTab === "save" ? "step-tab-active" : ""
						}`}
						type="button"
						onClick={() => setActiveTab("save")}
					>
						<Plus className="size-4 shrink-0" />
						<span className="step-tab-label">
							{editingAddressId ? "Edit address" : "Save address"}
						</span>
					</button>
				</div>

				<div className="min-h-0 flex-1 overflow-y-auto">
					{activeTab === "list" ? (
						<section className="grid content-start gap-2">
							<div className="flex justify-end">
								<div className="flex items-center gap-1">
									<label
										aria-label="Import contacts"
										className="icon-button cursor-pointer"
										title="Import contacts"
									>
										<Upload className="size-4" />
										<input
											className="sr-only"
											type="file"
											accept=".json,.csv,application/json,text/csv"
											onChange={(event) =>
												void onImport(event.target.files?.[0]).finally(() => {
													event.currentTarget.value = "";
												})
											}
										/>
									</label>
									<button
										aria-label="Download address book as JSON"
										className="icon-button"
										title="Download JSON"
										type="button"
										onClick={() =>
											downloadText(
												`sapphire-address-book-${formatDateToken()}.json`,
												stringifyJson(entries),
												"application/json",
											)
										}
									>
										<Download className="size-4" />
									</button>
									<button
										aria-label="Download address book as CSV"
										className="icon-button"
										title="Download CSV"
										type="button"
										onClick={() =>
											downloadText(
												`sapphire-address-book-${formatDateToken()}.csv`,
												convertAddressBookEntriesToCsv(entries),
												"text/csv;charset=utf-8",
											)
										}
									>
										<FileText className="size-4" />
									</button>
								</div>
							</div>

							<div className="overflow-hidden rounded-[1.75rem] bg-white">
								<div className="overflow-x-auto">
									<table className="w-full min-w-[980px]">
										<thead className="bg-muted/60">
											<tr>
												<AddressBookTableHead
													activeKey={sortConfig.key}
													direction={sortConfig.direction}
													filterValue={columnFilters.id}
													label="ID"
													sortKey="id"
													onFilterChange={setColumnFilter}
													onSort={toggleSort}
												/>
												<AddressBookTableHead
													activeKey={sortConfig.key}
													direction={sortConfig.direction}
													filterValue={columnFilters.name}
													label="Name"
													sortKey="name"
													onFilterChange={setColumnFilter}
													onSort={toggleSort}
												/>
												<AddressBookTableHead
													activeKey={sortConfig.key}
													direction={sortConfig.direction}
													filterValue={columnFilters.address}
													label="Address"
													sortKey="address"
													onFilterChange={setColumnFilter}
													onSort={toggleSort}
												/>
												<AddressBookTableHead
													filterValue={columnFilters.trustStatus}
													label="Trust"
													sortKey="trustStatus"
													onFilterChange={setColumnFilter}
													onSort={toggleSort}
												/>
												<th className="px-3 py-3 text-right text-sm font-semibold text-muted-foreground">
													Actions
												</th>
											</tr>
										</thead>
										<tbody className="bg-white">
											{paginatedEntries.length > 0 ? (
												paginatedEntries.map((entry) => (
													<tr
														className="border-t border-border transition-colors hover:bg-muted/35"
														key={entry.id}
													>
														<td className="px-3 py-3 align-top text-sm">
															{entry.id.slice(0, 8)}
														</td>
														<td className="px-3 py-3 align-top text-sm">
															<div className="flex items-center gap-3">
																<span className="inline-flex size-8 items-center justify-center rounded-full bg-muted text-sm">
																	{entry.emoji}
																</span>
																<div className="min-w-0">
																	<p className="font-semibold">
																		{entry.name || "Unnamed contact"}
																	</p>
																	<p className="text-xs text-muted-foreground">
																		Saved locally
																	</p>
																</div>
															</div>
														</td>
														<td className="px-3 py-3 align-top text-sm text-muted-foreground">
															<p className="break-all font-mono text-xs leading-5">
																{entry.address}
															</p>
															<p className="mt-1 text-xs font-semibold text-foreground">
																{getPublicAddressFingerprint(entry.address)}
															</p>
														</td>
														<td className="px-3 py-3 align-top">
															<TrustStatusSelect
																value={entry.trustStatus}
																onChange={(value) =>
																	onTrustChange(entry.id, value)
																}
															/>
														</td>
														<td className="px-3 py-3 align-top">
															<div className="flex flex-wrap justify-end gap-1">
																<button
																	className="icon-button bg-black text-white hover:bg-zinc-700 hover:text-white"
																	title="Use this address"
																	type="button"
																	onClick={() => onUse(entry.address)}
																>
																	<Send className="size-4" />
																</button>
																<button
																	className="icon-button"
																	title="Edit"
																	type="button"
																	onClick={() => {
																		onEdit(entry);
																		setActiveTab("save");
																	}}
																>
																	<Edit3 className="size-4" />
																</button>
																<button
																	className="icon-button"
																	title="Copy"
																	type="button"
																	onClick={() => onCopy(entry.address)}
																>
																	<Copy className="size-4" />
																</button>
																<button
																	className="icon-button"
																	title="Download contact"
																	type="button"
																	onClick={() =>
																		downloadText(
																			`sapphire-contact-${entry.id}.json`,
																			stringifyJson(entry),
																			"application/json",
																		)
																	}
																>
																	<Download className="size-4" />
																</button>
																<button
																	className="icon-button text-red-600 hover:bg-red-50 hover:text-red-700"
																	title="Delete"
																	type="button"
																	onClick={() => onDelete(entry.id)}
																>
																	<Trash2 className="size-4" />
																</button>
															</div>
														</td>
													</tr>
												))
											) : (
												<tr>
													<td
														className="px-3 py-8 text-center text-sm text-muted-foreground"
														colSpan={5}
													>
														No contacts match the current filters.
													</td>
												</tr>
											)}
										</tbody>
									</table>
								</div>
								<div className="flex flex-col gap-3 border-t border-border bg-white px-3 py-3 sm:flex-row sm:items-center sm:justify-between">
									<p className="text-sm text-muted-foreground">
										Showing{" "}
										{sortedEntries.length === 0
											? 0
											: (currentPage - 1) * itemsPerPage + 1}{" "}
										to{" "}
										{Math.min(currentPage * itemsPerPage, sortedEntries.length)}{" "}
										of {sortedEntries.length} contacts
									</p>
									<div className="flex items-center gap-2">
										<button
											className="button button-pill px-3"
											type="button"
											disabled={currentPage === 1}
											onClick={() =>
												setPage((current) => Math.max(1, current - 1))
											}
										>
											Previous
										</button>
										<span className="rounded-full bg-muted px-3 py-2 text-sm font-semibold">
											{currentPage} / {totalPages}
										</span>
										<button
											className="button button-pill px-3"
											type="button"
											disabled={currentPage === totalPages}
											onClick={() =>
												setPage((current) => Math.min(totalPages, current + 1))
											}
										>
											Next
										</button>
									</div>
								</div>
							</div>
							<NoticeBox notice={notice} />
						</section>
					) : (
						<section className="grid content-start gap-3 rounded-[1.75rem] bg-white p-3">
							<div className="grid gap-3 rounded-[1.5rem] bg-white p-3">
								<div className="flex items-center gap-2 text-sm font-semibold">
									<UserPlus className="size-4" />
									{editingAddressId ? "Edit address" : "Save address"}
								</div>
								<Field label="Emoji">
									<select
										className="field max-w-32"
										value={emoji}
										onChange={(event) => onEmojiChange(event.target.value)}
									>
										{addressBookEmojiOptions.map((option) => (
											<option key={option} value={option}>
												{option}
											</option>
										))}
									</select>
								</Field>
								<Field label="Name">
									<input
										className="field"
										value={name}
										placeholder="Contact name"
										onChange={(event) => onNameChange(event.target.value)}
									/>
								</Field>
								<Field label="Trust status">
									<TrustStatusSelect
										value={trustStatus}
										onChange={onTrustStatusChange}
									/>
								</Field>
								<Field label="Public address">
									<textarea
										className="field min-h-32 resize-y font-mono text-xs leading-5"
										value={address}
										placeholder="Public address"
										onChange={(event) => onAddressChange(event.target.value)}
									/>
								</Field>
								<div className="grid gap-2 pt-1 sm:grid-cols-[minmax(0,1fr)_auto]">
									<button
										className="button button-primary"
										type="button"
										onClick={onSave}
									>
										{editingAddressId ? (
											<>
												<Check className="size-4" />
												Save changes
											</>
										) : (
											<>
												<Plus className="size-4" />
												Save address
											</>
										)}
									</button>
									<button
										className="button button-pill sm:min-w-32"
										type="button"
										onClick={onCancelEdit}
									>
										<X className="size-4" />
										Clear
									</button>
								</div>
							</div>
							<NoticeBox notice={notice} />
						</section>
					)}
				</div>
			</section>
		</div>
	);
}

function AddressBookTableHead({
	activeKey,
	direction,
	filterValue,
	label,
	onFilterChange,
	onSort,
	sortKey,
}: {
	activeKey?: "id" | "name" | "address";
	direction?: "asc" | "desc";
	filterValue: string;
	label: string;
	onFilterChange: (
		key: "id" | "name" | "address" | "trustStatus",
		value: string,
	) => void;
	onSort: (key: "id" | "name" | "address") => void;
	sortKey: "id" | "name" | "address" | "trustStatus";
}) {
	const isActive = activeKey === sortKey;
	const sortable = sortKey !== "trustStatus";

	return (
		<th className="px-3 py-3 text-left text-sm font-semibold text-muted-foreground">
			<button
				className="flex w-full items-center gap-2 text-left transition-colors hover:text-foreground disabled:hover:text-muted-foreground"
				disabled={!sortable}
				type="button"
				onClick={() => {
					if (sortable) {
						onSort(sortKey);
					}
				}}
			>
				<span>{label}</span>
				{sortable ? (
					<span className="flex flex-col">
						<ChevronUp
							className={`size-3 ${
								isActive && direction === "asc"
									? "text-primary"
									: "text-muted-foreground/40"
							}`}
						/>
						<ChevronDown
							className={`-mt-1 size-3 ${
								isActive && direction === "desc"
									? "text-primary"
									: "text-muted-foreground/40"
							}`}
						/>
					</span>
				) : null}
			</button>
			<div className="relative mt-2">
				<Search className="pointer-events-none absolute left-2 top-1/2 size-3 -translate-y-1/2 text-muted-foreground/60" />
				<input
					className="w-full rounded-md border border-border bg-white py-1.5 pl-7 pr-2 text-xs font-medium text-foreground outline-none transition focus:border-ring focus:ring-2 focus:ring-black/10"
					type="text"
					value={filterValue}
					placeholder="Filter..."
					onChange={(event) => onFilterChange(sortKey, event.target.value)}
				/>
			</div>
		</th>
	);
}

function NoticeBox({ notice }: { notice: Notice | null }) {
	if (!notice) {
		return null;
	}

	const toneClass = {
		error: "border-red-200 bg-red-50 text-red-800",
		info: "border-border bg-muted text-muted-foreground",
		success: "border-emerald-200 bg-emerald-50 text-emerald-800",
	}[notice.tone];
	const Icon = notice.tone === "error" ? CircleAlert : CircleCheck;

	return (
		<p
			className={`flex items-start gap-2 rounded-2xl border px-3 py-2.5 text-sm leading-5 shadow-sm ${toneClass}`}
		>
			<Icon className="mt-0.5 size-4 shrink-0" />
			{notice.message}
		</p>
	);
}

function TrustStatusSelect({
	onChange,
	value,
}: {
	onChange: (value: TrustStatus) => void;
	value: TrustStatus;
}) {
	return (
		<select
			className={`field py-1.5 text-xs font-semibold ${getTrustStatusClass(
				value,
			)}`}
			value={value}
			onChange={(event) => onChange(sanitizeTrustStatus(event.target.value))}
		>
			{trustStatusOptions.map((option) => (
				<option key={option} value={option}>
					{formatTrustStatus(option)}
				</option>
			))}
		</select>
	);
}

async function copyText(
	value: string,
	setCopyNotice: (notice: Notice) => void,
) {
	try {
		await navigator.clipboard.writeText(value);
		setCopyNotice({ tone: "success", message: "Copied to clipboard." });
	} catch {
		setCopyNotice({ tone: "error", message: "Clipboard copy failed." });
	}
}

async function fileToBase64Payload(file: File): Promise<AttachmentDraft> {
	const dataUrl = await readFileAsDataUrl(file);
	const dataBase64 = dataUrl.includes(",")
		? dataUrl.split(",")[1] ?? ""
		: dataUrl;

	return {
		dataBase64,
		id: crypto.randomUUID(),
		name: file.name || "attachment",
		size: file.size,
		type: file.type || "application/octet-stream",
	};
}

function stripAttachmentDraft(
	attachment: AttachmentDraft,
): EncryptedAttachment {
	return {
		dataBase64: attachment.dataBase64,
		id: attachment.id,
		name: attachment.name,
		size: attachment.size,
		type: attachment.type,
	};
}

function readFileAsDataUrl(file: File): Promise<string> {
	return new Promise((resolve, reject) => {
		const reader = new FileReader();
		reader.onload = () => resolve(String(reader.result ?? ""));
		reader.onerror = () => reject(new Error("Could not read this file."));
		reader.readAsDataURL(file);
	});
}

function base64PayloadToBlob(attachment: EncryptedAttachment): Blob {
	const binary = atob(attachment.dataBase64);
	const bytes = new Uint8Array(binary.length);

	for (let index = 0; index < binary.length; index += 1) {
		bytes[index] = binary.charCodeAt(index);
	}

	return new Blob([bytes], {
		type: attachment.type || "application/octet-stream",
	});
}

function downloadUrl(url: string, fileName: string) {
	const anchor = document.createElement("a");
	anchor.href = url;
	anchor.download = fileName;
	anchor.click();
}

function downloadText(fileName: string, text: string, type: string) {
	const url = URL.createObjectURL(new Blob([text], { type }));
	const anchor = document.createElement("a");
	anchor.href = url;
	anchor.download = fileName;
	anchor.click();
	URL.revokeObjectURL(url);
}

function formatFileSize(bytes: number) {
	if (bytes < 1024) {
		return `${bytes} B`;
	}

	const kilobytes = bytes / 1024;
	if (kilobytes < 1024) {
		return `${kilobytes.toFixed(1)} KB`;
	}

	return `${(kilobytes / 1024).toFixed(1)} MB`;
}

function formatDuration(seconds: number) {
	const minutes = Math.floor(seconds / 60)
		.toString()
		.padStart(2, "0");
	const remainder = (seconds % 60).toString().padStart(2, "0");
	return `${minutes}:${remainder}`;
}

function loadAddressBook(): AddressBookEntry[] {
	try {
		const storedValue = localStorage.getItem(addressBookStorageKey);

		if (!storedValue) {
			return [];
		}

		const parsed: unknown = JSON.parse(storedValue);

		if (!Array.isArray(parsed)) {
			return [];
		}

		return parsed
			.map(normalizeAddressBookEntry)
			.filter((entry): entry is AddressBookEntry => entry !== null);
	} catch {
		return [];
	}
}

function saveAddressBook(entries: AddressBookEntry[]) {
	localStorage.setItem(addressBookStorageKey, JSON.stringify(entries));
}

function normalizeAddressBookEntry(value: unknown): AddressBookEntry | null {
	if (typeof value !== "object" || value === null) {
		return null;
	}

	const entry = value as Record<string, unknown>;

	if (
		typeof entry.address !== "string" ||
		typeof entry.createdAt !== "number" ||
		typeof entry.id !== "string"
	) {
		return null;
	}

	return {
		address: entry.address,
		createdAt: entry.createdAt,
		emoji: sanitizeEmoji(entry.emoji),
		id: entry.id,
		name:
			typeof entry.name === "string"
				? entry.name
				: typeof entry.nickname === "string"
				? entry.nickname
				: "",
		trustStatus: sanitizeTrustStatus(entry.trustStatus),
	};
}

function safeString(value: unknown) {
	return typeof value === "string" ? value : "";
}

function getOptionalFingerprint(value: string) {
	try {
		return value.trim() ? getPublicAddressFingerprint(value) : "";
	} catch {
		return "";
	}
}

function getPasswordStrength(password: string): PasswordStrength {
	let score = 0;

	if (password.length >= 12) {
		score += 1;
	}

	if (/[a-z]/u.test(password) && /[A-Z]/u.test(password)) {
		score += 1;
	}

	if (/\d/u.test(password)) {
		score += 1;
	}

	if (/[^A-Za-z0-9]/u.test(password)) {
		score += 1;
	}

	const normalizedScore = Math.max(1, score) as PasswordStrength["score"];

	if (normalizedScore <= 1) {
		return { className: "bg-red-500", label: "Weak", score: normalizedScore };
	}

	if (normalizedScore === 2) {
		return { className: "bg-amber-500", label: "Fair", score: normalizedScore };
	}

	if (normalizedScore === 3) {
		return { className: "bg-lime-500", label: "Good", score: normalizedScore };
	}

	return { className: "bg-emerald-500", label: "Strong", score: 4 };
}

function sanitizeEmoji(value: unknown) {
	const emoji = safeString(value).trim();
	return emoji || addressBookEmojiOptions[0];
}

function sanitizeTrustStatus(value: unknown): TrustStatus {
	return trustStatusOptions.includes(value as TrustStatus)
		? (value as TrustStatus)
		: "unverified";
}

function formatTrustStatus(value: TrustStatus) {
	return value.charAt(0).toUpperCase() + value.slice(1);
}

function getTrustStatusClass(value: TrustStatus) {
	return {
		blocked: "border-red-200 bg-red-50 text-red-800",
		unverified: "border-amber-200 bg-amber-50 text-amber-800",
		verified: "border-emerald-200 bg-emerald-50 text-emerald-800",
	}[value];
}

function mergeAddressBookEntries(
	currentEntries: AddressBookEntry[],
	importedEntries: AddressBookEntry[],
) {
	const merged = new Map(
		currentEntries.map(
			(entry) => [entry.address, entry] satisfies [string, AddressBookEntry],
		),
	);

	importedEntries.forEach((entry) => {
		const existingEntry = merged.get(entry.address);
		merged.set(entry.address, {
			...existingEntry,
			...entry,
			createdAt: existingEntry?.createdAt ?? entry.createdAt,
			id: existingEntry?.id ?? entry.id,
		});
	});

	return Array.from(merged.values()).sort(
		(left, right) => right.createdAt - left.createdAt,
	);
}

function parseAddressBookImport(
	fileName: string,
	text: string,
): AddressBookEntry[] {
	const lowerFileName = fileName.toLowerCase();

	if (lowerFileName.endsWith(".json")) {
		const parsed = JSON.parse(text) as unknown;

		if (!Array.isArray(parsed)) {
			throw new Error(
				"The contacts JSON file must contain an array of contacts.",
			);
		}

		const contacts = parsed
			.map(normalizeAddressBookEntry)
			.filter((entry): entry is AddressBookEntry => entry !== null);

		if (contacts.length === 0) {
			throw new Error("No valid contacts were found in the JSON file.");
		}

		return contacts;
	}

	if (!lowerFileName.endsWith(".csv")) {
		throw new Error("Upload a CSV or JSON file.");
	}

	const rows = text
		.split(/\r?\n/u)
		.map((row) => row.trim())
		.filter(Boolean);

	if (rows.length < 2) {
		throw new Error("The CSV file does not contain any contacts.");
	}

	const headers = parseCsvRow(rows[0]).map((value) =>
		value.trim().toLowerCase(),
	);
	const idIndex = headers.indexOf("id");
	const nameIndex = headers.indexOf("name");
	const addressIndex = headers.indexOf("address");
	const emojiIndex = headers.indexOf("emoji");
	const trustStatusIndex = headers.indexOf("truststatus");

	if (nameIndex === -1 || addressIndex === -1) {
		throw new Error(
			"The CSV file must include at least name and address columns.",
		);
	}

	const contacts = rows
		.slice(1)
		.map((row, index) => {
			const values = parseCsvRow(row);
			const rawAddress = values[addressIndex] ?? "";

			if (!rawAddress.trim()) {
				return null;
			}

			return {
				address: normalizePublicAddress(rawAddress),
				createdAt: Date.now() + index,
				emoji: sanitizeEmoji(values[emojiIndex] ?? addressBookEmojiOptions[0]),
				id: (values[idIndex] ?? "").trim() || crypto.randomUUID(),
				name: (values[nameIndex] ?? "").trim(),
				trustStatus: sanitizeTrustStatus(values[trustStatusIndex]),
			} satisfies AddressBookEntry;
		})
		.filter((entry): entry is AddressBookEntry => entry !== null);

	if (contacts.length === 0) {
		throw new Error("No valid contacts were found in the CSV file.");
	}

	return contacts;
}

function convertAddressBookEntriesToCsv(entries: AddressBookEntry[]) {
	const header = ["id", "name", "emoji", "trustStatus", "address"];
	const rows = entries.map((entry) => [
		entry.id,
		entry.name,
		entry.emoji,
		entry.trustStatus,
		entry.address,
	]);

	return [header, ...rows]
		.map((row) => row.map(escapeCsvValue).join(","))
		.join("\n");
}

function parseCsvRow(row: string) {
	const values: string[] = [];
	let current = "";
	let insideQuotes = false;

	for (let index = 0; index < row.length; index += 1) {
		const character = row[index];
		const nextCharacter = row[index + 1];

		if (character === '"' && insideQuotes && nextCharacter === '"') {
			current += '"';
			index += 1;
			continue;
		}

		if (character === '"') {
			insideQuotes = !insideQuotes;
			continue;
		}

		if (character === "," && !insideQuotes) {
			values.push(current);
			current = "";
			continue;
		}

		current += character;
	}

	values.push(current);
	return values;
}

function escapeCsvValue(value: string) {
	if (/[",\n]/u.test(value)) {
		return `"${value.replaceAll('"', '""')}"`;
	}

	return value;
}

function formatDateToken() {
	return new Date().toISOString().slice(0, 10);
}

function toNotice(error: unknown, fallback: string): Notice {
	return {
		tone: "error",
		message: error instanceof Error ? error.message : fallback,
	};
}

function App() {
	return (
		<Routes>
			<Route path="/*" element={<HomePage />} />
		</Routes>
	);
}

export default App;
