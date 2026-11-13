/**
 * Chat attachments (m.image, m.video, m.audio, m.file): read the event
 * content, locate the bytes on the homeserver, and decrypt them when the
 * room is encrypted.
 *
 * Downloads use authenticated media (`/_matrix/client/v1/media/download`,
 * Matrix 1.11): the plain `/_matrix/media/v3` routes are frozen on current
 * homeservers. Encrypted attachments follow the spec's `EncryptedFile`:
 * AES-256-CTR with the key as a JWK and a 16-byte IV whose counter half is
 * zero, and a SHA-256 of the ciphertext that MUST be checked before
 * decrypting. Written against WebCrypto, no extra dependency.
 */

export type AttachmentKind = 'image' | 'video' | 'audio' | 'file';

/** `EncryptedFile` from the Matrix spec (only the members used here). */
export interface EncryptedFile {
	url: string;
	key: { k: string; alg?: string };
	iv: string;
	hashes: { sha256?: string };
	v?: string;
}

/** Where the bytes are: a plain `mxc://` URL, or an encrypted file. */
export type AttachmentSource = { url: string } | { file: EncryptedFile };

export interface Attachment {
	kind: AttachmentKind;
	/** File name as sent (the event's `filename`, else `body`). */
	name: string;
	mimetype?: string;
	size?: number;
	width?: number;
	height?: number;
	source: AttachmentSource;
	thumbnail?: AttachmentSource;
}

const KINDS: Record<string, AttachmentKind> = {
	'm.image': 'image',
	'm.video': 'video',
	'm.audio': 'audio',
	'm.file': 'file'
};

type Json = Record<string, unknown>;
const isObj = (v: unknown): v is Json => typeof v === 'object' && v !== null;
const num = (v: unknown): number | undefined => (typeof v === 'number' ? v : undefined);
const str = (v: unknown): string | undefined => (typeof v === 'string' ? v : undefined);

function encryptedFile(v: unknown): EncryptedFile | undefined {
	if (!isObj(v) || !isObj(v.key) || !isObj(v.hashes)) return undefined;
	const url = str(v.url);
	const k = str(v.key.k);
	const iv = str(v.iv);
	if (!url || !k || !iv) return undefined;
	return { url, key: { k, alg: str(v.key.alg) }, iv, hashes: { sha256: str(v.hashes.sha256) } };
}

function source(url: unknown, file: unknown): AttachmentSource | undefined {
	const enc = encryptedFile(file);
	if (enc) return { file: enc };
	const plain = str(url);
	return plain?.startsWith('mxc://') ? { url: plain } : undefined;
}

/**
 * The attachment in a room message's content, or `null` when it is not a
 * media message or carries no usable source.
 */
export function attachmentFromContent(c: Json): Attachment | null {
	const kind = KINDS[str(c.msgtype) ?? ''];
	if (!kind) return null;
	const src = source(c.url, c.file);
	if (!src) return null;
	const info = isObj(c.info) ? c.info : {};
	return {
		kind,
		name: str(c.filename) ?? str(c.body) ?? '',
		mimetype: str(info.mimetype),
		size: num(info.size),
		width: num(info.w),
		height: num(info.h),
		source: src,
		thumbnail: source(info.thumbnail_url, info.thumbnail_file)
	};
}

/**
 * Text to show with an attachment: a caption when the sender wrote one
 * (Matrix 1.10: `body` differs from `filename`), otherwise nothing.
 */
export function attachmentCaption(c: Json): string {
	const body = str(c.body) ?? '';
	const filename = str(c.filename);
	return filename && body !== filename ? body : '';
}

/** `mxc://server/id` → the authenticated download path, or null. */
export function mediaDownloadPath(mxc: string): string | null {
	const m = /^mxc:\/\/([^/]+)\/([A-Za-z0-9_-]+)$/.exec(mxc);
	if (!m) return null;
	return `/_matrix/client/v1/media/download/${encodeURIComponent(m[1])}/${encodeURIComponent(m[2])}`;
}

export function sourceUrl(src: AttachmentSource): string {
	return 'file' in src ? src.file.url : src.url;
}

function b64ToBytes(s: string): Uint8Array<ArrayBuffer> {
	const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
	const bin = atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4));
	const out = new Uint8Array(new ArrayBuffer(bin.length));
	for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
	return out;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
	if (a.length !== b.length) return false;
	let diff = 0;
	for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
	return diff === 0;
}

/**
 * Decrypt an encrypted attachment. Throws when the hash is missing or does
 * not match: the ciphertext was altered, and decrypting it anyway would
 * hand the user attacker-controlled bytes.
 */
export async function decryptAttachment(
	ciphertext: ArrayBuffer,
	file: EncryptedFile
): Promise<ArrayBuffer> {
	const expected = file.hashes.sha256;
	if (!expected) throw new Error('Encrypted attachment has no SHA-256 hash');
	const actual = new Uint8Array(await crypto.subtle.digest('SHA-256', ciphertext));
	if (!bytesEqual(actual, b64ToBytes(expected))) {
		throw new Error('Encrypted attachment failed its integrity check');
	}
	const key = await crypto.subtle.importKey(
		'jwk',
		{ kty: 'oct', k: file.key.k, alg: 'A256CTR', ext: true, key_ops: ['decrypt'] },
		{ name: 'AES-CTR' },
		false,
		['decrypt']
	);
	return crypto.subtle.decrypt(
		{ name: 'AES-CTR', counter: b64ToBytes(file.iv), length: 64 },
		key,
		ciphertext
	);
}
