import { describe, expect, it } from 'vitest';
import {
	attachmentCaption,
	attachmentContent,
	attachmentFromContent,
	decryptAttachment,
	encryptAttachment,
	kindForMime,
	mediaDownloadPath,
	type EncryptedFile
} from './attachment';

const b64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes)).replace(/=+$/, '');
const b64url = (bytes: Uint8Array) => b64(bytes).replace(/\+/g, '-').replace(/\//g, '_');

/** Encrypt like a Matrix client does, to test our decryption against it. */
async function encryptLikeAClient(
	plain: Uint8Array<ArrayBuffer>
): Promise<{ cipher: ArrayBuffer; file: EncryptedFile }> {
	const key = await crypto.subtle.generateKey({ name: 'AES-CTR', length: 256 }, true, [
		'encrypt',
		'decrypt'
	]);
	const iv = new Uint8Array(16);
	crypto.getRandomValues(iv.subarray(0, 8)); // counter half stays zero
	const cipher = await crypto.subtle.encrypt(
		{ name: 'AES-CTR', counter: iv, length: 64 },
		key,
		plain
	);
	const jwk = await crypto.subtle.exportKey('jwk', key);
	const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', cipher));
	return {
		cipher,
		file: {
			url: 'mxc://example.org/abc',
			key: { k: jwk.k!, alg: 'A256CTR' },
			iv: b64(iv),
			hashes: { sha256: b64(hash) },
			v: 'v2'
		}
	};
}

describe('attachmentFromContent', () => {
	it('reads a plain image with its info and thumbnail', () => {
		const a = attachmentFromContent({
			msgtype: 'm.image',
			body: 'cat.jpg',
			url: 'mxc://example.org/full',
			info: {
				mimetype: 'image/jpeg',
				size: 1234,
				w: 800,
				h: 600,
				thumbnail_url: 'mxc://example.org/thumb'
			}
		});
		expect(a).toEqual({
			kind: 'image',
			name: 'cat.jpg',
			mimetype: 'image/jpeg',
			size: 1234,
			width: 800,
			height: 600,
			source: { url: 'mxc://example.org/full' },
			thumbnail: { url: 'mxc://example.org/thumb' }
		});
	});

	it('prefers the encrypted file over a url and keeps the key material', () => {
		const a = attachmentFromContent({
			msgtype: 'm.file',
			body: 'report.pdf',
			file: {
				url: 'mxc://example.org/enc',
				key: { k: 'KEY', alg: 'A256CTR', kty: 'oct' },
				iv: 'IV',
				hashes: { sha256: 'HASH' },
				v: 'v2'
			}
		});
		expect(a?.kind).toBe('file');
		expect(a?.source).toEqual({
			file: {
				url: 'mxc://example.org/enc',
				key: { k: 'KEY', alg: 'A256CTR' },
				iv: 'IV',
				hashes: { sha256: 'HASH' }
			}
		});
	});

	it('ignores text messages and media without a usable source', () => {
		expect(attachmentFromContent({ msgtype: 'm.text', body: 'hi' })).toBeNull();
		expect(
			attachmentFromContent({ msgtype: 'm.image', body: 'x', url: 'https://evil.example/x' })
		).toBeNull();
		expect(
			attachmentFromContent({ msgtype: 'm.file', body: 'x', file: { url: 'mxc://a/b' } })
		).toBeNull();
	});

	it('uses filename for the name and treats a different body as the caption', () => {
		const c = { msgtype: 'm.image', body: 'Look at this', filename: 'cat.jpg', url: 'mxc://e/x' };
		expect(attachmentFromContent(c)?.name).toBe('cat.jpg');
		expect(attachmentCaption(c)).toBe('Look at this');
		expect(attachmentCaption({ msgtype: 'm.image', body: 'cat.jpg', url: 'mxc://e/x' })).toBe('');
	});
});

describe('mediaDownloadPath', () => {
	it('maps mxc URLs to authenticated media and refuses anything else', () => {
		expect(mediaDownloadPath('mxc://hoyer.xyz/AbC_1-2')).toBe(
			'/_matrix/client/v1/media/download/hoyer.xyz/AbC_1-2'
		);
		expect(mediaDownloadPath('mxc://hoyer.xyz/../../admin')).toBeNull();
		expect(mediaDownloadPath('https://hoyer.xyz/x')).toBeNull();
	});
});

describe('decryptAttachment', () => {
	it('decrypts what a client encrypted', async () => {
		const plain = new TextEncoder().encode('hello attachment');
		const { cipher, file } = await encryptLikeAClient(plain);
		const out = new Uint8Array(await decryptAttachment(cipher, file));
		expect(new TextDecoder().decode(out)).toBe('hello attachment');
	});

	it('refuses altered ciphertext and a missing hash', async () => {
		const { cipher, file } = await encryptLikeAClient(new Uint8Array([1, 2, 3, 4]));
		const tampered = new Uint8Array(cipher.slice(0));
		tampered[0] ^= 1;
		await expect(decryptAttachment(tampered.buffer, file)).rejects.toThrow(/integrity/);
		await expect(decryptAttachment(cipher, { ...file, hashes: {} })).rejects.toThrow(/hash/);
	});

	it('accepts url-safe or padded base64 in the hash', async () => {
		const { cipher, file } = await encryptLikeAClient(new Uint8Array([9, 9, 9]));
		const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', cipher));
		const out = await decryptAttachment(cipher, { ...file, hashes: { sha256: b64url(hash) } });
		expect(Array.from(new Uint8Array(out))).toEqual([9, 9, 9]);
	});
});

describe('sending', () => {
	it('picks the message type from the MIME type, never image for SVG', () => {
		expect(kindForMime('image/png')).toBe('image');
		expect(kindForMime('image/svg+xml')).toBe('file');
		expect(kindForMime('video/mp4')).toBe('video');
		expect(kindForMime('audio/ogg')).toBe('audio');
		expect(kindForMime('application/pdf')).toBe('file');
	});

	it('encrypts so that our own (spec) decryption reads it back', async () => {
		const plain = new TextEncoder().encode('round trip').buffer as ArrayBuffer;
		const { cipher, file } = await encryptAttachment(plain);
		expect(Array.from(new Uint8Array(cipher))).not.toEqual(Array.from(new Uint8Array(plain)));
		const back = await decryptAttachment(cipher, { ...file, url: 'mxc://e/x' });
		expect(new TextDecoder().decode(back)).toBe('round trip');
	});

	it('uses a fresh key and IV per file, with a zero counter half', async () => {
		const a = await encryptAttachment(new ArrayBuffer(4));
		const b = await encryptAttachment(new ArrayBuffer(4));
		expect(a.file.key.k).not.toBe(b.file.key.k);
		const iv = Uint8Array.from(
			atob(a.file.iv + '=='.slice(0, (4 - (a.file.iv.length % 4)) % 4)),
			(c) => c.charCodeAt(0)
		);
		expect(Array.from(iv.subarray(8))).toEqual([0, 0, 0, 0, 0, 0, 0, 0]);
	});

	it('builds content other clients and our parser read back', async () => {
		const { file } = await encryptAttachment(new ArrayBuffer(8));
		const content = attachmentContent(
			'cat.jpg',
			'image/jpeg',
			8,
			{ file: { ...file, url: 'mxc://e/x' } },
			{ w: 4, h: 3 }
		);
		expect(content).toMatchObject({
			msgtype: 'm.image',
			body: 'cat.jpg',
			filename: 'cat.jpg',
			info: { mimetype: 'image/jpeg', size: 8, w: 4, h: 3 },
			file: {
				url: 'mxc://e/x',
				key: { kty: 'oct', alg: 'A256CTR', ext: true, key_ops: ['encrypt', 'decrypt'] },
				v: 'v2'
			}
		});
		const parsed = attachmentFromContent(content);
		expect(parsed?.kind).toBe('image');
		expect(parsed?.source).toMatchObject({ file: { url: 'mxc://e/x', iv: file.iv } });

		const plainContent = attachmentContent('a.pdf', 'application/pdf', 5, { url: 'mxc://e/y' });
		expect(plainContent).toEqual({
			msgtype: 'm.file',
			body: 'a.pdf',
			filename: 'a.pdf',
			info: { mimetype: 'application/pdf', size: 5 },
			url: 'mxc://e/y'
		});
	});
});
