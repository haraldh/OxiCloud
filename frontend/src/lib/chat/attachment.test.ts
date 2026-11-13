import { describe, expect, it } from 'vitest';
import {
	attachmentCaption,
	attachmentFromContent,
	decryptAttachment,
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
