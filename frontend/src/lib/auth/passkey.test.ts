import { describe, expect, it } from 'vitest';
import {
	assertionToJson,
	b64urlToBytes,
	bytesToB64url,
	isPasskeyCancelled,
	registrationToJson,
	toCreationOptions,
	toRequestOptions
} from './passkey';

const bytes = (...b: number[]) => new Uint8Array(b);

describe('base64url', () => {
	it('round-trips without padding and with url-safe characters', () => {
		// 0xfb 0xff → "+/8" in standard base64; url-safe and unpadded here.
		const raw = bytes(0xfb, 0xff, 0x00, 0x10);
		const s = bytesToB64url(raw);
		expect(s).toBe('-_8AEA');
		expect(Array.from(b64urlToBytes(s))).toEqual(Array.from(raw));
	});

	it('decodes every padding length', () => {
		for (const len of [0, 1, 2, 3, 4, 5]) {
			const raw = new Uint8Array(len).map((_, i) => i * 37);
			expect(Array.from(b64urlToBytes(bytesToB64url(raw)))).toEqual(Array.from(raw));
		}
	});
});

describe('server options → navigator.credentials', () => {
	it('decodes the binary members of creation options and drops nulls', () => {
		const opts = toCreationOptions({
			publicKey: {
				rp: { id: 'oxi.example.org', name: 'OxiCloud' },
				user: { id: bytesToB64url(bytes(1, 2)), name: 'alice', displayName: 'Alice' },
				challenge: bytesToB64url(bytes(9, 9, 9)),
				pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
				excludeCredentials: [{ type: 'public-key', id: bytesToB64url(bytes(7)), transports: null }],
				authenticatorSelection: { residentKey: 'preferred', authenticatorAttachment: null },
				hints: null,
				attestation: 'none'
			}
		});
		expect(Array.from(new Uint8Array(opts.challenge as ArrayBuffer))).toEqual([9, 9, 9]);
		expect(Array.from(new Uint8Array(opts.user.id as ArrayBuffer))).toEqual([1, 2]);
		const ex = opts.excludeCredentials![0];
		expect(Array.from(new Uint8Array(ex.id as ArrayBuffer))).toEqual([7]);
		expect('transports' in ex).toBe(false);
		expect('hints' in opts).toBe(false);
		expect(opts.authenticatorSelection).toEqual({ residentKey: 'preferred' });
	});

	it('decodes request options with an empty allow list (discoverable sign-in)', () => {
		const opts = toRequestOptions({
			publicKey: {
				challenge: bytesToB64url(bytes(5)),
				rpId: 'oxi.example.org',
				allowCredentials: [],
				userVerification: 'required'
			}
		});
		expect(Array.from(new Uint8Array(opts.challenge as ArrayBuffer))).toEqual([5]);
		expect(opts.allowCredentials).toEqual([]);
		expect(opts.userVerification).toBe('required');
	});
});

describe('credentials → server JSON', () => {
	const ab = (...b: number[]) => bytes(...b).buffer;

	it('encodes a registration with the field names webauthn-rs reads', () => {
		const cred = {
			id: 'AQI',
			rawId: ab(1, 2),
			type: 'public-key',
			response: {
				attestationObject: ab(3),
				clientDataJSON: ab(4),
				getTransports: () => ['internal']
			},
			getClientExtensionResults: () => ({ credProps: { rk: true } })
		} as unknown as PublicKeyCredential;
		expect(registrationToJson(cred)).toEqual({
			id: 'AQI',
			rawId: 'AQI',
			type: 'public-key',
			response: { attestationObject: 'Aw', clientDataJSON: 'BA', transports: ['internal'] },
			extensions: { credProps: { rk: true } }
		});
	});

	it('encodes an assertion, keeping a missing user handle as null', () => {
		const cred = {
			id: 'AQI',
			rawId: ab(1, 2),
			type: 'public-key',
			response: {
				authenticatorData: ab(5),
				clientDataJSON: ab(6),
				signature: ab(7),
				userHandle: null
			},
			getClientExtensionResults: () => ({})
		} as unknown as PublicKeyCredential;
		const json = assertionToJson(cred) as { response: Record<string, unknown> };
		expect(json.response).toEqual({
			authenticatorData: 'BQ',
			clientDataJSON: 'Bg',
			signature: 'Bw',
			userHandle: null
		});
	});
});

describe('isPasskeyCancelled', () => {
	it('treats a dismissed or timed-out prompt as cancellation, nothing else', () => {
		expect(isPasskeyCancelled(new DOMException('x', 'NotAllowedError'))).toBe(true);
		expect(isPasskeyCancelled(new DOMException('x', 'AbortError'))).toBe(true);
		expect(isPasskeyCancelled(new DOMException('x', 'SecurityError'))).toBe(false);
		expect(isPasskeyCancelled(new Error('NotAllowedError'))).toBe(false);
	});
});
