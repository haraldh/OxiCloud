/**
 * WebAuthn glue between the server's JSON (webauthn-rs: binary fields as
 * unpadded base64url) and `navigator.credentials`, which wants and returns
 * ArrayBuffers. See docs/plan/passkeys.md.
 *
 * Written by hand instead of `PublicKeyCredential.parseCreationOptionsFromJSON`
 * / `credential.toJSON()` because those are still missing in browsers we
 * support.
 */

export function bytesToB64url(buf: ArrayBuffer | ArrayBufferView): string {
	const bytes =
		buf instanceof ArrayBuffer
			? new Uint8Array(buf)
			: new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
	let bin = '';
	for (const b of bytes) bin += String.fromCharCode(b);
	return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function b64urlToBytes(s: string): Uint8Array<ArrayBuffer> {
	const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
	const bin = atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4));
	const out = new Uint8Array(new ArrayBuffer(bin.length));
	for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
	return out;
}

/** The browser can do WebAuthn at all (secure context, API present). */
export function passkeysSupported(): boolean {
	return (
		typeof window !== 'undefined' &&
		window.isSecureContext &&
		typeof window.PublicKeyCredential !== 'undefined' &&
		typeof navigator.credentials?.create === 'function'
	);
}

type Json = Record<string, unknown>;

/** Drop `null`s: the server serialises unset options as null, which some
 * browsers reject where they expect the member to be absent. */
function compact(o: Json): Json {
	const out: Json = {};
	for (const [k, v] of Object.entries(o)) if (v !== null && v !== undefined) out[k] = v;
	return out;
}

interface CredentialDescriptorJson {
	type: string;
	id: string;
	transports?: string[] | null;
}

function descriptor(d: CredentialDescriptorJson): PublicKeyCredentialDescriptor {
	return compact({
		type: d.type,
		id: b64urlToBytes(d.id),
		transports: d.transports
	}) as unknown as PublicKeyCredentialDescriptor;
}

/** `{ publicKey: … }` from `/api/auth/passkeys/register/start`. */
export function toCreationOptions(options: unknown): PublicKeyCredentialCreationOptions {
	const pk = (options as { publicKey: Json }).publicKey;
	const user = pk.user as Json;
	return compact({
		...pk,
		challenge: b64urlToBytes(pk.challenge as string),
		user: compact({ ...user, id: b64urlToBytes(user.id as string) }),
		excludeCredentials: ((pk.excludeCredentials as CredentialDescriptorJson[] | null) ?? []).map(
			descriptor
		),
		authenticatorSelection: pk.authenticatorSelection
			? compact(pk.authenticatorSelection as Json)
			: undefined,
		extensions: pk.extensions ? compact(pk.extensions as Json) : undefined
	}) as unknown as PublicKeyCredentialCreationOptions;
}

/** `{ publicKey: … }` from `/api/auth/passkey/login/start`. */
export function toRequestOptions(options: unknown): PublicKeyCredentialRequestOptions {
	const pk = (options as { publicKey: Json }).publicKey;
	return compact({
		...pk,
		challenge: b64urlToBytes(pk.challenge as string),
		allowCredentials: ((pk.allowCredentials as CredentialDescriptorJson[] | null) ?? []).map(
			descriptor
		),
		extensions: pk.extensions ? compact(pk.extensions as Json) : undefined
	}) as unknown as PublicKeyCredentialRequestOptions;
}

/** A new credential from `navigator.credentials.create()`, as the server reads it. */
export function registrationToJson(cred: PublicKeyCredential): Json {
	const r = cred.response as AuthenticatorAttestationResponse;
	return {
		id: cred.id,
		rawId: bytesToB64url(cred.rawId),
		type: cred.type,
		response: compact({
			attestationObject: bytesToB64url(r.attestationObject),
			clientDataJSON: bytesToB64url(r.clientDataJSON),
			transports: typeof r.getTransports === 'function' ? r.getTransports() : undefined
		}),
		extensions: cred.getClientExtensionResults()
	};
}

/** A sign-in assertion from `navigator.credentials.get()`, as the server reads it. */
export function assertionToJson(cred: PublicKeyCredential): Json {
	const r = cred.response as AuthenticatorAssertionResponse;
	return {
		id: cred.id,
		rawId: bytesToB64url(cred.rawId),
		type: cred.type,
		response: {
			authenticatorData: bytesToB64url(r.authenticatorData),
			clientDataJSON: bytesToB64url(r.clientDataJSON),
			signature: bytesToB64url(r.signature),
			userHandle: r.userHandle ? bytesToB64url(r.userHandle) : null
		},
		extensions: cred.getClientExtensionResults()
	};
}

/**
 * The user dismissed the browser's passkey prompt (or it timed out).
 * Not an error worth showing; the caller just stays where it was.
 */
export function isPasskeyCancelled(err: unknown): boolean {
	return (
		err instanceof DOMException && (err.name === 'NotAllowedError' || err.name === 'AbortError')
	);
}
