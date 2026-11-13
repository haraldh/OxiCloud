/**
 * The signed-in user's passkeys: list, add, rename, remove.
 * Sign-in itself lives in `endpoints/auth.ts` (`passkeyLogin`), next to
 * the password login. See docs/plan/passkeys.md.
 */
import {
	passkeyList,
	passkeyRegisterFinish,
	passkeyRegisterStart,
	passkeyRemove,
	passkeyRename
} from '$lib/api/generated/openapi/sdk.gen';
import type { PasskeyInfo } from '$lib/api/generated/openapi/types.gen';
import { registrationToJson, toCreationOptions } from '$lib/auth/passkey';
import { apiErrorFromSdkError } from './auth';

export type { PasskeyInfo };

export async function listPasskeys(): Promise<PasskeyInfo[]> {
	try {
		return await passkeyList({ throwOnError: true });
	} catch (e) {
		throw apiErrorFromSdkError(e, '/api/auth/passkeys');
	}
}

/**
 * Create a passkey on this device and register it. Throws the browser's
 * DOMException when the user cancels (see `isPasskeyCancelled`).
 */
export async function addPasskey(name: string): Promise<PasskeyInfo> {
	let start;
	try {
		start = await passkeyRegisterStart({ throwOnError: true });
	} catch (e) {
		throw apiErrorFromSdkError(e, '/api/auth/passkeys/register/start');
	}
	const created = await navigator.credentials.create({
		publicKey: toCreationOptions(start.options)
	});
	if (!(created instanceof PublicKeyCredential)) {
		throw new Error('The browser returned no passkey');
	}
	try {
		return await passkeyRegisterFinish({
			body: {
				ceremonyId: start.ceremonyId,
				name,
				credential: registrationToJson(created)
			},
			throwOnError: true
		});
	} catch (e) {
		throw apiErrorFromSdkError(e, '/api/auth/passkeys/register/finish');
	}
}

export async function renamePasskey(id: string, name: string): Promise<void> {
	try {
		await passkeyRename({ path: { id }, body: { name }, throwOnError: true });
	} catch (e) {
		throw apiErrorFromSdkError(e, '/api/auth/passkeys/{id}');
	}
}

export async function removePasskey(id: string): Promise<void> {
	try {
		await passkeyRemove({ path: { id }, throwOnError: true });
	} catch (e) {
		throw apiErrorFromSdkError(e, '/api/auth/passkeys/{id}');
	}
}
