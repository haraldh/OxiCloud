/**
 * Step-up re-authentication ("confirm it's you"), docs/plan/passkeys.md
 * Phase 2a. The UI flow around it is `$lib/auth/reauth`.
 */
import {
	reauthMethods,
	reauthPasskeyFinish,
	reauthPasskeyStart,
	reauthPassword
} from '$lib/api/generated/openapi/sdk.gen';
import type { ReauthMethods } from '$lib/api/generated/openapi/types.gen';
import { assertionToJson, toRequestOptions } from '$lib/auth/passkey';
import { apiErrorFromSdkError } from './auth';

export type { ReauthMethods };

export async function getReauthMethods(): Promise<ReauthMethods> {
	try {
		return await reauthMethods({ throwOnError: true });
	} catch (e) {
		throw apiErrorFromSdkError(e, '/api/auth/reauth');
	}
}

export async function reauthWithPassword(password: string): Promise<void> {
	try {
		await reauthPassword({ body: { password }, throwOnError: true });
	} catch (e) {
		throw apiErrorFromSdkError(e, '/api/auth/reauth/password');
	}
}

/**
 * Confirm with one of the account's own passkeys. Throws the browser's
 * DOMException when the user dismisses the prompt.
 */
export async function reauthWithPasskey(): Promise<void> {
	let start;
	try {
		start = await reauthPasskeyStart({ throwOnError: true });
	} catch (e) {
		throw apiErrorFromSdkError(e, '/api/auth/reauth/passkey/start');
	}
	const got = await navigator.credentials.get({ publicKey: toRequestOptions(start.options) });
	if (!(got instanceof PublicKeyCredential)) {
		throw new Error('The browser returned no passkey');
	}
	try {
		await reauthPasskeyFinish({
			body: { ceremonyId: start.ceremonyId, credential: assertionToJson(got) },
			throwOnError: true
		});
	} catch (e) {
		throw apiErrorFromSdkError(e, '/api/auth/reauth/passkey/finish');
	}
}
