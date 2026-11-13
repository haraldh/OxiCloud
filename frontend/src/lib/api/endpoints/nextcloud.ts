/**
 * Nextcloud Login Flow v2 from the signed-in browser
 * (docs/plan/passkeys.md, Phase 2a): link the client that opened the grant
 * page to this account without typing a password.
 */
import { nextcloudLoginFlowGrant } from '$lib/api/generated/openapi/sdk.gen';
import type { LoginFlowGrantResponse } from '$lib/api/generated/openapi/types.gen';
import { apiErrorFromSdkError } from './auth';

export type { LoginFlowGrantResponse };

export async function grantLoginFlow(token: string): Promise<LoginFlowGrantResponse> {
	try {
		return await nextcloudLoginFlowGrant({ path: { token }, throwOnError: true });
	} catch (e) {
		throw apiErrorFromSdkError(e, '/api/nextcloud/login-flow/{token}/grant');
	}
}
