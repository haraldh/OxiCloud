/**
 * The signed-in user's recovery codes (docs/plan/passkeys.md, Phase 2a).
 * Signing in with one lives in `endpoints/auth.ts` (`recoveryLogin`).
 */
import { recoveryCodesGenerate, recoveryCodesStatus } from '$lib/api/generated/openapi/sdk.gen';
import type { RecoveryCodeStatusDto } from '$lib/api/generated/openapi/types.gen';
import { apiErrorFromSdkError } from './auth';

export type { RecoveryCodeStatusDto };

export async function getRecoveryCodeStatus(): Promise<RecoveryCodeStatusDto> {
	try {
		return await recoveryCodesStatus({ throwOnError: true });
	} catch (e) {
		throw apiErrorFromSdkError(e, '/api/auth/recovery-codes');
	}
}

/** Make a new set; the old codes stop working. Returns them once. */
export async function generateRecoveryCodes(): Promise<string[]> {
	try {
		return (await recoveryCodesGenerate({ throwOnError: true })).codes;
	} catch (e) {
		throw apiErrorFromSdkError(e, '/api/auth/recovery-codes');
	}
}
