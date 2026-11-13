import { describe, expect, it } from 'vitest';
import { bypassesRetry } from './transport';

describe('bypassesRetry', () => {
	// A sign-in answering 401 means "wrong credential", not "expired
	// session": retrying it after a refresh would re-submit a used passkey
	// assertion or recovery code. The signed-in management routes next to
	// them must keep the normal refresh-on-401 (docs/plan/passkeys.md).
	it('treats passkey and recovery-code sign-in as auth primitives', () => {
		expect(bypassesRetry('/api/auth/passkey/login/finish')).toBe(true);
		expect(bypassesRetry('/api/auth/recovery/login')).toBe(true);
	});

	it('keeps refresh-on-401 for the signed-in passkey and recovery-code routes', () => {
		expect(bypassesRetry('/api/auth/passkeys')).toBe(false);
		expect(bypassesRetry('/api/auth/recovery-codes')).toBe(false);
		expect(bypassesRetry('/api/auth/reauth/password')).toBe(false);
	});
});
