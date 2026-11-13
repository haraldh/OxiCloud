/**
 * "Confirm it's you" (docs/plan/passkeys.md, Phase 2a). Sensitive account
 * changes answer 403 `ReauthRequired` when the session's last sign-in is
 * older than the step-up window; `withReauth` catches that, asks the user
 * to confirm with a passkey or their password, and retries once.
 */
import { ApiError } from '$lib/api/client';
import {
	getReauthMethods,
	reauthWithPasskey,
	reauthWithPassword,
	type ReauthMethods
} from '$lib/api/endpoints/reauth';
import { t } from '$lib/i18n/index.svelte';
import { confirmDialog, formDialog } from '$lib/stores/dialogs.svelte';
import { isPasskeyCancelled, passkeysSupported } from './passkey';

export function isReauthRequired(err: unknown): boolean {
	return err instanceof ApiError && err.errorType === 'ReauthRequired';
}

/** Dialog actions throw a readable message; the dialog shows it inline. */
function readable(err: unknown): Error {
	if (isPasskeyCancelled(err)) {
		return new Error(t('reauth.passkey_cancelled', 'No passkey was used. Try again or cancel.'));
	}
	if (err instanceof ApiError && err.errorType === 'InvalidCredentials') {
		return new Error(t('reauth.rejected', 'That did not work. Please try again.'));
	}
	return err instanceof Error ? err : new Error(String(err));
}

/**
 * Ask the user to confirm who they are. Resolves `true` once the session
 * is stamped, `false` when they cancel or the account has no way to
 * confirm here. `methods` is injectable for tests.
 */
export async function confirmIdentity(methods?: ReauthMethods): Promise<boolean> {
	const m = methods ?? (await getReauthMethods());
	const title = t('reauth.title', 'Confirm it’s you');
	const message = t(
		'reauth.message',
		'You are about to change how you sign in. Confirm it’s you first.'
	);

	if (m.passkey && passkeysSupported()) {
		const ok = await confirmDialog({
			title,
			message,
			confirmText: t('reauth.use_passkey', 'Use passkey'),
			cancelText: m.password ? t('reauth.use_password', 'Use password') : undefined,
			action: async () => {
				try {
					await reauthWithPasskey();
				} catch (err) {
					throw readable(err);
				}
			}
		});
		if (ok) return true;
		if (!m.password) return false;
	}

	if (m.password) {
		const values = await formDialog({
			title,
			message,
			fields: [
				{
					key: 'password',
					label: t('auth.password', 'Password'),
					type: 'password',
					autocomplete: 'current-password'
				}
			],
			confirmText: t('reauth.confirm', 'Confirm'),
			action: async (v) => {
				try {
					await reauthWithPassword(v.password ?? '');
				} catch (err) {
					throw readable(err);
				}
			}
		});
		return values !== null;
	}

	await confirmDialog({
		title,
		message: t(
			'reauth.unavailable',
			'Sign out and sign in again, then retry. This account has no passkey or password to confirm with here.'
		),
		confirmText: t('common.ok', 'OK')
	});
	return false;
}

/**
 * Run `fn`; when the server asks for a fresh confirmation, ask the user and
 * retry once. Any other error, or a cancelled confirmation, rethrows the
 * original error.
 */
export async function withReauth<T>(
	fn: () => Promise<T>,
	confirm: () => Promise<boolean> = confirmIdentity
): Promise<T> {
	try {
		return await fn();
	} catch (err) {
		if (!isReauthRequired(err) || !(await confirm())) throw err;
		return await fn();
	}
}
