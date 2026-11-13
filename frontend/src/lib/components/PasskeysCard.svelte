<script lang="ts">
	/**
	 * Profile → passkeys: list, add on this device, rename, remove.
	 * docs/plan/passkeys.md, Phase 1. Shown only when the server offers
	 * passkeys; adding one needs a browser that can create them.
	 */
	import Button from '$lib/components/Button.svelte';
	import Icon from '$lib/icons/Icon.svelte';
	import { t } from '$lib/i18n/index.svelte';
	import { ApiError } from '$lib/api/client';
	import {
		addPasskey,
		listPasskeys,
		removePasskey,
		removePassword,
		renamePasskey,
		type PasskeyInfo
	} from '$lib/api/endpoints/passkeys';
	import { isPasskeyCancelled, passkeysSupported } from '$lib/auth/passkey';
	import { isReauthRequired, withReauth } from '$lib/auth/reauth';
	import { confirmDialog, promptDialog } from '$lib/stores/dialogs.svelte';
	import { fetchMe } from '$lib/api/endpoints/auth';
	import { session } from '$lib/stores/session.svelte';
	import { formatDate } from '$lib/utils/display';
	import { relativeTimeAgo } from '$lib/utils/time';
	import { errorMessage } from '$lib/utils/errors';

	let passkeys = $state<PasskeyInfo[]>([]);
	let loaded = $state(false);
	let busy = $state(false);
	let error = $state<string | null>(null);
	let notice = $state<string | null>(null);
	let newName = $state(defaultName());

	const supported = passkeysSupported();

	/** A starting name from the platform, so most people just press Add. */
	function defaultName(): string {
		const ua = typeof navigator === 'undefined' ? '' : navigator.userAgent;
		if (/iPhone|iPad/.test(ua)) return 'iPhone/iPad';
		if (/Android/.test(ua)) return 'Android';
		if (/Macintosh/.test(ua)) return 'Mac';
		if (/Windows/.test(ua)) return 'Windows';
		if (/Linux/.test(ua)) return 'Linux';
		return t('passkeys.default_name', 'My passkey');
	}

	const timeAgo = (value: string | null | undefined): string =>
		relativeTimeAgo(value, { empty: t('profile.never', 'Never'), invalidAsString: true });

	function messageFor(err: unknown): string {
		if (err instanceof ApiError) {
			switch (err.errorType) {
				case 'PasskeyLastFactor':
					return t(
						'passkeys.last_factor',
						'This is your only way to sign in. Add another passkey or a password first.'
					);
				case 'PasskeyDuplicate':
					return t('passkeys.duplicate', 'This passkey is already registered.');
				case 'PasskeyInvalidName':
					return t('passkeys.invalid_name', 'Use a name of 1 to 64 characters.');
				case 'PasskeyVerificationFailed':
					return t(
						'passkeys.verification_failed',
						'The passkey could not be verified. Please try again.'
					);
				case 'PasskeyNotAllowed':
					return t('passkeys.not_allowed', 'This account cannot add passkeys.');
			}
		}
		return errorMessage(err);
	}

	async function load() {
		try {
			passkeys = await listPasskeys();
		} catch (err) {
			error = messageFor(err);
		} finally {
			loaded = true;
		}
	}

	async function add() {
		const name = newName.trim();
		if (!name) return;
		busy = true;
		error = null;
		notice = null;
		try {
			await withReauth(() => addPasskey(name));
			notice = t('passkeys.added', 'Passkey added. You can now use it to sign in.');
			newName = defaultName();
			await load();
		} catch (err) {
			// Cancelled at the browser prompt or at "Confirm it's you":
			// nothing to report.
			if (!isPasskeyCancelled(err) && !isReauthRequired(err)) error = messageFor(err);
		} finally {
			busy = false;
		}
	}

	async function rename(p: PasskeyInfo) {
		await promptDialog({
			title: t('passkeys.rename_title', 'Rename passkey'),
			defaultValue: p.name,
			selectOnOpen: true,
			confirmText: t('passkeys.rename', 'Rename'),
			action: async (value) => {
				try {
					await renamePasskey(p.id, value);
				} catch (err) {
					throw new Error(messageFor(err), { cause: err });
				}
				await load();
			}
		});
	}

	async function remove(p: PasskeyInfo) {
		const ok = await confirmDialog({
			title: t('passkeys.remove_title', { name: p.name }, 'Remove “{{name}}”?'),
			message: t(
				'passkeys.remove_message',
				'You will no longer be able to sign in with this passkey. The passkey itself stays on your device until you delete it there.'
			),
			confirmText: t('passkeys.remove', 'Remove'),
			danger: true
		});
		if (!ok) return;
		error = null;
		notice = null;
		try {
			await withReauth(() => removePasskey(p.id));
			await load();
		} catch (err) {
			if (!isReauthRequired(err)) error = messageFor(err);
		}
	}

	// Passkey-only accounts (Phase 2a): the password can go once there is
	// something to fall back on. SSO accounts keep theirs; their provider
	// owns the login.
	const canRemovePassword = $derived(
		!session.me?.full.federation_kind &&
			((session.me?.full.has_password ?? false) || (session.me?.full.opaque_registered ?? false))
	);

	async function dropPassword() {
		const ok = await confirmDialog({
			title: t('passkeys.remove_password_title', 'Sign in without a password?'),
			message: t(
				'passkeys.remove_password_message',
				'Your password will be deleted. You will sign in with a passkey, or with a recovery code if you lose them all. An administrator can give you a new password.'
			),
			confirmText: t('passkeys.remove_password', 'Remove password'),
			danger: true
		});
		if (!ok) return;
		error = null;
		notice = null;
		try {
			await withReauth(removePassword);
			const me = await fetchMe();
			if (me) session.me = me;
			notice = t(
				'passkeys.password_removed',
				'Password removed. Sign in with a passkey from now on.'
			);
		} catch (err) {
			if (isReauthRequired(err)) return;
			error =
				err instanceof ApiError && err.errorType === 'PasswordRemovalNeedsBackup'
					? t(
							'passkeys.remove_password_needs_backup',
							'Add a second passkey or create recovery codes first.'
						)
					: messageFor(err);
		}
	}

	$effect(() => {
		void load();
	});
</script>

<div class="card" data-testid="profile-passkeys">
	<h2><Icon name="key" /> {t('passkeys.title', 'Passkeys')}</h2>
	<p class="muted">
		{t(
			'passkeys.desc',
			'Sign in with your fingerprint, face or device PIN instead of your password. Passkeys cannot be phished, and your password keeps working.'
		)}
	</p>

	{#if supported}
		<form
			class="passkeys__add"
			onsubmit={(e) => {
				e.preventDefault();
				void add();
			}}
		>
			<input
				bind:value={newName}
				maxlength="64"
				aria-label={t('passkeys.name_label', 'Passkey name')}
				placeholder={t('passkeys.name_placeholder', 'Name (e.g. Laptop, Phone)')}
				data-testid="profile-passkey-name-input"
			/>
			<Button
				type="submit"
				variant="primary"
				icon="user-plus"
				disabled={busy || !newName.trim()}
				data-testid="profile-passkey-add-btn"
			>
				{t('passkeys.add', 'Add passkey')}
			</Button>
		</form>
	{:else}
		<p class="muted">
			{t(
				'passkeys.unsupported',
				'This browser cannot create passkeys. You can still manage the ones you have.'
			)}
		</p>
	{/if}

	{#if error}<p class="passkeys__error" role="alert">{error}</p>{/if}
	{#if notice}<p class="passkeys__notice" role="status">{notice}</p>{/if}

	{#if loaded && passkeys.length === 0}
		<p class="muted">{t('passkeys.none', 'No passkeys yet.')}</p>
	{:else if passkeys.length > 0}
		<ul class="passkeys__list">
			{#each passkeys as p (p.id)}
				<li class="passkeys__item">
					<div class="passkeys__info">
						<strong>{p.name}</strong>
						<span class="muted">
							{t('passkeys.added_on', { date: formatDate(p.created_at) }, 'Added {{date}}')}
							·
							{t('passkeys.last_used', { when: timeAgo(p.last_used_at) }, 'Last used: {{when}}')}
						</span>
					</div>
					<Button small onclick={() => void rename(p)}>{t('passkeys.rename', 'Rename')}</Button>
					<Button small variant="danger" onclick={() => void remove(p)}>
						{t('passkeys.remove', 'Remove')}
					</Button>
				</li>
			{/each}
		</ul>
	{/if}

	{#if canRemovePassword && passkeys.length > 0}
		<div class="passkeys__passwordless">
			<p class="muted">
				{t(
					'passkeys.passwordless_desc',
					'Only use passkeys: remove your password. Needs a second passkey or recovery codes.'
				)}
			</p>
			<Button small variant="danger" onclick={() => void dropPassword()}>
				{t('passkeys.remove_password', 'Remove password')}
			</Button>
		</div>
	{/if}
</div>

<style>
	.card {
		display: flex;
		flex-direction: column;
		gap: 0.75rem;
		padding: 1.5rem;
		background: var(--color-bg-surface);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-lg);
	}

	.muted {
		margin: 0;
		color: var(--color-text-muted);
		font-size: var(--text-sm);
	}

	.passkeys__add {
		display: flex;
		flex-wrap: wrap;
		gap: var(--space-2);
	}

	.passkeys__add input {
		flex: 1 1 12rem;
		min-width: 0;
		padding: var(--space-2);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-md);
		background: var(--color-bg-input);
		color: var(--color-text);
		font: inherit;
	}

	.passkeys__error {
		margin: 0;
		color: var(--color-danger-text);
	}

	.passkeys__notice {
		margin: 0;
		color: var(--color-success-text);
	}

	.passkeys__list {
		display: flex;
		flex-direction: column;
		margin: 0;
		padding: 0;
		list-style: none;
	}

	.passkeys__item {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: var(--space-2);
		padding: var(--space-2) 0;
		border-bottom: 1px solid var(--color-border);
	}

	.passkeys__passwordless {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: var(--space-2);
		padding-top: var(--space-2);
		border-top: 1px solid var(--color-border);
	}

	.passkeys__info {
		display: flex;
		flex: 1 1 14rem;
		flex-direction: column;
		min-width: 0;
		overflow-wrap: anywhere;
	}
</style>
