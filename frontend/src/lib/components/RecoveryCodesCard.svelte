<script lang="ts">
	/**
	 * Profile → recovery codes (docs/plan/passkeys.md, Phase 2a): how many
	 * are left, and a new set shown exactly once. Shown next to the
	 * passkeys card; the codes are the way back when every passkey is gone.
	 */
	import Button from '$lib/components/Button.svelte';
	import Icon from '$lib/icons/Icon.svelte';
	import { t } from '$lib/i18n/index.svelte';
	import {
		generateRecoveryCodes,
		getRecoveryCodeStatus,
		type RecoveryCodeStatusDto
	} from '$lib/api/endpoints/recoveryCodes';
	import { isReauthRequired, withReauth } from '$lib/auth/reauth';
	import { confirmDialog } from '$lib/stores/dialogs.svelte';
	import { errorMessage } from '$lib/utils/errors';

	let status = $state<RecoveryCodeStatusDto | null>(null);
	let codes = $state<string[] | null>(null);
	let busy = $state(false);
	let error = $state<string | null>(null);
	let copied = $state(false);

	async function load() {
		try {
			status = await getRecoveryCodeStatus();
		} catch (err) {
			error = errorMessage(err);
		}
	}

	async function generate() {
		if (status && status.remaining > 0) {
			const ok = await confirmDialog({
				title: t('recovery.replace_title', 'Create new recovery codes?'),
				message: t('recovery.replace_message', 'Your current recovery codes will stop working.'),
				confirmText: t('recovery.create', 'Create codes'),
				danger: true
			});
			if (!ok) return;
		}
		busy = true;
		error = null;
		copied = false;
		try {
			codes = await withReauth(generateRecoveryCodes);
			await load();
		} catch (err) {
			if (!isReauthRequired(err)) error = errorMessage(err);
		} finally {
			busy = false;
		}
	}

	async function copy() {
		if (!codes) return;
		try {
			await navigator.clipboard.writeText(codes.join('\n'));
			copied = true;
		} catch (err) {
			error = errorMessage(err);
		}
	}

	function download() {
		if (!codes) return;
		const text = `${t('recovery.file_header', 'OxiCloud recovery codes — each works once.')}\n${location.host}\n\n${codes.join('\n')}\n`;
		const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
		const a = document.createElement('a');
		a.href = url;
		a.download = `oxicloud-recovery-codes-${location.host}.txt`;
		a.click();
		URL.revokeObjectURL(url);
	}

	$effect(() => {
		void load();
	});
</script>

<div class="card" data-testid="profile-recovery-codes">
	<h2><Icon name="key" /> {t('recovery.title', 'Recovery codes')}</h2>
	<p class="muted">
		{t(
			'recovery.desc',
			'If you lose every passkey, sign in with one of these codes instead. Each code works once. Keep them somewhere safe, away from your devices.'
		)}
	</p>

	{#if codes}
		<p class="recovery__warning" role="status">
			{t('recovery.shown_once', 'Save these codes now. They will not be shown again.')}
		</p>
		<ol class="recovery__codes" data-testid="profile-recovery-codes-list">
			{#each codes as code (code)}<li>{code}</li>{/each}
		</ol>
		<div class="recovery__actions">
			<Button small icon="copy" onclick={() => void copy()}>
				{copied ? t('recovery.copied', 'Copied') : t('recovery.copy', 'Copy')}
			</Button>
			<Button small icon="download" onclick={download}>{t('recovery.download', 'Download')}</Button>
			<Button small variant="primary" onclick={() => (codes = null)}>
				{t('recovery.done', 'I have saved them')}
			</Button>
		</div>
	{:else}
		{#if status}
			<p class="muted">
				{status.remaining > 0
					? t(
							'recovery.remaining',
							{ count: String(status.remaining) },
							'{{count}} unused codes left.'
						)
					: t('recovery.none', 'No recovery codes yet.')}
			</p>
		{/if}
		<div class="recovery__actions">
			<Button
				variant={status && status.remaining > 0 ? 'secondary' : 'primary'}
				disabled={busy}
				onclick={() => void generate()}
				data-testid="profile-recovery-generate-btn"
			>
				{status && status.remaining > 0
					? t('recovery.regenerate', 'Create new codes')
					: t('recovery.create', 'Create codes')}
			</Button>
		</div>
	{/if}

	{#if error}<p class="recovery__error" role="alert">{error}</p>{/if}
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

	.recovery__warning {
		margin: 0;
		color: var(--color-warning-text);
		font-weight: 600;
	}

	.recovery__codes {
		display: grid;
		grid-template-columns: repeat(auto-fill, minmax(12rem, 1fr));
		gap: var(--space-1) var(--space-4);
		margin: 0;
		padding-inline-start: 1.5rem;
		font-family: var(--font-mono);
		color: var(--color-text);
	}

	.recovery__actions {
		display: flex;
		flex-wrap: wrap;
		gap: var(--space-2);
	}

	.recovery__error {
		margin: 0;
		color: var(--color-danger-text);
	}
</style>
