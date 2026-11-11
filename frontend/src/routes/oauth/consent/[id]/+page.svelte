<script lang="ts">
	// Consent step of OxiCloud's OpenID Provider (docs/plan/chat-matrix.md
	// § seam 1). `/oidc/authorize` parks the request server-side and sends
	// the browser here; the decision is an authenticated API call because a
	// top-level navigation cannot carry the DPoP proof a bound session needs.
	import '$lib/styles/ported/auth.css';
	import { goto } from '$app/navigation';
	import { resolve } from '$app/paths';
	import { page } from '$app/state';
	import { onMount } from 'svelte';
	import { idpConsentInfo, idpDecide } from '$lib/api/generated/openapi/sdk.gen';
	import type { ConsentInfoDto } from '$lib/api/generated/openapi/types.gen';
	import { t } from '$lib/i18n/index.svelte';

	type Step = 'loading' | 'review' | 'redirecting' | 'error';

	const requestId = $derived(page.params.id ?? '');
	let step = $state<Step>('loading');
	let info = $state<ConsentInfoDto | null>(null);
	let errorText = $state('');
	let busy = $state(false);

	function statusOf(err: unknown): number | undefined {
		return (err as { response?: { status?: number } })?.response?.status;
	}

	function fail(status: number | undefined) {
		errorText =
			status === 404
				? t('idp.expired', 'This sign-in request has expired. Start again from the application.')
				: status === 403
					? t('idp.forbidden', "This account can't be used to sign in to other services.")
					: t('idp.failed', 'Sign-in failed. Please try again.');
		step = 'error';
	}

	async function decide(approve: boolean) {
		busy = true;
		try {
			const res = await idpDecide({
				throwOnError: true,
				path: { id: requestId },
				body: { approve }
			});
			step = 'redirecting';
			// Leaves the SPA for the relying party's registered redirect URI.
			window.location.assign(res.redirect_to);
		} catch (err) {
			fail(statusOf(err));
		} finally {
			busy = false;
		}
	}

	onMount(async () => {
		try {
			info = await idpConsentInfo({ throwOnError: true, path: { id: requestId } });
		} catch (err) {
			const status = statusOf(err);
			if (status === 401) {
				// Sign in first, then come straight back to this request.
				const here = `/oauth/consent/${requestId}`;
				await goto(resolve(`/login?redirect=${encodeURIComponent(here)}`), {
					replaceState: true
				});
				return;
			}
			fail(status);
			return;
		}
		if (info.skip_consent) await decide(true);
		else step = 'review';
	});
</script>

<svelte:head><title>{t('idp.title', 'Sign in with OxiCloud')} · OxiCloud</title></svelte:head>

<main class="consent">
	<div class="consent__card">
		<div class="auth-logo">
			<div class="auth-logo-icon">
				<svg viewBox="95 67 320 320" aria-hidden="true">
					<path
						d="M345 310c32 0 58-26 58-58s-26-58-58-58c-6.2 0-12 0.9-17.5 2.7C318 166 289 143 255 143c-34.3 0-63.1 22.6-73 53.7C176.9 195.7 171 195 165 195c-32 0-58 26-58 58s26 58 58 58h180z"
					/>
				</svg>
			</div>
			<div class="auth-logo-text"><span class="brand-oxi">Oxi</span>Cloud</div>
		</div>
		<h1>{t('idp.title', 'Sign in with OxiCloud')}</h1>

		{#if step === 'loading' || step === 'redirecting'}
			<p data-testid="idp-consent-busy">{t('idp.redirecting', 'Signing you in…')}</p>
		{:else if step === 'review' && info}
			<p data-testid="idp-consent-prompt">
				{t(
					'idp.prompt',
					{ client: info.client_name },
					'{{client}} wants to sign you in with your OxiCloud account.'
				)}
			</p>
			<p>{t('idp.shares', 'It will receive:')}</p>
			<ul class="consent__scopes">
				{#if info.scopes.includes('profile')}
					<li>{t('idp.scope_profile', 'Your name and username')}</li>
				{/if}
				{#if info.scopes.includes('email')}
					<li>{t('idp.scope_email', 'Your email address')}</li>
				{/if}
			</ul>
			<div class="consent__actions">
				<button
					type="button"
					class="consent__deny"
					data-testid="idp-consent-deny"
					disabled={busy}
					onclick={() => decide(false)}>{t('idp.deny', 'Cancel')}</button
				>
				<button
					type="button"
					class="consent__allow"
					data-testid="idp-consent-allow"
					disabled={busy}
					onclick={() => decide(true)}>{t('idp.allow', 'Continue')}</button
				>
			</div>
		{:else if step === 'error'}
			<p class="consent__error" role="alert" data-testid="idp-consent-error">{errorText}</p>
		{/if}
	</div>
</main>

<style>
	.consent {
		width: 100%;
		min-height: 100vh;
		display: grid;
		place-items: center;
		padding: 1rem;
		background: var(--color-bg-page);
	}

	.consent__card {
		width: min(92vw, 24rem);
		display: flex;
		flex-direction: column;
		gap: 1rem;
		padding: 2rem;
		background: var(--color-bg-surface);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-lg);
		box-shadow: var(--shadow-lg);
	}

	.consent__scopes {
		margin: 0;
		padding-left: 1.25rem;
		color: var(--color-text);
	}

	.consent__actions {
		display: flex;
		justify-content: flex-end;
		gap: 0.5rem;
	}

	button {
		padding: 0.5rem 1rem;
		border: 1px solid var(--color-border);
		border-radius: var(--radius-md);
		background: var(--color-bg-surface);
		color: var(--color-text);
		cursor: pointer;
	}

	.consent__allow {
		background: var(--color-primary);
		color: var(--color-text-light);
		border-color: transparent;
	}

	.consent__deny {
		color: var(--color-danger-alt);
	}

	.consent__error {
		color: var(--color-danger-text);
	}
</style>
