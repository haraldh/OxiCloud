<script lang="ts">
	import { untrack } from 'svelte';
	import Button from '$lib/components/Button.svelte';
	import Modal from '$lib/components/Modal.svelte';
	import ChatInviteForm from '$lib/components/chat/ChatInviteForm.svelte';
	import { t } from '$lib/i18n/index.svelte';
	import { confirmDialog } from '$lib/stores/dialogs.svelte';
	import { errorMessage } from '$lib/utils/errors';
	import type { ChatClient } from '$lib/chat/matrix.svelte';

	interface Props {
		open: boolean;
		chat: ChatClient;
		roomId: string;
		/** The user left the room. */
		onleft: () => void;
	}

	let { open = $bindable(false), chat, roomId, onleft }: Props = $props();

	const details = $derived(chat.details(roomId));

	let name = $state('');
	let topic = $state('');
	let busy = $state(false);
	let error = $state<string | null>(null);
	let notice = $state<string | null>(null);

	// Fill the form and fetch the full member list each time it opens. Only
	// `open` and `roomId` are tracked: `details` changes on every chat event,
	// and re-running on those would wipe what the user is typing and, via
	// loadMembers' own update, loop.
	$effect(() => {
		if (!open) return;
		const id = roomId;
		untrack(() => {
			const d = chat.details(id);
			name = d?.name ?? '';
			topic = d?.topic ?? '';
			error = null;
			notice = null;
			void chat.loadMembers(id).catch(() => undefined);
		});
	});

	async function run(fn: () => Promise<void>, done?: string) {
		busy = true;
		error = null;
		notice = null;
		try {
			await fn();
			if (done) notice = done;
		} catch (err) {
			error = errorMessage(err);
		} finally {
			busy = false;
		}
	}

	function saveAbout() {
		const d = details;
		if (!d) return;
		void run(
			async () => {
				if (d.can.rename && name.trim() && name.trim() !== d.name) {
					await chat.setName(roomId, name);
				}
				if (d.can.setTopic && topic.trim() !== d.topic) await chat.setTopic(roomId, topic);
			},
			t('chat.saved', 'Saved')
		);
	}

	async function remove(userId: string, displayName: string) {
		const ok = await confirmDialog({
			title: t('chat.remove_title', { name: displayName }, 'Remove {{name}}?'),
			message: t('chat.remove_message', 'They can rejoin only if invited again.'),
			confirmText: t('chat.remove', 'Remove'),
			danger: true
		});
		if (ok) void run(() => chat.remove(roomId, userId));
	}

	async function setPublic(isPublic: boolean) {
		await run(() => chat.setPublic(roomId, isPublic));
	}

	async function enableEncryption() {
		const ok = await confirmDialog({
			title: t('chat.encrypt_title', 'Turn on encryption?'),
			message: t(
				'chat.encrypt_message',
				'Messages from now on are end-to-end encrypted. This cannot be turned off again.'
			),
			confirmText: t('chat.encrypt_confirm', 'Turn on')
		});
		if (ok) void run(() => chat.enableEncryption(roomId));
	}

	async function leave() {
		const d = details;
		const ok = await confirmDialog({
			title: t('chat.leave_title', { name: d?.name ?? '' }, 'Leave {{name}}?'),
			message: d?.isPublic
				? t('chat.leave_public', 'You can join again from Explore rooms.')
				: t('chat.leave_private', 'You need a new invite to come back.'),
			confirmText: t('chat.leave', 'Leave'),
			danger: true
		});
		if (!ok) return;
		await run(async () => {
			await chat.leave(roomId);
			open = false;
			onleft();
		});
	}
</script>

<Modal bind:open title={t('chat.room_settings', 'Room settings')} size="lg">
	{#if details}
		{@const d = details}
		<div class="room-settings">
			{#if error}<p class="room-settings__error" role="alert">{error}</p>{/if}
			{#if notice}<p class="room-settings__notice" role="status">{notice}</p>{/if}

			<form
				class="room-settings__section"
				onsubmit={(e) => {
					e.preventDefault();
					saveAbout();
				}}
			>
				<label class="room-settings__label">
					{t('chat.room_name', 'Name')}
					<input
						class="room-settings__field"
						bind:value={name}
						disabled={!d.can.rename || d.isDirect}
						data-testid="chat-room-name"
					/>
				</label>
				<label class="room-settings__label">
					{t('chat.room_topic', 'Topic')}
					<textarea
						class="room-settings__field"
						rows="2"
						bind:value={topic}
						disabled={!d.can.setTopic}
						data-testid="chat-room-topic"></textarea>
				</label>
				{#if d.alias}
					<p class="room-settings__hint">
						{t('chat.room_address', 'Address')}: <code>{d.alias}</code>
					</p>
				{/if}
				{#if d.can.rename || d.can.setTopic}
					<div class="room-settings__actions">
						<Button type="submit" small variant="primary" disabled={busy}>
							{t('chat.save', 'Save')}
						</Button>
					</div>
				{/if}
			</form>

			{#if !d.isDirect}
				<section class="room-settings__section">
					<h3 class="room-settings__heading">{t('chat.access', 'Who can join')}</h3>
					<label class="room-settings__radio">
						<input
							type="radio"
							name="chat-access"
							checked={!d.isPublic}
							disabled={!d.can.setVisibility || busy}
							onchange={() => void setPublic(false)}
						/>
						{t('chat.access_invite', 'Only people who are invited')}
					</label>
					<label class="room-settings__radio">
						<input
							type="radio"
							name="chat-access"
							checked={d.isPublic}
							disabled={!d.can.setVisibility || busy}
							onchange={() => void setPublic(true)}
						/>
						{t('chat.access_public', 'Anyone on this server (listed in Explore rooms)')}
					</label>
				</section>
			{/if}

			<section class="room-settings__section">
				<h3 class="room-settings__heading">{t('chat.encryption', 'Encryption')}</h3>
				{#if d.isEncrypted}
					<p class="room-settings__hint">
						{t('chat.notice_encryption', 'Messages in this chat are end-to-end encrypted')}
					</p>
				{:else}
					<p class="room-settings__hint">
						{t('chat.not_encrypted', 'Messages in this room are not end-to-end encrypted.')}
					</p>
					{#if d.can.enableEncryption}
						<div class="room-settings__actions">
							<Button small disabled={busy} onclick={() => void enableEncryption()}>
								{t('chat.encrypt_confirm', 'Turn on')}
							</Button>
						</div>
					{/if}
				{/if}
			</section>

			<section class="room-settings__section">
				<h3 class="room-settings__heading">
					{t('chat.members', { n: d.members.length }, 'Members ({{n}})')}
				</h3>
				{#if d.can.invite}
					<ChatInviteForm {chat} {roomId} />
				{/if}
				<ul class="room-settings__members">
					{#each d.members as m (m.userId)}
						<li class="room-settings__member">
							<span class="room-settings__member-name">
								{m.name}
								<span class="room-settings__muted">{m.userId}</span>
							</span>
							{#if m.membership === 'invite'}
								<span class="room-settings__tag">{t('chat.invited', 'Invite')}</span>
							{:else if m.powerLevel >= 100}
								<span class="room-settings__tag">{t('chat.role_admin', 'Admin')}</span>
							{:else if m.powerLevel >= 50}
								<span class="room-settings__tag">{t('chat.role_moderator', 'Moderator')}</span>
							{/if}
							{#if m.canRemove}
								<Button small variant="secondary" onclick={() => void remove(m.userId, m.name)}>
									{t('chat.remove', 'Remove')}
								</Button>
							{/if}
						</li>
					{/each}
				</ul>
			</section>

			<section class="room-settings__section room-settings__section--danger">
				<Button
					variant="danger"
					small
					icon="sign-out-alt"
					disabled={busy}
					onclick={() => void leave()}
				>
					{t('chat.leave', 'Leave')}
				</Button>
			</section>
		</div>
	{/if}
</Modal>

<style>
	.room-settings {
		display: flex;
		flex-direction: column;
		gap: var(--space-4);
	}

	.room-settings__section {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}

	.room-settings__section--danger {
		align-items: flex-start;
		padding-top: var(--space-3);
		border-top: 1px solid var(--color-border);
	}

	.room-settings__heading {
		margin: 0;
		font-size: var(--text-base);
		font-weight: var(--weight-semibold);
	}

	.room-settings__label {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
		font-size: var(--text-sm);
		color: var(--color-text-secondary);
	}

	.room-settings__field {
		flex: 1;
		min-width: 0;
		padding: var(--space-2);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-md);
		background: var(--color-bg-input);
		color: var(--color-text);
		font: inherit;
		font-size: var(--text-base);
	}

	.room-settings__radio {
		display: flex;
		align-items: center;
		gap: var(--space-2);
	}

	.room-settings__hint {
		margin: 0;
		color: var(--color-text-secondary);
		font-size: var(--text-sm);
		overflow-wrap: anywhere;
	}

	.room-settings__actions {
		display: flex;
		justify-content: flex-end;
	}

	.room-settings__members {
		display: flex;
		flex-direction: column;
		margin: 0;
		padding: 0;
		list-style: none;
		max-height: 40vh;
		overflow-y: auto;
	}

	.room-settings__member {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		padding: var(--space-1) 0;
	}

	.room-settings__member-name {
		display: flex;
		flex: 1;
		flex-direction: column;
		min-width: 0;
		overflow-wrap: anywhere;
	}

	.room-settings__muted {
		color: var(--color-text-muted);
		font-size: var(--text-xs);
	}

	.room-settings__tag {
		padding: 0 var(--space-2);
		border-radius: var(--radius-full);
		background: var(--color-bg-muted);
		color: var(--color-text-secondary);
		font-size: var(--text-xs);
	}

	.room-settings__error {
		margin: 0;
		color: var(--color-danger-text);
		overflow-wrap: anywhere;
	}

	.room-settings__notice {
		margin: 0;
		color: var(--color-success-text);
	}
</style>
