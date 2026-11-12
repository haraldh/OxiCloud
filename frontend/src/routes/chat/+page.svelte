<script lang="ts">
	import { onDestroy, onMount, tick } from 'svelte';
	import { replaceState } from '$app/navigation';
	import { resolve } from '$app/paths';
	import { page } from '$app/state';
	import Button from '$lib/components/Button.svelte';
	import EmptyState from '$lib/components/EmptyState.svelte';
	import ChatExplore from '$lib/components/chat/ChatExplore.svelte';
	import ChatInviteForm from '$lib/components/chat/ChatInviteForm.svelte';
	import ChatUserPicker from '$lib/components/chat/ChatUserPicker.svelte';
	import Modal from '$lib/components/Modal.svelte';
	import ChatRoomSettings from '$lib/components/chat/ChatRoomSettings.svelte';
	import Icon from '$lib/icons/Icon.svelte';
	import { t } from '$lib/i18n/index.svelte';
	import { serverConfig } from '$lib/stores/serverConfig.svelte';
	import { session } from '$lib/stores/session.svelte';
	import { errorMessage } from '$lib/utils/errors';
	import { chatReturnUrl, takeLoginToken, toUserId } from '$lib/chat/session';
	import type { ChatClient, RoomSummary, TimelineItem } from '$lib/chat/matrix.svelte';

	let chat = $state<ChatClient | null>(null);
	let loadError = $state<string | null>(null);
	let busy = $state(false);
	let actionError = $state<string | null>(null);

	let selectedId = $state<string | null>(null);
	let draft = $state('');
	let recoveryKey = $state('');
	let composer = $state<'none' | 'direct' | 'group'>('none');
	let directTo = $state('');
	let groupName = $state('');
	let groupInvite = $state('');
	let groupPublic = $state(false);
	let copied = $state(false);
	let exploreOpen = $state(false);
	let settingsOpen = $state(false);
	let inviteOpen = $state(false);

	let timelineEl = $state<HTMLElement | null>(null);
	let stickToBottom = true;

	const enabled = $derived(serverConfig.features.chat && !!serverConfig.chat.homeserver_url);
	const rooms = $derived<RoomSummary[]>(chat?.rooms ?? []);
	const selected = $derived(rooms.find((r) => r.id === selectedId) ?? null);
	const items = $derived<TimelineItem[]>(
		chat && selectedId && selected && !selected.isInvite ? chat.timeline(selectedId) : []
	);

	onMount(async () => {
		const ownerId = session.user?.id;
		const homeserver = serverConfig.chat.homeserver_url;
		if (!enabled || !ownerId || !homeserver) return;

		// Take the one-time token off the address bar before using it.
		const { token } = takeLoginToken(location.href);
		if (token) replaceState(resolve('/chat'), page.state);

		try {
			const mod = await import('$lib/chat/matrix.svelte');
			chat = new mod.ChatClient(ownerId, homeserver);
		} catch (err) {
			loadError = errorMessage(err);
			return;
		}
		if (token) await chat.completeSignIn(token);
		else await chat.resume();
	});

	onDestroy(() => chat?.stop());

	// Pick the first room once the list arrives, on wide screens only:
	// on a phone the list IS the first screen.
	$effect(() => {
		if (selectedId || rooms.length === 0) return;
		if (window.matchMedia('(width >= 768px)').matches) selectedId = rooms[0].id;
	});

	// Follow new messages while the user is at the bottom.
	$effect(() => {
		void items.length;
		void selectedId;
		if (!stickToBottom) return;
		void tick().then(() => {
			if (timelineEl) timelineEl.scrollTop = timelineEl.scrollHeight;
		});
	});

	// Read receipts for what's on screen.
	$effect(() => {
		const id = selectedId;
		void items.length;
		if (!chat || !id || document.visibilityState !== 'visible') return;
		void chat.markRead(id).catch(() => undefined);
	});

	function onTimelineScroll() {
		if (!timelineEl) return;
		const { scrollTop, scrollHeight, clientHeight } = timelineEl;
		stickToBottom = scrollHeight - scrollTop - clientHeight < 48;
	}

	async function run(fn: () => Promise<void>) {
		busy = true;
		actionError = null;
		try {
			await fn();
		} catch (err) {
			actionError = errorMessage(err);
		} finally {
			busy = false;
		}
	}

	async function connect() {
		const c = chat;
		if (!c) return;
		await run(async () => {
			location.assign(await c.signInUrl(chatReturnUrl()));
		});
	}

	function select(id: string) {
		selectedId = id;
		stickToBottom = true;
		actionError = null;
	}

	async function send() {
		const c = chat;
		const id = selectedId;
		const text = draft;
		if (!c || !id || !text.trim()) return;
		draft = '';
		stickToBottom = true;
		try {
			await c.send(id, text);
		} catch (err) {
			draft = text;
			actionError = errorMessage(err);
		}
	}

	function onComposerKey(e: KeyboardEvent) {
		if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) {
			e.preventDefault();
			void send();
		}
	}

	async function loadOlder() {
		const c = chat;
		const id = selectedId;
		if (!c || !id || !timelineEl) return;
		const before = timelineEl.scrollHeight;
		stickToBottom = false;
		await run(() => c.loadOlder(id));
		await tick();
		if (timelineEl) timelineEl.scrollTop += timelineEl.scrollHeight - before;
	}

	async function startDirect() {
		const c = chat;
		if (!c) return;
		const userId = toUserId(directTo, c.serverName());
		if (!userId) {
			actionError = t('chat.invalid_user', 'Enter a user name or a Matrix ID like @name:server');
			return;
		}
		await run(async () => {
			selectedId = await c.openDirect(userId);
			composer = 'none';
			directTo = '';
		});
	}

	async function startGroup() {
		const c = chat;
		if (!c || !groupName.trim()) return;
		const invite: string[] = [];
		for (const part of groupInvite.split(/[\s,]+/).filter(Boolean)) {
			const id = toUserId(part, c.serverName());
			if (!id) {
				actionError = t('chat.invalid_user', 'Enter a user name or a Matrix ID like @name:server');
				return;
			}
			invite.push(id);
		}
		await run(async () => {
			selectedId = await c.createGroup(groupName, invite, groupPublic);
			composer = 'none';
			groupName = '';
			groupInvite = '';
			groupPublic = false;
		});
	}

	async function copyRecoveryKey(key: string) {
		try {
			await navigator.clipboard.writeText(key);
			copied = true;
		} catch {
			copied = false;
		}
	}

	function noticeText(item: TimelineItem): string {
		const who = item.notice?.who ?? item.senderName;
		switch (item.notice?.what) {
			case 'join':
				return t('chat.notice_join', { name: who }, '{{name}} joined');
			case 'leave':
				return t('chat.notice_leave', { name: who }, '{{name}} left');
			case 'invite':
				return t('chat.notice_invite', { name: who }, '{{name}} was invited');
			case 'ban':
				return t('chat.notice_ban', { name: who }, '{{name}} was banned');
			case 'encryption':
				return t('chat.notice_encryption', 'Messages in this chat are end-to-end encrypted');
			default:
				return '';
		}
	}

	function timeOf(ts: number): string {
		const d = new Date(ts);
		const today = new Date().toDateString() === d.toDateString();
		return today
			? d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
			: d.toLocaleString([], {
					month: 'short',
					day: 'numeric',
					hour: '2-digit',
					minute: '2-digit'
				});
	}

	function initials(name: string): string {
		const clean = name.replace(/^[@#!]/, '');
		return clean.slice(0, 2).toUpperCase();
	}
</script>

<svelte:head><title>{t('chat.title', 'Chat')} · OxiCloud</title></svelte:head>

{#if !enabled}
	<EmptyState icon="paper-plane" title={t('chat.disabled', 'Chat is not enabled on this server')} />
{:else if loadError}
	<EmptyState icon="exclamation-triangle" title={t('chat.load_failed', 'Chat could not be loaded')}>
		<p>{loadError}</p>
	</EmptyState>
{:else if !chat || chat.status === 'idle' || chat.status === 'starting' || chat.status === 'signing-in'}
	<div class="chat-state" data-testid="chat-connecting">
		<Icon name="spinner" />
		<p>{t('chat.connecting', 'Connecting to chat…')}</p>
	</div>
{:else if chat.status === 'signed-out'}
	<div class="chat-state">
		<Icon name="paper-plane" />
		<h1 class="page-title">{t('chat.title', 'Chat')}</h1>
		<p>
			{t(
				'chat.connect_hint',
				'Chat uses your OxiCloud account. Connect once in this browser to see your conversations.'
			)}
		</p>
		<Button variant="primary" disabled={busy} onclick={connect} data-testid="chat-connect-btn">
			{t('chat.connect', 'Connect to chat')}
		</Button>
		{#if actionError}<p class="chat-error">{actionError}</p>{/if}
	</div>
{:else if chat.status === 'error'}
	{@const c = chat}
	<div class="chat-state">
		<Icon name="exclamation-triangle" />
		<p>{t('chat.error', 'Chat ran into a problem')}</p>
		<p class="chat-error">{c.error}</p>
		<div class="chat-state__actions">
			<Button onclick={() => location.reload()}>{t('chat.retry', 'Try again')}</Button>
			<Button variant="danger" onclick={() => void c.signOut()}>
				{t('chat.disconnect', 'Disconnect')}
			</Button>
		</div>
	</div>
{:else}
	{@const c = chat}
	<div class="chat" class:chat--room-open={selectedId !== null}>
		<aside class="chat__list" aria-label={t('chat.conversations', 'Conversations')}>
			<header class="chat__list-head">
				<h1 class="chat__title">{t('chat.title', 'Chat')}</h1>
				<div class="chat__list-actions">
					<Button
						small
						icon="globe"
						title={t('chat.explore', 'Explore rooms')}
						onclick={() => (exploreOpen = true)}
						data-testid="chat-explore-btn"
					/>
					<Button
						small
						icon="user-plus"
						title={t('chat.new_direct', 'New direct chat')}
						onclick={() => (composer = composer === 'direct' ? 'none' : 'direct')}
						data-testid="chat-new-direct-btn"
					/>
					<Button
						small
						icon="users"
						title={t('chat.new_group', 'New group')}
						onclick={() => (composer = composer === 'group' ? 'none' : 'group')}
						data-testid="chat-new-group-btn"
					/>
				</div>
			</header>

			{#if composer === 'direct'}
				<form
					class="chat__form"
					onsubmit={(e) => {
						e.preventDefault();
						void startDirect();
					}}
				>
					<ChatUserPicker
						chat={c}
						bind:value={directTo}
						label={t('chat.new_direct', 'New direct chat')}
						placeholder={t('chat.direct_placeholder', 'User name or @name:server')}
					/>
					<Button type="submit" variant="primary" small disabled={busy}>
						{t('chat.start', 'Start')}
					</Button>
				</form>
			{:else if composer === 'group'}
				<form
					class="chat__form chat__form--stack"
					onsubmit={(e) => {
						e.preventDefault();
						void startGroup();
					}}
				>
					<input
						class="chat__field"
						bind:value={groupName}
						placeholder={t('chat.group_name', 'Group name')}
						aria-label={t('chat.group_name', 'Group name')}
					/>
					<input
						class="chat__field"
						bind:value={groupInvite}
						placeholder={t('chat.group_invite', 'Invite (user names, comma-separated)')}
						aria-label={t('chat.group_invite', 'Invite (user names, comma-separated)')}
					/>
					<label class="chat__check">
						<input type="checkbox" bind:checked={groupPublic} data-testid="chat-group-public" />
						<span>
							{t('chat.group_public', 'Anyone on this server can find and join')}
							<small class="chat__check-hint">
								{groupPublic
									? t(
											'chat.group_public_hint',
											'Listed in Explore rooms, not encrypted, and never reachable from other servers.'
										)
									: t('chat.group_private_hint', 'Invite-only and end-to-end encrypted.')}
							</small>
						</span>
					</label>
					<Button type="submit" variant="primary" small disabled={busy || !groupName.trim()}>
						{t('chat.create', 'Create')}
					</Button>
				</form>
			{/if}

			{#if rooms.length === 0}
				<p class="chat__empty">{t('chat.no_rooms', 'No conversations yet')}</p>
			{:else}
				<ul class="chat__rooms">
					{#each rooms as room (room.id)}
						<li>
							<button
								type="button"
								class="chat__room"
								class:chat__room--active={room.id === selectedId}
								onclick={() => select(room.id)}
							>
								<span class="chat__avatar" aria-hidden="true">{initials(room.name)}</span>
								<span class="chat__room-name">{room.name}</span>
								{#if room.isInvite}
									<span class="chat__badge chat__badge--invite">{t('chat.invited', 'Invite')}</span>
								{:else if room.unread > 0}
									<span class="chat__badge">{room.unread}</span>
								{/if}
							</button>
						</li>
					{/each}
				</ul>
			{/if}

			<footer class="chat__list-foot">
				<span class="chat__me" title={c.userId ?? ''}>{c.userId}</span>
				<Button small variant="secondary" onclick={() => void c.signOut()}>
					{t('chat.disconnect', 'Disconnect')}
				</Button>
			</footer>
		</aside>

		<section class="chat__room-view">
			{#if c.confirmation}
				{@const conf = c.confirmation}
				<div class="chat-banner">
					<p>
						{t(
							'chat.confirm_popup',
							'Confirm with your OxiCloud account in the window that opened.'
						)}
						<!-- The homeserver's own confirmation page, not an app route. -->
						<!-- eslint-disable-next-line svelte/no-navigation-without-resolve -->
						<a href={conf.url} target="_blank" rel="noopener"
							>{t('chat.open_again', 'Open it again')}</a
						>
					</p>
					<Button small onclick={conf.done}>{t('chat.confirm_done', 'Done')}</Button>
				</div>
			{/if}

			{#if c.newRecoveryKey}
				{@const key = c.newRecoveryKey}
				<div class="chat-banner chat-banner--key">
					<p>
						<strong>{t('chat.recovery_save_title', 'Save your recovery key')}</strong>
						{t(
							'chat.recovery_save_hint',
							'You need it to read encrypted messages on a new device. OxiCloud cannot recover it for you.'
						)}
					</p>
					<code class="chat-banner__key" data-testid="chat-recovery-key">{key}</code>
					<div class="chat-state__actions">
						<Button small icon="copy" onclick={() => void copyRecoveryKey(key)}>
							{copied ? t('chat.copied', 'Copied') : t('chat.copy', 'Copy')}
						</Button>
						<Button small variant="primary" onclick={() => (c.newRecoveryKey = null)}>
							{t('chat.saved_it', "I've saved it")}
						</Button>
					</div>
				</div>
			{:else if c.crypto === 'needs-recovery-key'}
				<form
					class="chat-banner"
					onsubmit={(e) => {
						e.preventDefault();
						void run(async () => {
							await c.unlock(recoveryKey);
							recoveryKey = '';
						});
					}}
				>
					<p>
						<Icon name="lock" />
						{t(
							'chat.unlock_hint',
							'Enter your recovery key to read encrypted messages in this browser.'
						)}
					</p>
					<!--
						Password managers ignore autocomplete="off" on a password
						field and, with no username beside it, filled in the OxiCloud
						login password. Naming the Matrix account makes the recovery
						key its own saved login, offered again on the next unlock.
					-->
					<input
						class="sr-only"
						type="text"
						autocomplete="username"
						value={c.userId ?? ''}
						readonly
						tabindex="-1"
						aria-hidden="true"
					/>
					<input
						class="chat__field"
						type="password"
						autocomplete="current-password"
						bind:value={recoveryKey}
						placeholder={t('chat.recovery_key', 'Recovery key')}
						aria-label={t('chat.recovery_key', 'Recovery key')}
					/>
					<Button type="submit" small variant="primary" disabled={busy || !recoveryKey.trim()}>
						{t('chat.unlock', 'Unlock')}
					</Button>
				</form>
			{:else if c.crypto === 'needs-setup'}
				<div class="chat-banner">
					<p>
						<Icon name="lock" />
						{t(
							'chat.setup_hint',
							'Set up encryption to keep your message history readable on other devices.'
						)}
					</p>
					<Button
						small
						variant="primary"
						disabled={busy}
						onclick={() => void run(() => c.setUpEncryption())}
					>
						{t('chat.setup', 'Set up encryption')}
					</Button>
				</div>
			{/if}

			{#if actionError}
				<p class="chat-error chat-error--bar" role="alert">{actionError}</p>
			{/if}

			{#if !selected}
				<div class="chat-state chat-state--inline">
					<p>{t('chat.pick_room', 'Pick a conversation or start a new one.')}</p>
				</div>
			{:else}
				{@const room = selected}
				<header class="chat__room-head">
					<button
						type="button"
						class="chat__back"
						aria-label={t('chat.back', 'Back to conversations')}
						onclick={() => (selectedId = null)}
					>
						<Icon name="arrow-left" />
					</button>
					<div class="chat__room-heading">
						<h2 class="chat__room-title">{room.name}</h2>
						{#if room.topic}<p class="chat__room-topic" title={room.topic}>{room.topic}</p>{/if}
					</div>
					{#if room.isEncrypted}
						<span class="chat__lock" title={t('chat.encrypted', 'End-to-end encrypted')}>
							<Icon name="lock" />
						</span>
					{/if}
					{#if !room.isInvite}
						<Button
							small
							icon="user-plus"
							title={t('chat.invite_people', 'Invite people')}
							onclick={() => (inviteOpen = true)}
							data-testid="chat-invite-btn"
						/>
						<Button
							small
							icon="cog"
							title={t('chat.room_settings', 'Room settings')}
							onclick={() => (settingsOpen = true)}
							data-testid="chat-settings-btn"
						/>
					{/if}
				</header>

				{#if room.isInvite}
					<div class="chat-state chat-state--inline">
						<p>
							{room.inviter
								? t('chat.invite_from', { name: room.inviter }, '{{name}} invited you')
								: t('chat.invite_plain', 'You were invited')}
						</p>
						<div class="chat-state__actions">
							<Button
								variant="primary"
								disabled={busy}
								onclick={() => void run(() => c.accept(room.id))}
							>
								{t('chat.accept', 'Accept')}
							</Button>
							<Button
								disabled={busy}
								onclick={() =>
									void run(async () => {
										await c.leave(room.id);
										selectedId = null;
									})}
							>
								{t('chat.decline', 'Decline')}
							</Button>
						</div>
					</div>
				{:else}
					<div
						class="chat__timeline"
						bind:this={timelineEl}
						onscroll={onTimelineScroll}
						data-testid="chat-timeline"
					>
						{#if c.canLoadOlder(room.id)}
							<div class="chat__older">
								<Button small disabled={busy} onclick={() => void loadOlder()}>
									{t('chat.load_older', 'Load older messages')}
								</Button>
							</div>
						{/if}
						{#each items as item (item.id)}
							{#if item.kind === 'notice'}
								<p class="chat__notice">{noticeText(item)}</p>
							{:else}
								<div
									class="chat__msg"
									class:chat__msg--own={item.own}
									class:chat__msg--pending={item.pending}
								>
									{#if !item.own}
										<span class="chat__sender">{item.senderName}</span>
									{/if}
									{#if item.kind === 'undecryptable'}
										<p class="chat__body chat__body--locked">
											<Icon name="lock" />
											{t('chat.undecryptable', 'Encrypted message: unlock this browser to read it')}
										</p>
									{:else}
										<p class="chat__body">{item.body}</p>
									{/if}
									<time class="chat__time" datetime={new Date(item.ts).toISOString()}>
										{timeOf(item.ts)}
									</time>
								</div>
							{/if}
						{/each}
					</div>

					<form
						class="chat__composer"
						onsubmit={(e) => {
							e.preventDefault();
							void send();
						}}
					>
						<textarea
							class="chat__field chat__input"
							rows="1"
							bind:value={draft}
							onkeydown={onComposerKey}
							placeholder={t('chat.message_placeholder', 'Write a message…')}
							aria-label={t('chat.message_placeholder', 'Write a message…')}
							data-testid="chat-composer"></textarea>
						<Button type="submit" variant="primary" icon="paper-plane" disabled={!draft.trim()}>
							{t('chat.send', 'Send')}
						</Button>
					</form>
				{/if}
			{/if}
		</section>
	</div>

	<ChatExplore bind:open={exploreOpen} chat={c} onopenroom={select} />
	{#if selectedId}
		<Modal bind:open={inviteOpen} title={t('chat.invite_people', 'Invite people')}>
			{#if inviteOpen}<ChatInviteForm chat={c} roomId={selectedId} />{/if}
		</Modal>
		<ChatRoomSettings
			bind:open={settingsOpen}
			chat={c}
			roomId={selectedId}
			onleft={() => (selectedId = null)}
		/>
	{/if}
{/if}

<style>
	.chat-state {
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: var(--space-3);
		max-width: 32rem;
		margin: var(--space-12) auto;
		text-align: center;
		color: var(--color-text-secondary);
	}

	.chat-state--inline {
		margin: auto;
	}

	.chat-state__actions {
		display: flex;
		gap: var(--space-2);
		flex-wrap: wrap;
		justify-content: center;
	}

	.chat-error {
		color: var(--color-danger-text);
		overflow-wrap: anywhere;
	}

	.chat-error--bar {
		margin: 0;
		padding: var(--space-2) var(--space-4);
		background: var(--color-danger-bg);
	}

	.chat {
		display: grid;
		grid-template-columns: 1fr;
		height: calc(100dvh - 8rem - var(--mobile-nav-height));
		min-height: 24rem;
		background: var(--color-bg-surface);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-2xl);
		overflow: hidden;
	}

	.chat__list,
	.chat__room-view {
		display: flex;
		flex-direction: column;
		min-height: 0;
		min-width: 0;
	}

	/* Phones show one pane at a time. */
	.chat--room-open .chat__list,
	.chat:not(.chat--room-open) .chat__room-view {
		display: none;
	}

	.chat__list {
		border-right: 1px solid var(--color-border);
	}

	.chat__list-head,
	.chat__room-head {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		padding: var(--space-3) var(--space-4);
		border-bottom: 1px solid var(--color-border);
	}

	.chat__title,
	.chat__room-title {
		flex: 1;
		margin: 0;
		font-size: var(--text-lg);
		font-weight: var(--weight-semibold);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.chat__room-heading {
		flex: 1;
		min-width: 0;
	}

	.chat__room-topic {
		margin: 0;
		color: var(--color-text-muted);
		font-size: var(--text-xs);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.chat__list-actions {
		display: flex;
		gap: var(--space-1);
	}

	.chat__form {
		display: flex;
		gap: var(--space-2);
		padding: var(--space-3) var(--space-4);
		border-bottom: 1px solid var(--color-border);
	}

	.chat__form--stack {
		flex-direction: column;
	}

	.chat__check {
		display: flex;
		align-items: flex-start;
		gap: var(--space-2);
		font-size: var(--text-sm);
	}

	.chat__check-hint {
		display: block;
		color: var(--color-text-muted);
	}

	.chat__empty {
		padding: var(--space-4);
		color: var(--color-text-muted);
	}

	.chat__rooms {
		flex: 1;
		margin: 0;
		padding: var(--space-1) 0;
		list-style: none;
		overflow-y: auto;
	}

	.chat__room {
		display: flex;
		align-items: center;
		gap: var(--space-3);
		width: 100%;
		padding: var(--space-2) var(--space-4);
		border: 0;
		background: none;
		color: var(--color-text);
		text-align: left;
		cursor: pointer;
	}

	.chat__room:hover {
		background: var(--color-bg-hover);
	}

	.chat__room--active {
		background: var(--color-accent-bg);
	}

	.chat__avatar {
		display: inline-flex;
		flex: none;
		align-items: center;
		justify-content: center;
		width: 2rem;
		height: 2rem;
		border-radius: var(--radius-full);
		background: var(--color-avatar-gradient);
		color: var(--color-on-accent);
		font-size: var(--text-xs);
		font-weight: var(--weight-semibold);
	}

	.chat__room-name {
		flex: 1;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.chat__badge {
		min-width: 1.25rem;
		padding: 0 var(--space-1);
		border-radius: var(--radius-full);
		background: var(--color-accent);
		color: var(--color-on-accent);
		font-size: var(--text-xs);
		text-align: center;
	}

	.chat__badge--invite {
		background: var(--color-warning-bg);
		color: var(--color-warning-text);
	}

	.chat__list-foot {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		padding: var(--space-2) var(--space-4);
		border-top: 1px solid var(--color-border);
		font-size: var(--text-sm);
	}

	.chat__me {
		flex: 1;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		color: var(--color-text-muted);
	}

	.chat__back {
		display: inline-flex;
		padding: var(--space-1);
		border: 0;
		background: none;
		color: var(--color-text);
		cursor: pointer;
	}

	.chat__lock {
		color: var(--color-success-text);
	}

	.chat-banner {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: var(--space-2);
		padding: var(--space-3) var(--space-4);
		border-bottom: 1px solid var(--color-warning-border);
		background: var(--color-warning-bg-faint);
	}

	.chat-banner p {
		flex: 1 1 16rem;
		margin: 0;
	}

	.chat-banner input {
		flex: 1 1 14rem;
	}

	.chat-banner--key {
		flex-direction: column;
		align-items: stretch;
	}

	.chat-banner__key {
		padding: var(--space-2);
		border-radius: var(--radius-md);
		background: var(--color-bg-muted);
		font-family: var(--font-mono);
		overflow-wrap: anywhere;
		user-select: all;
	}

	.chat__timeline {
		display: flex;
		flex: 1;
		flex-direction: column;
		gap: var(--space-2);
		padding: var(--space-4);
		overflow-y: auto;
	}

	.chat__older {
		display: flex;
		justify-content: center;
	}

	.chat__notice {
		margin: 0;
		color: var(--color-text-muted);
		font-size: var(--text-sm);
		text-align: center;
	}

	.chat__msg {
		align-self: flex-start;
		max-width: min(36rem, 85%);
		padding: var(--space-2) var(--space-3);
		border-radius: var(--radius-xl);
		background: var(--color-bg-muted);
	}

	.chat__msg--own {
		align-self: flex-end;
		background: var(--color-accent-bg);
	}

	.chat__msg--pending {
		opacity: 0.6;
	}

	.chat__sender {
		display: block;
		color: var(--color-accent-text);
		font-size: var(--text-xs);
		font-weight: var(--weight-semibold);
	}

	.chat__body {
		margin: 0;
		white-space: pre-wrap;
		overflow-wrap: anywhere;
	}

	.chat__body--locked {
		color: var(--color-text-muted);
		font-style: italic;
	}

	.chat__time {
		display: block;
		color: var(--color-text-muted);
		font-size: var(--text-xs);
		text-align: right;
	}

	.chat__field {
		min-width: 0;
		padding: var(--space-2);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-md);
		background: var(--color-bg-input);
		color: var(--color-text);
		font: inherit;
		font-size: var(--text-base);
	}

	.chat__form .chat__field {
		flex: 1;
	}

	.chat__composer {
		display: flex;
		align-items: flex-end;
		gap: var(--space-2);
		padding: var(--space-3) var(--space-4);
		border-top: 1px solid var(--color-border);
	}

	.chat__input {
		flex: 1;
		min-height: 2.5rem;
		max-height: 10rem;
		resize: vertical;
	}

	@media (width >= 768px) {
		.chat {
			grid-template-columns: minmax(14rem, 20rem) 1fr;
			height: calc(100dvh - 8rem);
		}

		.chat--room-open .chat__list,
		.chat:not(.chat--room-open) .chat__room-view {
			display: flex;
		}

		.chat__back {
			display: none;
		}
	}
</style>
