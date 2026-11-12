<script lang="ts">
	import Button from '$lib/components/Button.svelte';
	import Modal from '$lib/components/Modal.svelte';
	import { t } from '$lib/i18n/index.svelte';
	import { errorMessage } from '$lib/utils/errors';
	import { joinTarget } from '$lib/chat/session';
	import type { ChatClient, PublicRoom } from '$lib/chat/matrix.svelte';

	interface Props {
		open: boolean;
		chat: ChatClient;
		/** A room was joined (or was already joined) and should be shown. */
		onopenroom: (roomId: string) => void;
	}

	let { open = $bindable(false), chat, onopenroom }: Props = $props();

	let term = $state('');
	let results = $state<PublicRoom[]>([]);
	let next = $state<string | null>(null);
	let loading = $state(false);
	let joining = $state<string | null>(null);
	let error = $state<string | null>(null);
	/** Drops answers to searches the user has already typed past. */
	let seq = 0;

	const direct = $derived(joinTarget(term, chat.serverName()));

	async function search(more = false) {
		const mine = ++seq;
		loading = true;
		error = null;
		try {
			const res = await chat.searchPublicRooms(term, more ? (next ?? undefined) : undefined);
			if (mine !== seq) return;
			results = more ? [...results, ...res.rooms] : res.rooms;
			next = res.next;
		} catch (err) {
			if (mine === seq) error = errorMessage(err);
		} finally {
			if (mine === seq) loading = false;
		}
	}

	// List the directory on open, and search again as the user types.
	let timer: ReturnType<typeof setTimeout> | undefined;
	$effect(() => {
		if (!open) return;
		void term;
		clearTimeout(timer);
		timer = setTimeout(() => void search(), 250);
		return () => clearTimeout(timer);
	});

	async function join(idOrAlias: string, alreadyJoined = false) {
		if (alreadyJoined) {
			open = false;
			onopenroom(idOrAlias);
			return;
		}
		joining = idOrAlias;
		error = null;
		try {
			const roomId = await chat.join(idOrAlias);
			open = false;
			onopenroom(roomId);
		} catch (err) {
			error = errorMessage(err);
		} finally {
			joining = null;
		}
	}
</script>

<Modal bind:open title={t('chat.explore', 'Explore rooms')} size="lg">
	<div class="explore">
		<form
			class="explore__search"
			onsubmit={(e) => {
				e.preventDefault();
				if (direct) void join(direct);
				else void search();
			}}
		>
			<input
				class="explore__field"
				type="search"
				bind:value={term}
				placeholder={t('chat.explore_placeholder', 'Search rooms, or enter #room:server')}
				aria-label={t('chat.explore', 'Explore rooms')}
				data-testid="chat-explore-input"
			/>
			{#if direct}
				<Button type="submit" variant="primary" small disabled={joining !== null}>
					{t('chat.join_alias', { room: direct }, 'Join {{room}}')}
				</Button>
			{/if}
		</form>

		{#if error}<p class="explore__error" role="alert">{error}</p>{/if}

		{#if results.length === 0 && !loading}
			<p class="explore__empty">{t('chat.explore_empty', 'No public rooms found')}</p>
		{:else}
			<ul class="explore__list">
				{#each results as room (room.id)}
					<li class="explore__room">
						<div class="explore__info">
							<span class="explore__name">{room.name}</span>
							{#if room.alias && room.alias !== room.name}
								<span class="explore__alias">{room.alias}</span>
							{/if}
							{#if room.topic}<span class="explore__topic">{room.topic}</span>{/if}
							<span class="explore__members">
								{t('chat.member_count', { n: room.members }, '{{n}} members')}
							</span>
						</div>
						<Button
							small
							variant={room.joined ? 'secondary' : 'primary'}
							disabled={joining !== null}
							onclick={() => void join(room.id, room.joined)}
						>
							{room.joined ? t('chat.open', 'Open') : t('chat.join', 'Join')}
						</Button>
					</li>
				{/each}
			</ul>
			{#if next}
				<div class="explore__more">
					<Button small disabled={loading} onclick={() => void search(true)}>
						{t('chat.load_more', 'Load more')}
					</Button>
				</div>
			{/if}
		{/if}
	</div>
</Modal>

<style>
	.explore {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
	}

	.explore__search {
		display: flex;
		flex-wrap: wrap;
		gap: var(--space-2);
	}

	.explore__field {
		flex: 1 1 14rem;
		min-width: 0;
		padding: var(--space-2);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-md);
		background: var(--color-bg-input);
		color: var(--color-text);
		font: inherit;
		font-size: var(--text-base);
	}

	.explore__error {
		margin: 0;
		color: var(--color-danger-text);
		overflow-wrap: anywhere;
	}

	.explore__empty {
		margin: 0;
		color: var(--color-text-muted);
	}

	.explore__list {
		display: flex;
		flex-direction: column;
		margin: 0;
		padding: 0;
		list-style: none;
		max-height: 60vh;
		overflow-y: auto;
	}

	.explore__room {
		display: flex;
		align-items: center;
		gap: var(--space-3);
		padding: var(--space-2) 0;
		border-bottom: 1px solid var(--color-border);
	}

	.explore__info {
		display: flex;
		flex: 1;
		flex-direction: column;
		min-width: 0;
	}

	.explore__name {
		font-weight: var(--weight-semibold);
		overflow-wrap: anywhere;
	}

	.explore__alias,
	.explore__members {
		color: var(--color-text-muted);
		font-size: var(--text-xs);
	}

	.explore__topic {
		color: var(--color-text-secondary);
		font-size: var(--text-sm);
		overflow-wrap: anywhere;
	}

	.explore__more {
		display: flex;
		justify-content: center;
	}
</style>
