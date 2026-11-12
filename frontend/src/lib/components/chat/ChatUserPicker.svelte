<script lang="ts">
	import { t } from '$lib/i18n/index.svelte';
	import type { ChatClient, UserSuggestion } from '$lib/chat/matrix.svelte';

	interface Props {
		chat: ChatClient;
		/** What is typed; set to the Matrix ID when a suggestion is picked. */
		value: string;
		placeholder?: string;
		label: string;
		/** User IDs not to offer (e.g. people already in the room). */
		exclude?: ReadonlySet<string>;
		testid?: string;
	}

	let { chat, value = $bindable(''), placeholder, label, exclude, testid }: Props = $props();

	const listId = `chat-user-picker-${Math.random().toString(36).slice(2, 9)}`;

	let suggestions = $state<UserSuggestion[]>([]);
	let active = $state(-1);
	let open = $state(false);
	/** Drops answers to searches the user has already typed past. */
	let seq = 0;
	let timer: ReturnType<typeof setTimeout> | undefined;

	function search(term: string) {
		clearTimeout(timer);
		const q = term.trim();
		if (!q) {
			suggestions = [];
			open = false;
			return;
		}
		timer = setTimeout(async () => {
			const mine = ++seq;
			try {
				const found = await chat.searchUsers(q);
				if (mine !== seq) return;
				suggestions = exclude ? found.filter((u) => !exclude.has(u.userId)) : found;
				active = suggestions.length > 0 ? 0 : -1;
				open = suggestions.length > 0;
			} catch {
				// Directory unavailable: typing a full name still works.
				if (mine === seq) open = false;
			}
		}, 200);
	}

	function pick(u: UserSuggestion) {
		value = u.userId;
		open = false;
		suggestions = [];
		// A pick is final until the user types again.
		seq++;
		clearTimeout(timer);
	}

	function onkeydown(e: KeyboardEvent) {
		if (!open || suggestions.length === 0) return;
		if (e.key === 'ArrowDown') {
			e.preventDefault();
			active = (active + 1) % suggestions.length;
		} else if (e.key === 'ArrowUp') {
			e.preventDefault();
			active = (active - 1 + suggestions.length) % suggestions.length;
		} else if (e.key === 'Enter' && active >= 0) {
			// Take the suggestion instead of submitting the half-typed name.
			e.preventDefault();
			pick(suggestions[active]);
		} else if (e.key === 'Escape') {
			e.preventDefault();
			e.stopPropagation();
			open = false;
		}
	}
</script>

<div class="picker">
	<input
		class="picker__field"
		type="text"
		role="combobox"
		autocomplete="off"
		aria-autocomplete="list"
		aria-expanded={open}
		aria-controls={listId}
		aria-activedescendant={open && active >= 0 ? `${listId}-${active}` : undefined}
		aria-label={label}
		{placeholder}
		bind:value
		oninput={() => search(value)}
		{onkeydown}
		onblur={() => (open = false)}
		data-testid={testid}
	/>
	{#if open}
		<ul class="picker__list" id={listId} role="listbox" aria-label={label}>
			{#each suggestions as u, i (u.userId)}
				<li
					id={`${listId}-${i}`}
					class="picker__option"
					class:picker__option--active={i === active}
					role="option"
					aria-selected={i === active}
					onmousedown={(e) => {
						// Before the input's blur closes the list.
						e.preventDefault();
						pick(u);
					}}
				>
					<span class="picker__name">{u.name}</span>
					<span class="picker__id">{u.userId}</span>
				</li>
			{/each}
		</ul>
	{/if}
	<span class="sr-only" aria-live="polite">
		{open ? t('chat.suggestions', { n: suggestions.length }, '{{n}} suggestions') : ''}
	</span>
</div>

<style>
	.picker {
		position: relative;
		flex: 1;
		min-width: 0;
	}

	.picker__field {
		width: 100%;
		min-width: 0;
		padding: var(--space-2);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-md);
		background: var(--color-bg-input);
		color: var(--color-text);
		font: inherit;
		font-size: var(--text-base);
	}

	/*
	 * In the flow, not absolutely positioned: the picker sits inside a
	 * Modal and the sidebar, both of which clip overflow, so a floating
	 * list was cut off below the field. Here it pushes the content down.
	 */
	.picker__list {
		margin: var(--space-1) 0 0;
		padding: var(--space-1) 0;
		max-height: 16rem;
		overflow-y: auto;
		list-style: none;
		border: 1px solid var(--color-border);
		border-radius: var(--radius-md);
		background: var(--color-bg-surface);
		box-shadow: var(--shadow-md);
	}

	.picker__option {
		display: flex;
		flex-direction: column;
		padding: var(--space-2) var(--space-3);
		cursor: pointer;
	}

	.picker__option--active,
	.picker__option:hover {
		background: var(--color-bg-hover);
	}

	.picker__name {
		overflow-wrap: anywhere;
	}

	.picker__id {
		color: var(--color-text-muted);
		font-size: var(--text-xs);
		overflow-wrap: anywhere;
	}
</style>
