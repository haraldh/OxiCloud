<script lang="ts">
	import Button from '$lib/components/Button.svelte';
	import ChatUserPicker from '$lib/components/chat/ChatUserPicker.svelte';
	import { t } from '$lib/i18n/index.svelte';
	import { errorMessage } from '$lib/utils/errors';
	import { inviteOrExplain } from '$lib/chat/invite';
	import { toUserId } from '$lib/chat/session';
	import type { ChatClient } from '$lib/chat/matrix.svelte';

	interface Props {
		chat: ChatClient;
		roomId: string;
		/** Called after an invite went out. */
		oninvited?: (userId: string) => void;
	}

	let { chat, roomId, oninvited }: Props = $props();

	let to = $state('');
	let busy = $state(false);
	let error = $state<string | null>(null);
	let notice = $state<string | null>(null);

	// People already in the room (or invited) aren't offered again.
	const exclude = $derived(new Set(chat.details(roomId)?.members.map((m) => m.userId) ?? []));

	async function invite() {
		const userId = toUserId(to, chat.serverName());
		error = null;
		notice = null;
		if (!userId) {
			error = t('chat.invalid_user', 'Enter a user name or a Matrix ID like @name:server');
			return;
		}
		busy = true;
		try {
			await inviteOrExplain(chat, roomId, userId);
			to = '';
			notice = t('chat.invited_user', { name: userId }, '{{name}} was invited');
			oninvited?.(userId);
		} catch (err) {
			error = errorMessage(err);
		} finally {
			busy = false;
		}
	}
</script>

<form
	class="invite-form"
	onsubmit={(e) => {
		e.preventDefault();
		void invite();
	}}
>
	<div class="invite-form__row">
		<ChatUserPicker
			{chat}
			bind:value={to}
			{exclude}
			label={t('chat.invite_people', 'Invite people')}
			placeholder={t('chat.direct_placeholder', 'User name or @name:server')}
			testid="chat-invite-input"
		/>
		<Button type="submit" small icon="user-plus" disabled={busy || !to.trim()}>
			{t('chat.invite', 'Invite')}
		</Button>
	</div>
	{#if error}<p class="invite-form__error" role="alert">{error}</p>{/if}
	{#if notice}<p class="invite-form__notice" role="status">{notice}</p>{/if}
</form>

<style>
	.invite-form {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}

	.invite-form__row {
		display: flex;
		align-items: flex-start;
		gap: var(--space-2);
	}

	.invite-form__error {
		margin: 0;
		color: var(--color-danger-text);
		overflow-wrap: anywhere;
	}

	.invite-form__notice {
		margin: 0;
		color: var(--color-success-text);
	}
</style>
