/**
 * Invite with a readable refusal, shared by the room header's invite
 * dialog and the room settings. No SDK import: `ChatClient` comes in as a
 * type, so this stays out of the lazily loaded chunk's way.
 */
import { t } from '$lib/i18n/index.svelte';
import type { ChatClient } from './matrix.svelte';
import type { InviteRefusal } from './session';

export function inviteRefusalText(refusal: InviteRefusal, userId: string): string {
	switch (refusal) {
		case 'member':
			return t('chat.invite_member', { name: userId }, '{{name}} is already in this room');
		case 'invited':
			return t('chat.invite_pending', { name: userId }, '{{name}} has already been invited');
		case 'banned':
			return t('chat.invite_banned', { name: userId }, '{{name}} is banned from this room');
	}
}

/** Invite, or throw an Error whose message says why it was not sent. */
export async function inviteOrExplain(
	chat: Pick<ChatClient, 'invite'>,
	roomId: string,
	userId: string
): Promise<void> {
	const refusal = await chat.invite(roomId, userId);
	if (refusal) throw new Error(inviteRefusalText(refusal, userId));
}
