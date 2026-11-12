import { describe, expect, it, vi } from 'vitest';
import { inviteOrExplain } from './invite';
import { inviteRefusal, type InviteRefusal } from './session';

describe('inviteRefusal', () => {
	it('maps memberships that rule out an invite', () => {
		expect(inviteRefusal('join')).toBe('member');
		expect(inviteRefusal('invite')).toBe('invited');
		expect(inviteRefusal('ban')).toBe('banned');
	});

	it('lets everyone else be invited', () => {
		expect(inviteRefusal(undefined)).toBeNull();
		expect(inviteRefusal('leave')).toBeNull();
		expect(inviteRefusal('knock')).toBeNull();
	});
});

describe('inviteOrExplain', () => {
	// Regression: inviting someone already in the room surfaced the raw
	// homeserver error "MatrixError: [403] Auth check failed: cannot invite
	// user that is joined or banned". The refusal must come back as a
	// sentence naming the person, and no invite may be sent.
	it('explains a refusal instead of passing the homeserver error through', async () => {
		const chat = { invite: vi.fn(async (): Promise<InviteRefusal | null> => 'member') };
		await expect(inviteOrExplain(chat, '!r:x', '@bob:x')).rejects.toThrow(
			'@bob:x is already in this room'
		);
	});

	it('resolves when the invite went out', async () => {
		const chat = { invite: vi.fn(async (): Promise<InviteRefusal | null> => null) };
		await expect(inviteOrExplain(chat, '!r:x', '@bob:x')).resolves.toBeUndefined();
		expect(chat.invite).toHaveBeenCalledWith('!r:x', '@bob:x');
	});
});
