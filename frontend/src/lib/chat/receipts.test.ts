import { describe, expect, it } from 'vitest';
import { receiptTarget, type ReceiptEvent } from './receipts';

const ME = '@me:example.org';

function ev(id: string, sender: string): ReceiptEvent {
	return { getId: () => id, getSender: () => sender };
}

/** A room whose receipts behave like the SDK's: sending one records it at once. */
function fakeRoom(events: ReceiptEvent[]) {
	const readUpTo = new Map<string, string>();
	return {
		getLiveTimeline: () => ({ getEvents: () => events }),
		hasUserReadEvent: (userId: string, eventId: string) => readUpTo.get(userId) === eventId,
		localEchoReceipt(userId: string, eventId: string) {
			readUpTo.set(userId, eventId);
		}
	};
}

describe('receiptTarget', () => {
	it('picks the newest event from someone else', () => {
		const room = fakeRoom([ev('$1', '@a:x'), ev('$2', '@b:x')]);
		expect(receiptTarget(room, ME)?.getId()).toBe('$2');
	});

	it('skips own messages, empty rooms and a missing user', () => {
		expect(receiptTarget(fakeRoom([ev('$1', ME)]), ME)).toBeNull();
		expect(receiptTarget(fakeRoom([]), ME)).toBeNull();
		expect(receiptTarget(fakeRoom([ev('$1', '@a:x')]), null)).toBeNull();
	});

	// Regression: /chat froze Firefox in unencrypted rooms with unread
	// messages. markRead ran in a page $effect keyed on the timeline; the
	// SDK's local receipt echo emits `Receipt` synchronously, which re-ran the
	// effect, and the unread count (the only guard) stays up until the next
	// sync, so it sent receipts until Svelte aborted with
	// effect_update_depth_exceeded. The receipt must be sent once.
	it('sends one receipt even when the unread count never drops', () => {
		const room = fakeRoom([ev('$1', '@a:x')]);
		let sent = 0;
		for (let rerun = 0; rerun < 50; rerun++) {
			const target = receiptTarget(room, ME);
			if (!target) continue;
			sent++;
			room.localEchoReceipt(ME, target.getId() ?? '');
		}
		expect(sent).toBe(1);
	});

	it('sends again when a newer event arrives', () => {
		const events = [ev('$1', '@a:x')];
		const room = fakeRoom(events);
		room.localEchoReceipt(ME, '$1');
		expect(receiptTarget(room, ME)).toBeNull();
		events.push(ev('$2', '@a:x'));
		expect(receiptTarget(room, ME)?.getId()).toBe('$2');
	});
});
