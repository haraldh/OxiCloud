/**
 * Which event, if any, a read receipt should go to. Kept apart from
 * `matrix.svelte.ts` (and typed structurally) so it is testable without the
 * Matrix SDK.
 */

export interface ReceiptEvent {
	getId(): string | undefined;
	getSender(): string | undefined;
}

export interface ReceiptRoom<E extends ReceiptEvent = ReceiptEvent> {
	getLiveTimeline(): { getEvents(): E[] };
	hasUserReadEvent(userId: string, eventId: string): boolean;
}

/**
 * The newest event in the room, unless the user sent it or already has a
 * receipt on it (a local echo counts). Returns null when nothing is to send.
 *
 * Must be idempotent: sending a receipt makes the SDK emit `Receipt`
 * synchronously, which re-runs the page effect that asked. The unread count
 * is no guard on its own, since in an unencrypted room it only drops with
 * the next sync.
 */
export function receiptTarget<E extends ReceiptEvent>(
	room: ReceiptRoom<E>,
	userId: string | null
): E | null {
	if (!userId) return null;
	const events = room.getLiveTimeline().getEvents();
	const last = events[events.length - 1];
	const id = last?.getId();
	if (!last || !id || last.getSender() === userId) return null;
	if (room.hasUserReadEvent(userId, id)) return null;
	return last;
}
