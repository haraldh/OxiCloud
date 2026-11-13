/**
 * The chat client: a Matrix session against the deployment's homeserver,
 * with end-to-end encryption through the SDK's Rust crypto.
 *
 * Import this module only through `import()`. It pulls in matrix-js-sdk
 * and, at `initRustCrypto`, a ~8 MB WebAssembly crypto module; neither may
 * end up in the main bundle (AGENTS.md, frontend dependency rule).
 *
 * API calls go to `/_matrix/*` on OxiCloud's own origin (reverse-proxied to
 * the homeserver), because the SPA's CSP allows `connect-src 'self'` only.
 * Sign-in is the homeserver's SSO flow, whose identity provider is
 * OxiCloud itself, so it never asks for a password.
 */
import {
	ClientEvent,
	Direction,
	EventType,
	HttpApiEvent,
	JoinRule,
	KnownMembership,
	MatrixError,
	MatrixEventEvent,
	MsgType,
	NotificationCountType,
	PendingEventOrdering,
	Preset,
	RoomEvent,
	RoomStateEvent,
	SyncState,
	Visibility,
	createClient,
	type MatrixClient,
	type MatrixEvent,
	type Room
} from 'matrix-js-sdk';
import { CryptoEvent, decodeRecoveryKey } from 'matrix-js-sdk/lib/crypto-api';
import type { AuthDict } from 'matrix-js-sdk/lib/interactive-auth';
import {
	cryptoDbPrefix,
	directRoomIds,
	forgetChatSession,
	inviteRefusal,
	isDeviceTrusted,
	loadChatSession,
	matrixBaseUrl,
	originOf,
	saveChatSession,
	serverNameOf,
	ssoRedirectUrl,
	type ChatSession,
	type InviteRefusal
} from './session';
import { matrixFetch } from './matrixHttp';
import { receiptTarget } from './receipts';
import {
	attachmentCaption,
	attachmentFromContent,
	decryptAttachment,
	mediaDownloadPath,
	sourceUrl,
	type Attachment,
	type AttachmentSource
} from './attachment';

export type ChatStatus = 'idle' | 'signing-in' | 'starting' | 'ready' | 'signed-out' | 'error';

/**
 * Where this browser stands with encrypted history:
 * - `ready`: this device is cross-signed, so it receives keys and can
 *   restore older ones from the server-side backup.
 * - `needs-recovery-key`: the account has cross-signing (set up in Element,
 *   say) and this device isn't verified yet.
 * - `needs-setup`: the account has no cross-signing at all.
 */
export type CryptoStatus = 'unknown' | 'ready' | 'needs-recovery-key' | 'needs-setup';

export interface RoomSummary {
	id: string;
	name: string;
	isDirect: boolean;
	isInvite: boolean;
	isEncrypted: boolean;
	topic: string;
	unread: number;
	lastTs: number;
	inviter: string | null;
}

/** A person offered while typing a name to invite or chat with. */
export interface UserSuggestion {
	userId: string;
	name: string;
}

/** One room in the homeserver's public directory. */
export interface PublicRoom {
	id: string;
	name: string;
	topic: string;
	alias: string | null;
	members: number;
	/** The user is already in it. */
	joined: boolean;
}

export interface RoomMemberInfo {
	userId: string;
	name: string;
	membership: 'join' | 'invite';
	powerLevel: number;
	/** The user may remove this member. */
	canRemove: boolean;
}

/** What the settings view shows and what the user may change there. */
export interface RoomDetails {
	id: string;
	name: string;
	topic: string;
	alias: string | null;
	isPublic: boolean;
	/** Created with `m.federate: false`: can never leave this server. */
	localOnly: boolean;
	isEncrypted: boolean;
	isDirect: boolean;
	members: RoomMemberInfo[];
	can: {
		rename: boolean;
		setTopic: boolean;
		setVisibility: boolean;
		enableEncryption: boolean;
		invite: boolean;
	};
}

export type TimelineKind = 'message' | 'notice' | 'undecryptable';

export interface TimelineItem {
	id: string;
	kind: TimelineKind;
	sender: string;
	senderName: string;
	ts: number;
	body: string;
	own: boolean;
	pending: boolean;
	/** For `notice`: whose membership changed (display name), and to what. */
	notice?: { who: string; what: NoticeWhat };
	/** For a media message; `body` is then the caption (often empty). */
	attachment?: Attachment;
}

export type NoticeWhat = 'join' | 'leave' | 'invite' | 'ban' | 'knock' | 'encryption';

/** Raised when the account needs the user to confirm in a popup (UIA over SSO). */
export interface PendingConfirmation {
	url: string;
	done: () => void;
}

const MEGOLM = 'm.megolm.v1.aes-sha2';

function topicOf(room: Room): string {
	const topic = room.currentState.getStateEvents(EventType.RoomTopic, '')?.getContent().topic;
	return typeof topic === 'string' ? topic : '';
}

function isNoticeWhat(v: unknown): v is NoticeWhat {
	return v === 'join' || v === 'leave' || v === 'invite' || v === 'ban' || v === 'knock';
}

export class ChatClient {
	status = $state<ChatStatus>('idle');
	error = $state<string | null>(null);
	crypto = $state<CryptoStatus>('unknown');
	userId = $state<string | null>(null);
	/** Shown once after encryption setup; the user must save it. */
	newRecoveryKey = $state<string | null>(null);
	/** Set while a UIA step waits for the user to confirm in a popup. */
	confirmation = $state<PendingConfirmation | null>(null);
	/** Bumped on every relevant SDK event; reading it makes a getter reactive. */
	#rev = $state(0);

	#client: MatrixClient | null = null;
	#ownerId: string;
	#homeserverUrl: string;
	#ssKey: [string, Uint8Array<ArrayBuffer>] | null = null;
	/** Downloaded (and decrypted) attachments with their `blob:` URLs, by mxc URL. */
	// eslint-disable-next-line svelte/prefer-svelte-reactivity -- a download cache, never read reactively
	#media = new Map<string, Promise<{ blob: Blob; url: string }>>();
	#unsubscribe: (() => void) | null = null;

	constructor(ownerId: string, homeserverUrl: string) {
		this.#ownerId = ownerId;
		this.#homeserverUrl = homeserverUrl;
	}

	// ── sign-in ──────────────────────────────────────────────────────────

	/** The SSO URL to navigate to. Asks the homeserver for its provider id. */
	async signInUrl(returnUrl: string): Promise<string> {
		const res = await matrixFetch('/_matrix/client/v3/login');
		if (!res.ok) throw new Error(`homeserver answered ${res.status}`);
		const body = (await res.json()) as {
			flows?: { type: string; identity_providers?: { id: string }[] }[];
		};
		const sso = body.flows?.find((f) => f.type === 'm.login.sso');
		const idp = sso?.identity_providers?.[0]?.id;
		if (!idp) throw new Error('the homeserver offers no single sign-on');
		return ssoRedirectUrl(this.#homeserverUrl, idp, returnUrl);
	}

	/** Trade the SSO `loginToken` for a device and start. */
	async completeSignIn(loginToken: string): Promise<void> {
		this.status = 'signing-in';
		this.error = null;
		try {
			const tmp = createClient({ baseUrl: matrixBaseUrl() });
			const res = await tmp.loginRequest({
				type: 'm.login.token',
				token: loginToken,
				initial_device_display_name: 'OxiCloud web'
			});
			const session: ChatSession = {
				userId: res.user_id,
				deviceId: res.device_id,
				accessToken: res.access_token
			};
			saveChatSession(this.#ownerId, session);
			await this.#start(session);
		} catch (err) {
			this.#fail(err);
		}
	}

	/** Resume a stored session. Returns false when there is none. */
	async resume(): Promise<boolean> {
		const session = loadChatSession(this.#ownerId);
		if (!session) {
			this.status = 'signed-out';
			return false;
		}
		await this.#start(session);
		return true;
	}

	async signOut(): Promise<void> {
		this.stop();
		await forgetChatSession(this.#ownerId);
		this.userId = null;
		this.crypto = 'unknown';
		this.status = 'signed-out';
	}

	stop(): void {
		this.#unsubscribe?.();
		this.#unsubscribe = null;
		this.#client?.stopClient();
		this.#client = null;
		this.#releaseMedia();
	}

	#releaseMedia(): void {
		for (const m of this.#media.values()) {
			void m.then(
				(x) => URL.revokeObjectURL(x.url),
				() => {}
			);
		}
		this.#media.clear();
	}

	/**
	 * An attachment's bytes: downloaded through authenticated media with
	 * this session's token and, in encrypted rooms, decrypted here (the
	 * homeserver only ever has ciphertext). Cached for the session with a
	 * `blob:` URL; a failure is not cached, so a retry refetches.
	 */
	media(src: AttachmentSource, mimetype?: string): Promise<{ blob: Blob; url: string }> {
		const key = sourceUrl(src);
		const cached = this.#media.get(key);
		if (cached) return cached;
		const pending = this.#download(src, mimetype);
		this.#media.set(key, pending);
		pending.catch(() => this.#media.delete(key));
		return pending;
	}

	/** `media()` as a `blob:` URL, for `<img>`, `<video>` and downloads. */
	async mediaUrl(src: AttachmentSource, mimetype?: string): Promise<string> {
		return (await this.media(src, mimetype)).url;
	}

	async #download(src: AttachmentSource, mimetype?: string): Promise<{ blob: Blob; url: string }> {
		const client = this.#need();
		const path = mediaDownloadPath(sourceUrl(src));
		if (!path) throw new Error('Unsupported media URL');
		const res = await matrixFetch(path, {
			headers: { Authorization: `Bearer ${client.getAccessToken() ?? ''}` }
		});
		if (!res.ok) throw new Error(`Media download failed (${res.status})`);
		let bytes = await res.arrayBuffer();
		if ('file' in src) bytes = await decryptAttachment(bytes, src.file);
		// Never trust the sender's MIME type for active content: only media
		// types render inline; anything else is handed out as a plain blob.
		const type =
			mimetype && /^(image|video|audio)\//.test(mimetype) && !mimetype.includes('svg')
				? mimetype
				: 'application/octet-stream';
		const blob = new Blob([bytes], { type });
		return { blob, url: URL.createObjectURL(blob) };
	}

	async #start(session: ChatSession): Promise<void> {
		this.status = 'starting';
		this.userId = session.userId;
		const client = createClient({
			baseUrl: matrixBaseUrl(),
			accessToken: session.accessToken,
			userId: session.userId,
			deviceId: session.deviceId,
			cryptoCallbacks: {
				getSecretStorageKey: async ({ keys }) => {
					if (this.#ssKey && keys[this.#ssKey[0]]) return this.#ssKey;
					return null;
				},
				cacheSecretStorageKey: (keyId, _info, key) => {
					this.#ssKey = [keyId, key];
				}
			}
		});
		this.#client = client;
		this.#subscribe(client);

		try {
			await client.initRustCrypto({ cryptoDatabasePrefix: cryptoDbPrefix(session) });
			await client.startClient({
				initialSyncLimit: 30,
				lazyLoadMembers: true,
				// Keeps local echoes out of the live timeline; `timeline()` appends
				// them itself. `getPendingEvents()` throws in any other mode.
				pendingEventOrdering: PendingEventOrdering.Detached
			});
		} catch (err) {
			this.#fail(err);
		}
	}

	#subscribe(client: MatrixClient): void {
		const bump = () => {
			this.#rev++;
		};
		const onSync = (state: SyncState) => {
			if (state === SyncState.Prepared) {
				this.status = 'ready';
				void this.refreshCryptoStatus();
			}
			// Before the first sync, an error means we never got in: say so
			// instead of spinning. The SDK keeps retrying, and a later
			// `Prepared` flips the page to ready on its own.
			if (state === SyncState.Error && this.status !== 'ready') {
				this.status = 'error';
				this.error = 'the chat server is not reachable';
			}
			bump();
		};
		const onLoggedOut = () => {
			// Token revoked elsewhere (OxiCloud account disabled, device
			// removed in Element): drop it, the user signs in again.
			void this.signOut();
		};
		client.on(ClientEvent.Sync, onSync);
		client.on(ClientEvent.Room, bump);
		client.on(ClientEvent.DeleteRoom, bump);
		client.on(RoomEvent.Timeline, bump);
		client.on(RoomEvent.Name, bump);
		client.on(RoomStateEvent.Events, bump);
		client.on(RoomEvent.MyMembership, bump);
		client.on(RoomEvent.Receipt, bump);
		client.on(RoomEvent.LocalEchoUpdated, bump);
		client.on(MatrixEventEvent.Decrypted, bump);
		client.on(HttpApiEvent.SessionLoggedOut, onLoggedOut);
		// Trust changes land after the fact (key query after an unlock,
		// verification from another device): re-check the banner then.
		const onTrust = () => {
			if (this.status === 'ready') void this.refreshCryptoStatus();
		};
		client.on(CryptoEvent.UserTrustStatusChanged, onTrust);
		client.on(CryptoEvent.KeysChanged, onTrust);
		client.on(CryptoEvent.DevicesUpdated, onTrust);
		this.#unsubscribe = () => {
			client.off(CryptoEvent.UserTrustStatusChanged, onTrust);
			client.off(CryptoEvent.KeysChanged, onTrust);
			client.off(CryptoEvent.DevicesUpdated, onTrust);
			client.off(ClientEvent.Sync, onSync);
			client.off(ClientEvent.Room, bump);
			client.off(ClientEvent.DeleteRoom, bump);
			client.off(RoomEvent.Timeline, bump);
			client.off(RoomEvent.Name, bump);
			client.off(RoomStateEvent.Events, bump);
			client.off(RoomEvent.MyMembership, bump);
			client.off(RoomEvent.Receipt, bump);
			client.off(RoomEvent.LocalEchoUpdated, bump);
			client.off(MatrixEventEvent.Decrypted, bump);
			client.off(HttpApiEvent.SessionLoggedOut, onLoggedOut);
		};
	}

	#fail(err: unknown): void {
		this.status = 'error';
		this.error = err instanceof Error ? err.message : String(err);
	}

	#need(): MatrixClient {
		if (!this.#client) throw new Error('chat is not connected');
		return this.#client;
	}

	// ── rooms and timeline (reactive reads) ──────────────────────────────

	get rooms(): RoomSummary[] {
		void this.#rev;
		const client = this.#client;
		if (!client || this.status !== 'ready') return [];
		const direct = this.#directRoomIds(client);
		return client
			.getRooms()
			.filter((r) => {
				const m = r.getMyMembership();
				return m === KnownMembership.Join || m === KnownMembership.Invite;
			})
			.map((r) => {
				const isInvite = r.getMyMembership() === KnownMembership.Invite;
				return {
					id: r.roomId,
					name: r.name || r.roomId,
					isDirect: direct.has(r.roomId) || Boolean(r.getDMInviter()),
					isInvite,
					isEncrypted: r.hasEncryptionStateEvent(),
					topic: topicOf(r),
					unread: r.getUnreadNotificationCount(NotificationCountType.Total),
					lastTs: r.getLastActiveTimestamp(),
					inviter: isInvite ? (r.getDMInviter() ?? this.#inviterOf(r)) : null
				};
			})
			.sort((a, b) => Number(b.isInvite) - Number(a.isInvite) || b.lastTs - a.lastTs);
	}

	timeline(roomId: string): TimelineItem[] {
		void this.#rev;
		const room = this.#client?.getRoom(roomId);
		if (!room) return [];
		const out: TimelineItem[] = [];
		for (const ev of room.getLiveTimeline().getEvents()) {
			const item = this.#toItem(room, ev);
			if (item) out.push(item);
		}
		for (const ev of room.getPendingEvents()) {
			const item = this.#toItem(room, ev);
			if (item) out.push({ ...item, pending: true });
		}
		return out;
	}

	/** True while older history may exist above the loaded window. */
	canLoadOlder(roomId: string): boolean {
		void this.#rev;
		const room = this.#client?.getRoom(roomId);
		if (!room) return false;
		return room.getLiveTimeline().getPaginationToken(Direction.Backward) !== null;
	}

	#toItem(room: Room, ev: MatrixEvent): TimelineItem | null {
		const me = this.userId;
		const sender = ev.getSender() ?? '';
		const senderName = room.getMember(sender)?.name ?? sender;
		const base = {
			id: ev.getId() ?? ev.getTxnId() ?? `${ev.getTs()}`,
			sender,
			senderName,
			ts: ev.getTs(),
			own: sender === me,
			pending: false
		};
		if (ev.isRedacted()) return null;

		if (ev.isDecryptionFailure()) {
			return { ...base, kind: 'undecryptable', body: '' };
		}
		const type = ev.getType();
		if (type === EventType.RoomMessageEncrypted) {
			// Still decrypting; it re-renders on `Decrypted`.
			return { ...base, kind: 'undecryptable', body: '' };
		}
		if (type === EventType.RoomMessage) {
			const c = ev.getContent();
			if (typeof c.body !== 'string') return null;
			// Edits arrive as their own events and replace the original's text
			// in clients that support them; show the original only.
			if (c['m.relates_to']?.rel_type === 'm.replace') return null;
			const attachment = attachmentFromContent(c);
			if (attachment) {
				return { ...base, kind: 'message', body: attachmentCaption(c), attachment };
			}
			const prefix = c.msgtype === MsgType.Emote ? `* ${senderName} ` : '';
			return { ...base, kind: 'message', body: prefix + c.body };
		}
		if (type === EventType.RoomMember) {
			const membership = ev.getContent().membership;
			const prev = ev.getPrevContent().membership;
			const who = ev.getContent().displayname ?? ev.getStateKey() ?? '';
			if (membership === prev) return null; // profile change
			if (!isNoticeWhat(membership)) return null;
			return { ...base, kind: 'notice', body: '', notice: { who, what: membership } };
		}
		if (type === EventType.RoomEncryption) {
			return { ...base, kind: 'notice', body: '', notice: { who: senderName, what: 'encryption' } };
		}
		return null;
	}

	#directRoomIds(client: MatrixClient): Set<string> {
		return directRoomIds(client.getAccountData(EventType.Direct)?.getContent() ?? {});
	}

	#inviterOf(room: Room): string | null {
		const me = this.userId;
		if (!me) return null;
		const ev = room.currentState.getStateEvents(EventType.RoomMember, me);
		return ev?.getSender() ?? null;
	}

	// ── actions ──────────────────────────────────────────────────────────

	async loadOlder(roomId: string): Promise<void> {
		const client = this.#need();
		const room = client.getRoom(roomId);
		if (room) await client.scrollback(room, 30);
	}

	async send(roomId: string, body: string): Promise<void> {
		const text = body.trim();
		if (!text) return;
		await this.#need().sendTextMessage(roomId, text);
	}

	/**
	 * Mark everything up to the newest event in the room as read. Sends at
	 * most one receipt per event: see `receiptTarget`.
	 */
	async markRead(roomId: string): Promise<void> {
		const client = this.#need();
		const room = client.getRoom(roomId);
		if (!room || room.getUnreadNotificationCount(NotificationCountType.Total) === 0) return;
		const last = receiptTarget(room, this.userId);
		if (last) await client.sendReadReceipt(last);
	}

	async accept(roomId: string): Promise<void> {
		await this.#need().joinRoom(roomId);
	}

	/** Leave a room, or decline an invite to it. */
	async leave(roomId: string): Promise<void> {
		await this.#need().leave(roomId);
	}

	/** Join by room id or `#alias:server`; returns the room id. */
	async join(idOrAlias: string): Promise<string> {
		const room = await this.#need().joinRoom(idOrAlias);
		return room.roomId;
	}

	/** Search the homeserver's public room directory. */
	async searchPublicRooms(
		term: string,
		since?: string
	): Promise<{ rooms: PublicRoom[]; next: string | null }> {
		const client = this.#need();
		const q = term.trim();
		const res = await client.publicRooms({
			limit: 30,
			since,
			...(q ? { filter: { generic_search_term: q } } : {})
		});
		const rooms = res.chunk.map((r) => ({
			id: r.room_id,
			name: r.name || r.canonical_alias || r.room_id,
			topic: r.topic ?? '',
			alias: r.canonical_alias ?? null,
			members: r.num_joined_members,
			joined: client.getRoom(r.room_id)?.getMyMembership() === KnownMembership.Join
		}));
		return { rooms, next: res.next_batch ?? null };
	}

	/** People matching a name or Matrix ID, from the homeserver's user directory. */
	async searchUsers(term: string, limit = 8): Promise<UserSuggestion[]> {
		const q = term.trim();
		if (!q) return [];
		const res = await this.#need().searchUserDirectory({ term: q, limit });
		return res.results.map((u) => ({
			userId: u.user_id,
			name: u.display_name || u.user_id
		}));
	}

	/**
	 * Invite someone, unless their membership already rules it out: then
	 * nothing is sent and the reason comes back for the page to show.
	 */
	async invite(roomId: string, userId: string): Promise<InviteRefusal | null> {
		const client = this.#need();
		const room = client.getRoom(roomId);
		// Members load lazily; without the full list a joined user looks absent.
		await room?.loadMembersIfNeeded();
		const refusal = inviteRefusal(room?.getMember(userId)?.membership);
		if (refusal) return refusal;
		await client.invite(roomId, userId);
		return null;
	}

	async remove(roomId: string, userId: string): Promise<void> {
		await this.#need().kick(roomId, userId);
	}

	/**
	 * Members are loaded lazily (`lazyLoadMembers`); call this before
	 * showing `details()`, which then includes everyone.
	 */
	async loadMembers(roomId: string): Promise<void> {
		await this.#need().getRoom(roomId)?.loadMembersIfNeeded();
		this.#rev++;
	}

	details(roomId: string): RoomDetails | null {
		void this.#rev;
		const client = this.#client;
		const me = this.userId;
		const room = client?.getRoom(roomId);
		if (!client || !room || !me) return null;
		const state = room.currentState;
		const myLevel = room.getMember(me)?.powerLevel ?? 0;
		const mayKick = state.hasSufficientPowerLevelFor('kick', myLevel);
		const members: RoomMemberInfo[] = room
			.getMembers()
			.filter(
				(m) => m.membership === KnownMembership.Join || m.membership === KnownMembership.Invite
			)
			.map((m) => ({
				userId: m.userId,
				name: m.name || m.userId,
				membership: m.membership === KnownMembership.Invite ? 'invite' : 'join',
				powerLevel: m.powerLevel,
				canRemove: m.userId !== me && mayKick && m.powerLevel < myLevel
			}));
		members.sort((a, b) => b.powerLevel - a.powerLevel || a.name.localeCompare(b.name));
		const isEncrypted = room.hasEncryptionStateEvent();
		return {
			id: room.roomId,
			name: room.name || room.roomId,
			topic: topicOf(room),
			alias: room.getCanonicalAlias(),
			isPublic: room.getJoinRule() === JoinRule.Public,
			localOnly:
				state.getStateEvents(EventType.RoomCreate, '')?.getContent()['m.federate'] === false,
			isEncrypted,
			isDirect: this.#directRoomIds(client).has(room.roomId),
			members,
			can: {
				rename: state.maySendStateEvent(EventType.RoomName, me),
				setTopic: state.maySendStateEvent(EventType.RoomTopic, me),
				setVisibility: state.maySendStateEvent(EventType.RoomJoinRules, me),
				enableEncryption: !isEncrypted && state.maySendStateEvent(EventType.RoomEncryption, me),
				invite: room.canInvite(me)
			}
		};
	}

	async setName(roomId: string, name: string): Promise<void> {
		await this.#need().setRoomName(roomId, name.trim());
	}

	async setTopic(roomId: string, topic: string): Promise<void> {
		await this.#need().setRoomTopic(roomId, topic.trim());
	}

	/**
	 * Public: anyone on the server can find the room in the directory and
	 * join. Otherwise invite-only and unlisted.
	 */
	async setPublic(roomId: string, isPublic: boolean): Promise<void> {
		const client = this.#need();
		await client.sendStateEvent(
			roomId,
			EventType.RoomJoinRules,
			{ join_rule: isPublic ? JoinRule.Public : JoinRule.Invite },
			''
		);
		await client.setRoomDirectoryVisibility(
			roomId,
			isPublic ? Visibility.Public : Visibility.Private
		);
	}

	/** Turn on end-to-end encryption. Matrix offers no way back. */
	async enableEncryption(roomId: string): Promise<void> {
		await this.#need().sendStateEvent(roomId, EventType.RoomEncryption, { algorithm: MEGOLM }, '');
	}

	/** Open (or reuse) an encrypted direct chat with one user. */
	async openDirect(userId: string): Promise<string> {
		const client = this.#need();
		const content = client.getAccountData(EventType.Direct)?.getContent() ?? {};
		const existing = (content[userId] as string[] | undefined)?.find(
			(id) => client.getRoom(id)?.getMyMembership() === KnownMembership.Join
		);
		if (existing) return existing;

		const { room_id } = await client.createRoom({
			is_direct: true,
			invite: [userId],
			preset: Preset.TrustedPrivateChat,
			initial_state: [
				{ type: EventType.RoomEncryption, state_key: '', content: { algorithm: MEGOLM } }
			]
		});
		const next = { ...content, [userId]: [...((content[userId] as string[]) ?? []), room_id] };
		await client.setAccountData(EventType.Direct, next);
		return room_id;
	}

	/**
	 * Create a group. Private: encrypted and invite-only. Public: anyone on
	 * this server can find and join it, and `m.federate: false` (fixed at
	 * creation) keeps it on this server even if federation is turned on
	 * later. Public rooms start unencrypted, as in Element; settings can
	 * turn encryption on.
	 */
	async createGroup(name: string, invite: string[], isPublic = false): Promise<string> {
		const { room_id } = await this.#need().createRoom(
			isPublic
				? {
						name: name.trim(),
						invite,
						preset: Preset.PublicChat,
						visibility: Visibility.Public,
						creation_content: { 'm.federate': false }
					}
				: {
						name: name.trim(),
						invite,
						preset: Preset.PrivateChat,
						initial_state: [
							{ type: EventType.RoomEncryption, state_key: '', content: { algorithm: MEGOLM } }
						]
					}
		);
		return room_id;
	}

	serverName(): string {
		return this.userId ? serverNameOf(this.userId) : '';
	}

	// ── encryption ───────────────────────────────────────────────────────

	async refreshCryptoStatus(): Promise<void> {
		const client = this.#client;
		const crypto = client?.getCrypto();
		const userId = client?.getUserId();
		const deviceId = client?.getDeviceId();
		if (!crypto || !userId || !deviceId) return;
		const status = await crypto.getDeviceVerificationStatus(userId, deviceId);
		// Right after an unlock or setup, the device list still lacks this
		// device's new signature until the next key query, so
		// `crossSigningVerified` lags. Holding the private cross-signing keys
		// (bootstrapCrossSigning signed this device with them) is the same
		// trust, available at once.
		const keys = (await crypto.getCrossSigningStatus()).privateKeysCachedLocally;
		if (isDeviceTrusted(status?.crossSigningVerified ?? false, keys)) {
			this.crypto = 'ready';
			// Keys arrive in the backup continuously; make sure it's on.
			void crypto.checkKeyBackupAndEnable();
			return;
		}
		this.crypto = (await crypto.userHasCrossSigningKeys(userId, true))
			? 'needs-recovery-key'
			: 'needs-setup';
	}

	/**
	 * Unlock with the recovery key the account already has (from Element or
	 * an earlier setup here): cross-sign this device, then restore the
	 * message keys from the server-side backup.
	 */
	async unlock(recoveryKey: string): Promise<void> {
		const client = this.#need();
		const crypto = client.getCrypto();
		if (!crypto) throw new Error('encryption is not available');

		const key = decodeRecoveryKey(recoveryKey.replace(/\s+/g, ' ').trim());
		const tuple = await client.secretStorage.getKey();
		if (!tuple) throw new Error('no recovery key is set up for this account');
		const [keyId, info] = tuple;
		if (!(await client.secretStorage.checkKey(key, info))) {
			throw new Error('wrong recovery key');
		}
		this.#ssKey = [keyId, key];

		// bootstrapCrossSigning() creates a NEW identity when it can't read
		// the existing one from secret storage, which would throw away the
		// account's verification state. Only go on when this key can.
		const stored = await client.secretStorage.isStored('m.cross_signing.master');
		if (!stored || !stored[keyId]) {
			throw new Error('this recovery key does not unlock the cross-signing keys');
		}

		await crypto.bootstrapCrossSigning({});
		await crypto.loadSessionBackupPrivateKeyFromSecretStorage();
		await crypto.checkKeyBackupAndEnable();
		await this.refreshCryptoStatus();
		// Can take a while for a long history; messages re-render as keys land.
		void crypto
			.restoreKeyBackup()
			.then(() => this.#rev++)
			.catch(() => undefined);
	}

	/**
	 * First-time setup for an account without cross-signing: create the
	 * identity, a recovery key and the server-side key backup. The recovery
	 * key lands in `newRecoveryKey` for the user to save.
	 */
	async setUpEncryption(): Promise<void> {
		const crypto = this.#need().getCrypto();
		if (!crypto) throw new Error('encryption is not available');

		await crypto.bootstrapCrossSigning({
			authUploadDeviceSigningKeys: (makeRequest) => this.#withUia(makeRequest)
		});
		let generated: string | null = null;
		await crypto.bootstrapSecretStorage({
			setupNewSecretStorage: true,
			setupNewKeyBackup: true,
			createSecretStorageKey: async () => {
				const k = await crypto.createRecoveryKeyFromPassphrase();
				generated = k.encodedPrivateKey ?? null;
				return k;
			}
		});
		this.newRecoveryKey = generated;
		await this.refreshCryptoStatus();
	}

	/**
	 * User-interactive auth for SSO accounts: the homeserver wants the user
	 * to re-confirm through the identity provider. Try without auth first
	 * (a first cross-signing upload needs none, MSC3967), and on a 401 open
	 * the homeserver's fallback page and retry with the session once the
	 * user is done there.
	 */
	async #withUia<T>(makeRequest: (auth: AuthDict | null) => Promise<T>): Promise<T> {
		try {
			return await makeRequest(null);
		} catch (err) {
			if (!(err instanceof MatrixError) || err.httpStatus !== 401) throw err;
			const session = (err.data as { session?: unknown }).session;
			if (typeof session !== 'string') throw err;
			const url = `${this.#homeserverUrl}/_matrix/client/v3/auth/m.login.sso/fallback/web?session=${encodeURIComponent(session)}`;
			await this.#confirmInPopup(url);
			return makeRequest({ session });
		}
	}

	#confirmInPopup(url: string): Promise<void> {
		return new Promise((resolve) => {
			const popup = window.open(url, 'oxi-chat-confirm', 'width=520,height=680');
			let finished = false;
			const finish = () => {
				if (finished) return;
				finished = true;
				window.removeEventListener('message', onMessage);
				clearInterval(poll);
				this.confirmation = null;
				resolve();
			};
			const homeserverOrigin = originOf(this.#homeserverUrl);
			// The fallback page posts "authDone" to its opener when finished.
			const onMessage = (e: MessageEvent) => {
				if (e.origin === homeserverOrigin && e.data === 'authDone') finish();
			};
			window.addEventListener('message', onMessage);
			const poll = setInterval(() => {
				if (popup?.closed) finish();
			}, 500);
			// A blocked popup leaves the user a link and a "done" button.
			this.confirmation = { url, done: finish };
		});
	}
}
