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
	KnownMembership,
	MatrixError,
	MatrixEventEvent,
	MsgType,
	NotificationCountType,
	PendingEventOrdering,
	Preset,
	RoomEvent,
	SyncState,
	createClient,
	type MatrixClient,
	type MatrixEvent,
	type Room
} from 'matrix-js-sdk';
import { decodeRecoveryKey } from 'matrix-js-sdk/lib/crypto-api';
import type { AuthDict } from 'matrix-js-sdk/lib/interactive-auth';
import {
	cryptoDbPrefix,
	directRoomIds,
	forgetChatSession,
	loadChatSession,
	matrixBaseUrl,
	originOf,
	saveChatSession,
	serverNameOf,
	ssoRedirectUrl,
	type ChatSession
} from './session';
import { matrixFetch } from './matrixHttp';

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
	unread: number;
	lastTs: number;
	inviter: string | null;
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
}

export type NoticeWhat = 'join' | 'leave' | 'invite' | 'ban' | 'knock' | 'encryption';

/** Raised when the account needs the user to confirm in a popup (UIA over SSO). */
export interface PendingConfirmation {
	url: string;
	done: () => void;
}

const MEGOLM = 'm.megolm.v1.aes-sha2';

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
		client.on(RoomEvent.MyMembership, bump);
		client.on(RoomEvent.Receipt, bump);
		client.on(RoomEvent.LocalEchoUpdated, bump);
		client.on(MatrixEventEvent.Decrypted, bump);
		client.on(HttpApiEvent.SessionLoggedOut, onLoggedOut);
		this.#unsubscribe = () => {
			client.off(ClientEvent.Sync, onSync);
			client.off(ClientEvent.Room, bump);
			client.off(ClientEvent.DeleteRoom, bump);
			client.off(RoomEvent.Timeline, bump);
			client.off(RoomEvent.Name, bump);
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
			const prefix =
				c.msgtype === MsgType.Emote
					? `* ${senderName} `
					: c.msgtype === MsgType.Image ||
						  c.msgtype === MsgType.File ||
						  c.msgtype === MsgType.Video ||
						  c.msgtype === MsgType.Audio
						? '📎 '
						: '';
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

	/** Mark everything up to the newest event in the room as read. */
	async markRead(roomId: string): Promise<void> {
		const client = this.#need();
		const room = client.getRoom(roomId);
		const events = room?.getLiveTimeline().getEvents() ?? [];
		const last = events[events.length - 1];
		if (!room || !last || last.getSender() === this.userId) return;
		if (room.getUnreadNotificationCount(NotificationCountType.Total) === 0) return;
		await client.sendReadReceipt(last);
	}

	async accept(roomId: string): Promise<void> {
		await this.#need().joinRoom(roomId);
	}

	async decline(roomId: string): Promise<void> {
		await this.#need().leave(roomId);
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

	/** Create an encrypted, invite-only room. */
	async createGroup(name: string, invite: string[]): Promise<string> {
		const { room_id } = await this.#need().createRoom({
			name: name.trim(),
			invite,
			preset: Preset.PrivateChat,
			initial_state: [
				{ type: EventType.RoomEncryption, state_key: '', content: { algorithm: MEGOLM } }
			]
		});
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
		if (status?.crossSigningVerified) {
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
