/**
 * Chat (Matrix) session bookkeeping that needs no Matrix SDK.
 *
 * Kept apart from `matrix.svelte.ts` so the OxiCloud logout path and the
 * tests can use it without pulling the ~1 MB SDK (plus its crypto WASM)
 * into the main bundle.
 *
 * Sessions are keyed by the OxiCloud user id. Two OxiCloud accounts used in
 * one browser must never see each other's chat, and the crypto store is
 * keyed by Matrix device so a fresh sign-in never reopens another
 * device's keys.
 */
import { withBase } from '$lib/utils/appPath';

const STORAGE_KEY = 'oxi.chat.sessions';
/** IndexedDB name prefix for the Rust crypto store of one Matrix device. */
const CRYPTO_DB_PREFIX = 'oxi-chat';

export interface ChatSession {
	userId: string;
	deviceId: string;
	accessToken: string;
}

type SessionMap = Record<string, ChatSession>;

function isChatSession(v: unknown): v is ChatSession {
	if (!v || typeof v !== 'object') return false;
	const o = v as Record<string, unknown>;
	return (
		typeof o.userId === 'string' &&
		typeof o.deviceId === 'string' &&
		typeof o.accessToken === 'string'
	);
}

function readAll(): SessionMap {
	try {
		const raw = localStorage.getItem(STORAGE_KEY);
		if (!raw) return {};
		const parsed: unknown = JSON.parse(raw);
		if (!parsed || typeof parsed !== 'object') return {};
		const out: SessionMap = {};
		for (const [owner, s] of Object.entries(parsed as Record<string, unknown>)) {
			if (isChatSession(s)) out[owner] = s;
		}
		return out;
	} catch {
		return {};
	}
}

function writeAll(map: SessionMap): void {
	try {
		if (Object.keys(map).length === 0) localStorage.removeItem(STORAGE_KEY);
		else localStorage.setItem(STORAGE_KEY, JSON.stringify(map));
	} catch {
		// Storage blocked: the session just won't survive a reload.
	}
}

export function loadChatSession(ownerId: string): ChatSession | null {
	return readAll()[ownerId] ?? null;
}

export function saveChatSession(ownerId: string, session: ChatSession): void {
	const map = readAll();
	map[ownerId] = session;
	writeAll(map);
}

export function removeChatSession(ownerId: string): void {
	const map = readAll();
	delete map[ownerId];
	writeAll(map);
}

/** The crypto store prefix for one device (`initRustCrypto`'s `cryptoDatabasePrefix`). */
export function cryptoDbPrefix(session: Pick<ChatSession, 'userId' | 'deviceId'>): string {
	return `${CRYPTO_DB_PREFIX}:${session.userId}:${session.deviceId}`;
}

/** Base URL for the Matrix client-server API: OxiCloud's own origin. */
export function matrixBaseUrl(origin: string = location.origin): string {
	return origin + withBase('');
}

/** Where the homeserver sends the browser back to after SSO. */
export function chatReturnUrl(origin: string = location.origin): string {
	return origin + withBase('/chat');
}

/**
 * The homeserver's SSO entry point. Navigated to, not fetched, so the
 * SPA's `connect-src 'self'` doesn't apply, and the grant cookie the
 * homeserver sets lands on its own host, where its callback reads it.
 */
export function ssoRedirectUrl(homeserverUrl: string, idpId: string, returnUrl: string): string {
	const base = homeserverUrl.replace(/\/+$/, '');
	const url = new URL(`${base}/_matrix/client/v3/login/sso/redirect/${encodeURIComponent(idpId)}`);
	url.searchParams.set('redirectUrl', returnUrl);
	return url.toString();
}

/**
 * Pull the one-time `loginToken` off the current URL. Returns the token and
 * the URL without it, so the caller can `replaceState` before the token is
 * used: a token left in the address bar ends up in history and screenshots.
 */
export function takeLoginToken(href: string): { token: string | null; cleaned: string } {
	const url = new URL(href);
	const token = url.searchParams.get('loginToken');
	if (token === null) return { token: null, cleaned: href };
	url.searchParams.delete('loginToken');
	return { token, cleaned: url.toString() };
}

/** Room ids listed in an `m.direct` account-data event's content. */
export function directRoomIds(content: Record<string, unknown>): Set<string> {
	const ids = new Set<string>();
	for (const list of Object.values(content)) {
		if (Array.isArray(list)) for (const id of list) if (typeof id === 'string') ids.add(id);
	}
	return ids;
}

/** `https://m.example.org/x` → `https://m.example.org`. */
export function originOf(url: string): string {
	return new URL(url).origin;
}

/** `@alice:example.org` → `example.org`. */
export function serverNameOf(userId: string): string {
	const i = userId.indexOf(':');
	return i < 0 ? '' : userId.slice(i + 1);
}

/**
 * Turn what someone typed into a Matrix user ID. A bare OxiCloud username
 * becomes a local user (`alice` → `@alice:server`); a full ID passes
 * through. Matrix localparts are lowercase.
 */
export function toUserId(input: string, serverName: string): string | null {
	const s = input.trim();
	if (!s) return null;
	if (s.startsWith('@')) return s.includes(':') && s.length > 3 ? s : null;
	if (!/^[A-Za-z0-9._=\-/+]+$/.test(s)) return null;
	return `@${s.toLowerCase()}:${serverName}`;
}

async function deleteCryptoDatabases(prefix: string): Promise<void> {
	if (typeof indexedDB === 'undefined' || typeof indexedDB.databases !== 'function') return;
	const dbs = await indexedDB.databases();
	await Promise.all(
		dbs
			.map((d) => d.name)
			.filter((n): n is string => typeof n === 'string' && n.startsWith(prefix))
			.map(
				(name) =>
					new Promise<void>((done) => {
						const req = indexedDB.deleteDatabase(name);
						req.onsuccess = req.onerror = req.onblocked = () => done();
					})
			)
	);
}

/**
 * End one stored chat session: log the device out on the homeserver (best
 * effort, so a homeserver that is down can't block an OxiCloud logout),
 * drop the token and wipe that device's crypto store.
 */
export async function forgetChatSession(ownerId: string): Promise<void> {
	const s = loadChatSession(ownerId);
	removeChatSession(ownerId);
	if (!s) return;
	try {
		const { matrixFetch } = await import('./matrixHttp');
		await matrixFetch('/_matrix/client/v3/logout', {
			method: 'POST',
			headers: { Authorization: `Bearer ${s.accessToken}`, 'Content-Type': 'application/json' },
			body: '{}',
			keepalive: true
		});
	} catch {
		// Token already gone or homeserver down; the local copy is gone either way.
	}
	await deleteCryptoDatabases(cryptoDbPrefix(s)).catch(() => undefined);
}

/** Every stored session, for the OxiCloud logout path. */
export async function forgetAllChatSessions(): Promise<void> {
	await Promise.all(Object.keys(readAll()).map((owner) => forgetChatSession(owner)));
}

/**
 * Read what someone typed into the explore box as a room to join directly:
 * `#name:server` and `!id:server` pass through, `#name` gets this server.
 * Anything else is a search term (null).
 */
export function joinTarget(input: string, serverName: string): string | null {
	const s = input.trim();
	if (s.length < 2 || /\s/.test(s)) return null;
	if (s.startsWith('!')) return s.includes(':') ? s : null;
	if (!s.startsWith('#')) return null;
	if (s.includes(':')) return s.length > 3 ? s : null;
	return serverName ? `${s}:${serverName}` : null;
}

/**
 * Whether this browser's device can read the account's encrypted history:
 * the device list says it is cross-signed, or it holds the private master
 * and self-signing keys (which it used to sign itself). The device list
 * only learns of that signature at the next key query, so after an unlock
 * the first test lags and the second answers at once.
 */
export function isDeviceTrusted(
	crossSigningVerified: boolean,
	privateKeys: { masterKey: boolean; selfSigningKey: boolean }
): boolean {
	return crossSigningVerified || (privateKeys.masterKey && privateKeys.selfSigningKey);
}

/** Why an invite would be refused, from the invitee's current membership. */
export type InviteRefusal = 'member' | 'invited' | 'banned';

/**
 * The homeserver answers an invite for someone already joined or banned
 * with a bare 403; check the membership first so the user gets a reason.
 */
export function inviteRefusal(membership: string | undefined): InviteRefusal | null {
	switch (membership) {
		case 'join':
			return 'member';
		case 'invite':
			return 'invited';
		case 'ban':
			return 'banned';
		default:
			return null;
	}
}
