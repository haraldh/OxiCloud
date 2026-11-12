import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
	cryptoDbPrefix,
	forgetChatSession,
	loadChatSession,
	saveChatSession,
	ssoRedirectUrl,
	takeLoginToken,
	toUserId
} from './session';

const alice = { userId: '@alice:example.org', deviceId: 'DEV1', accessToken: 'tok-a' };
const bob = { userId: '@bob:example.org', deviceId: 'DEV2', accessToken: 'tok-b' };

beforeEach(() => {
	localStorage.clear();
});

describe('chat sessions', () => {
	// Two OxiCloud accounts in one browser (the "Kein Home-Ordner" setup on
	// oxi.hoyer.xyz) must never pick up each other's Matrix token.
	it('keeps one session per OxiCloud user', () => {
		saveChatSession('owner-a', alice);
		saveChatSession('owner-b', bob);
		expect(loadChatSession('owner-a')).toEqual(alice);
		expect(loadChatSession('owner-b')).toEqual(bob);
		expect(loadChatSession('owner-c')).toBeNull();
	});

	it('ignores malformed storage instead of throwing', () => {
		localStorage.setItem('oxi.chat.sessions', '{"owner-a":{"userId":1}}');
		expect(loadChatSession('owner-a')).toBeNull();
		localStorage.setItem('oxi.chat.sessions', 'not json');
		expect(loadChatSession('owner-a')).toBeNull();
	});

	// A homeserver that is down must not keep the token around: the local
	// copy goes first, the remote logout is best effort.
	it('forgets the token even when the homeserver logout fails', async () => {
		saveChatSession('owner-a', alice);
		saveChatSession('owner-b', bob);
		const fetchMock = vi.fn<typeof fetch>().mockRejectedValue(new Error('down'));
		vi.stubGlobal('fetch', fetchMock);
		await forgetChatSession('owner-a');
		vi.unstubAllGlobals();
		expect(fetchMock).toHaveBeenCalledOnce();
		expect(loadChatSession('owner-a')).toBeNull();
		expect(loadChatSession('owner-b')).toEqual(bob);
	});

	it('keys the crypto store by device', () => {
		expect(cryptoDbPrefix(alice)).toBe('oxi-chat:@alice:example.org:DEV1');
		expect(cryptoDbPrefix({ ...alice, deviceId: 'DEV9' })).not.toBe(cryptoDbPrefix(alice));
	});
});

describe('sign-in URLs', () => {
	it('builds the SSO redirect on the homeserver, not on OxiCloud', () => {
		const url = new URL(
			ssoRedirectUrl('https://matrix.example.org/', 'tuwunel', 'https://oxi.example.org/chat')
		);
		expect(url.origin).toBe('https://matrix.example.org');
		expect(url.pathname).toBe('/_matrix/client/v3/login/sso/redirect/tuwunel');
		expect(url.searchParams.get('redirectUrl')).toBe('https://oxi.example.org/chat');
	});

	// The login token is single-use but still a credential until redeemed;
	// it must come off the address bar before anything else happens.
	it('strips loginToken and keeps the rest of the URL', () => {
		const r = takeLoginToken('https://oxi.example.org/chat?loginToken=abc&x=1');
		expect(r.token).toBe('abc');
		expect(r.cleaned).toBe('https://oxi.example.org/chat?x=1');
		expect(takeLoginToken('https://oxi.example.org/chat').token).toBeNull();
	});
});

describe('toUserId', () => {
	it('maps a bare username to a local Matrix ID', () => {
		expect(toUserId('Harald', 'hoyer.xyz')).toBe('@harald:hoyer.xyz');
	});
	it('passes a full Matrix ID through', () => {
		expect(toUserId(' @bob:other.org ', 'hoyer.xyz')).toBe('@bob:other.org');
	});
	it('rejects what cannot be a user', () => {
		expect(toUserId('', 'hoyer.xyz')).toBeNull();
		expect(toUserId('@bob', 'hoyer.xyz')).toBeNull();
		expect(toUserId('two words', 'hoyer.xyz')).toBeNull();
	});
});
