import { it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';

const REQ = '6f1c2b8e-1a2b-4c3d-8e9f-0123456789ab';

const { pageState, gotoMock } = vi.hoisted(() => ({
	pageState: { params: { id: '' } as Record<string, string> },
	gotoMock: vi.fn()
}));
vi.mock('$app/state', () => ({ page: pageState }));
vi.mock('$app/navigation', () => ({ goto: gotoMock }));
vi.mock('$lib/api/generated/openapi/sdk.gen', () => ({
	idpConsentInfo: vi.fn(),
	idpDecide: vi.fn()
}));

import { idpConsentInfo, idpDecide } from '$lib/api/generated/openapi/sdk.gen';
import ConsentPage from './+page.svelte';

const m = (fn: unknown) => fn as ReturnType<typeof vi.fn>;
const httpError = (status: number) =>
	Object.assign(new Error(String(status)), { response: { status } });
const info = (skip: boolean) => ({
	request_id: REQ,
	client_id: 'chat',
	client_name: 'Chat',
	scopes: ['openid', 'profile', 'email'],
	skip_consent: skip
});

let assigned: string[];
beforeEach(() => {
	vi.clearAllMocks();
	pageState.params = { id: REQ };
	assigned = [];
	Object.defineProperty(window, 'location', {
		configurable: true,
		value: { assign: (u: string) => assigned.push(u) }
	});
});

// A signed-out user must come back to THIS request after login; losing the
// id in the redirect would strand them on /files with the RP waiting.
it('sends a signed-out user to login with a redirect back to the request', async () => {
	m(idpConsentInfo).mockRejectedValue(httpError(401));
	render(ConsentPage);
	await waitFor(() =>
		expect(gotoMock).toHaveBeenCalledWith(
			`/login?redirect=${encodeURIComponent(`/oauth/consent/${REQ}`)}`,
			{ replaceState: true }
		)
	);
	expect(idpDecide).not.toHaveBeenCalled();
});

// First-party clients (the bundled chat server) must not show a prompt;
// the regression would be an extra click on every chat login.
it('auto-approves skip_consent clients and follows the redirect', async () => {
	m(idpConsentInfo).mockResolvedValue(info(true));
	m(idpDecide).mockResolvedValue({ redirect_to: 'https://rp.example/cb?code=x' });
	render(ConsentPage);
	await waitFor(() => expect(assigned).toEqual(['https://rp.example/cb?code=x']));
	expect(idpDecide).toHaveBeenCalledWith(
		expect.objectContaining({ path: { id: REQ }, body: { approve: true } })
	);
});

it('asks third-party clients and sends the decision', async () => {
	m(idpConsentInfo).mockResolvedValue(info(false));
	m(idpDecide).mockResolvedValue({ redirect_to: 'https://rp.example/cb?error=access_denied' });
	render(ConsentPage);
	await fireEvent.click(await screen.findByTestId('idp-consent-deny'));
	await waitFor(() =>
		expect(idpDecide).toHaveBeenCalledWith(expect.objectContaining({ body: { approve: false } }))
	);
	expect(assigned).toEqual(['https://rp.example/cb?error=access_denied']);
});

// Guests get a specific message, not the generic failure: the 403 branch
// must stay distinct from 404 (expired) and 5xx.
it('explains a refused (guest) account', async () => {
	m(idpConsentInfo).mockResolvedValue(info(true));
	m(idpDecide).mockRejectedValue(httpError(403));
	render(ConsentPage);
	const el = await screen.findByTestId('idp-consent-error');
	expect(el.textContent).toMatch(/other services/);
	expect(assigned).toEqual([]);
});

it('reports an expired request', async () => {
	m(idpConsentInfo).mockRejectedValue(httpError(404));
	render(ConsentPage);
	const el = await screen.findByTestId('idp-consent-error');
	expect(el.textContent).toMatch(/expired/);
});
