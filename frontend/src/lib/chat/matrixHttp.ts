/**
 * The one raw `fetch` for chat code outside matrix-js-sdk.
 *
 * The Matrix client-server API is not OxiCloud's API, so the generated
 * client doesn't cover it; this is the chat counterpart of
 * `lib/api/transport.ts` (named apart from it: `transport` imports are lint-restricted) and is exempted from the `fetch` lint rule on the
 * same terms. Requests stay on OxiCloud's origin (`/_matrix/*`, forwarded
 * to the homeserver by the reverse proxy).
 */
import { matrixBaseUrl } from './session';

export function matrixFetch(path: string, init?: RequestInit): Promise<Response> {
	return fetch(`${matrixBaseUrl()}${path}`, init);
}
