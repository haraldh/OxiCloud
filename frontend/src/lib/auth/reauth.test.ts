import { describe, expect, it, vi } from 'vitest';
import { ApiError } from '$lib/api/client';
import { isReauthRequired, withReauth } from './reauth';

const reauthRequired = () => new ApiError(403, 'Forbidden', '/api/x', 'ReauthRequired');
const otherForbidden = () => new ApiError(403, 'Forbidden', '/api/x', 'PasskeyNotAllowed');

describe('withReauth', () => {
	it('asks once and retries once when the server wants a fresh confirmation', async () => {
		const fn = vi.fn().mockRejectedValueOnce(reauthRequired()).mockResolvedValueOnce('done');
		const confirm = vi.fn().mockResolvedValue(true);
		await expect(withReauth(fn, confirm)).resolves.toBe('done');
		expect(confirm).toHaveBeenCalledTimes(1);
		expect(fn).toHaveBeenCalledTimes(2);
	});

	it('does not retry when the user cancels the confirmation', async () => {
		const err = reauthRequired();
		const fn = vi.fn().mockRejectedValue(err);
		const confirm = vi.fn().mockResolvedValue(false);
		await expect(withReauth(fn, confirm)).rejects.toBe(err);
		expect(fn).toHaveBeenCalledTimes(1);
	});

	it('never asks for other errors, even other 403s', async () => {
		const err = otherForbidden();
		const fn = vi.fn().mockRejectedValue(err);
		const confirm = vi.fn();
		await expect(withReauth(fn, confirm)).rejects.toBe(err);
		expect(confirm).not.toHaveBeenCalled();
	});

	it('retries only once: a second refusal surfaces instead of looping', async () => {
		const fn = vi.fn().mockRejectedValue(reauthRequired());
		const confirm = vi.fn().mockResolvedValue(true);
		await expect(withReauth(fn, confirm)).rejects.toSatisfy(isReauthRequired);
		expect(confirm).toHaveBeenCalledTimes(1);
		expect(fn).toHaveBeenCalledTimes(2);
	});
});
