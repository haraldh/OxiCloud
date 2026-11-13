import { beforeEach, describe, expect, it, vi } from 'vitest';

const api = vi.hoisted(() => ({
	listFolder: vi.fn(),
	createFolder: vi.fn(),
	uploadFile: vi.fn(),
	loadHomeFolder: vi.fn()
}));

vi.mock('$lib/api/endpoints/folders', () => ({
	listFolder: api.listFolder,
	createFolder: api.createFolder
}));
vi.mock('$lib/api/endpoints/files', () => ({ uploadFile: api.uploadFile }));
vi.mock('$lib/stores/session.svelte', () => ({
	session: { loadHomeFolder: api.loadHomeFolder }
}));

import { saveToChatFolder } from './saveToFiles';

const listing = (folders: { id: string; name: string }[], files: { name: string }[] = []) => ({
	folders,
	files
});

beforeEach(() => {
	vi.clearAllMocks();
	api.loadHomeFolder.mockResolvedValue('home');
	api.uploadFile.mockImplementation(async (_folder: string, file: File) => ({ name: file.name }));
});

describe('saveToChatFolder', () => {
	it('creates the Chat folder in the home drive on first use', async () => {
		api.listFolder.mockResolvedValueOnce(listing([])).mockResolvedValueOnce(listing([]));
		api.createFolder.mockResolvedValue({ id: 'chat' });

		const res = await saveToChatFolder(new Blob(['x']), 'cat.jpg', 'image/jpeg');

		expect(api.createFolder).toHaveBeenCalledWith('Chat', 'home');
		expect(api.uploadFile).toHaveBeenCalledWith('chat', expect.any(File));
		const file = api.uploadFile.mock.calls[0][1] as File;
		expect(file.name).toBe('cat.jpg');
		expect(file.type).toBe('image/jpeg');
		expect(res).toMatchObject({ name: 'cat.jpg', folderId: 'chat' });
	});

	it('reuses the Chat folder and numbers a taken name', async () => {
		api.listFolder
			.mockResolvedValueOnce(listing([{ id: 'chat', name: 'Chat' }]))
			.mockResolvedValueOnce(listing([], [{ name: 'cat.jpg' }]));

		const res = await saveToChatFolder(new Blob(['x']), 'cat.jpg');

		expect(api.createFolder).not.toHaveBeenCalled();
		expect(res.name).toBe('cat (1).jpg');
	});

	it('refuses when the account has no home drive (external user)', async () => {
		api.loadHomeFolder.mockResolvedValue(null);
		await expect(saveToChatFolder(new Blob(['x']), 'a.txt')).rejects.toThrow(/home drive/);
		expect(api.uploadFile).not.toHaveBeenCalled();
	});
});
