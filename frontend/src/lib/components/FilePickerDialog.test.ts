import { it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';

const { drives } = vi.hoisted(() => {
	const home = {
		id: 'drive-home',
		root_folder_id: 'home',
		name: 'Personal',
		kind: 'personal' as const,
		default_for_user: 'user-1',
		caller_role: 'owner' as const
	};
	return {
		drives: {
			drives: [home],
			load: vi.fn(async () => [home]),
			findDefault: vi.fn(() => home)
		}
	};
});
vi.mock('$lib/stores/drives.svelte', () => ({
	drives,
	driveIcon: () => 'home',
	compareDrives: () => 0
}));
vi.mock('$lib/utils/errors', () => ({ errorToast: vi.fn() }));
vi.mock('$lib/api/endpoints/folders', () => ({ listFolder: vi.fn() }));

import { listFolder } from '$lib/api/endpoints/folders';
import FilePickerDialog from './FilePickerDialog.svelte';

beforeEach(() => {
	vi.clearAllMocks();
	(listFolder as ReturnType<typeof vi.fn>).mockResolvedValue({
		folders: [{ id: 'sub', name: 'Photos' }],
		files: [{ id: 'f1', name: 'cat.jpg', mime_type: 'image/jpeg' }]
	});
});

it('lists files next to folders and picks the clicked file', async () => {
	const onpick = vi.fn();
	render(FilePickerDialog, { props: { open: true, onpick } });
	await waitFor(() => expect(listFolder).toHaveBeenCalledWith('home'));
	await screen.findByTestId('file-picker-folder-sub');
	await fireEvent.click(await screen.findByTestId('file-picker-file-f1'));
	expect(onpick).toHaveBeenCalledWith(expect.objectContaining({ id: 'f1', name: 'cat.jpg' }));
	await waitFor(() => expect(screen.queryByTestId('file-picker')).toBeNull());
});
