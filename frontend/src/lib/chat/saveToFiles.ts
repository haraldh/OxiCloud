/**
 * "Save to Files" for chat attachments: put a copy into the user's
 * OxiCloud files, in a `Chat` folder at the top of their home drive
 * (created on first use, like Nextcloud Talk's `Talk` folder).
 *
 * The bytes are the ones the browser already decrypted for display, so in
 * an encrypted room this is the user's explicit choice to keep a readable
 * copy on the server; nothing is saved without the click.
 */
import { uploadFile } from '$lib/api/endpoints/files';
import { createFolder, listFolder } from '$lib/api/endpoints/folders';
import type { FileItem } from '$lib/api/types';
import { session } from '$lib/stores/session.svelte';
import { uniqueName } from '$lib/utils/uniqueName';

/** Not translated: a folder name must not change with the UI language. */
export const CHAT_FOLDER_NAME = 'Chat';

async function chatFolderId(): Promise<string> {
	const home = await session.loadHomeFolder();
	if (!home) throw new Error('No home drive to save into');
	const listing = await listFolder(home, true);
	const existing = listing.folders.find((f) => f.name === CHAT_FOLDER_NAME);
	if (existing) return existing.id;
	return (await createFolder(CHAT_FOLDER_NAME, home)).id;
}

/** Save `blob` as `name` (numbered if taken) and return the new file. */
export async function saveToChatFolder(
	blob: Blob,
	name: string,
	mimetype?: string
): Promise<{ file: FileItem | null; name: string; folderId: string }> {
	const folder = await chatFolderId();
	const listing = await listFolder(folder, true);
	const finalName = uniqueName(
		name.trim() || 'attachment',
		listing.files.map((f) => f.name)
	);
	const type = mimetype ?? blob.type;
	const file = await uploadFile(folder, new File([blob], finalName, { type }));
	return { file, name: finalName, folderId: folder };
}
