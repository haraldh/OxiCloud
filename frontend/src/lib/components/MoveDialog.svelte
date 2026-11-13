<script lang="ts">
	import { moveFolder } from '$lib/api/endpoints/folders';
	import { moveFile } from '$lib/api/endpoints/files';
	import { copyFiles, copyFolders } from '$lib/api/endpoints/batch';
	import type { Drive, DriveRole } from '$lib/api/types';
	import FolderBrowser from '$lib/components/FolderBrowser.svelte';
	import Modal from '$lib/components/Modal.svelte';
	import { t } from '$lib/i18n/index.svelte';
	import { compareDrives, drives as drivesStore } from '$lib/stores/drives.svelte';
	import { ui } from '$lib/stores/ui.svelte';
	import { useAsyncAction } from '$lib/composables/useAsyncAction.svelte';

	// A drive accepts new items only if the caller can Create on its
	// root. Drive-scope roles are the management-ladder subset —
	// Owner / Editor / Viewer — so writability collapses to the top two;
	// Viewer cannot. `contributor`/`commenter` don't appear at drive
	// scope (folder/file-scope semantics), so they're not in `DriveRole`.
	const WRITABLE_ROLES: readonly DriveRole[] = ['owner', 'editor'] as const;
	function isWritable(d: Drive): boolean {
		// `d.caller_role` is typed `RoleDto` (all 5 values) because `Drive`
		// now aliases to `DriveDto`; at drive scope the server will only
		// emit the 3-value `DriveRole` subset, so `.includes` on the
		// 2-value `WRITABLE_ROLES` is safe — the two phantom values
		// (`contributor`, `commenter`) narrow back to `false`.
		return d.caller_role != null && WRITABLE_ROLES.includes(d.caller_role as DriveRole);
	}

	interface Target {
		id: string;
		name: string;
		kind: 'file' | 'folder';
	}

	interface Props {
		open: boolean;
		item: Target | null;
		/** Optional multi-item batch; takes precedence over `item`. */
		items?: Target[] | null;
		/** 'move' (default) relocates; 'copy' duplicates into the picked folder. */
		mode?: 'move' | 'copy';
		onmoved?: () => void;
	}

	let { open = $bindable(false), item, items = null, mode = 'move', onmoved }: Props = $props();

	const targets = $derived(items && items.length ? items : item ? [item] : []);
	const targetIds = $derived(new Set(targets.map((x) => x.id)));

	let currentId = $state<string | null>(null);

	const action = useAsyncAction();

	const writableDrives = $derived([...drivesStore.drives].filter(isWritable).sort(compareDrives));

	async function confirmMove() {
		if (!targets.length || !currentId) return;
		const ok = await action.run(async () => {
			if (mode === 'copy') {
				const fileIds = targets.filter((x) => x.kind === 'file').map((x) => x.id);
				const folderIds = targets.filter((x) => x.kind === 'folder').map((x) => x.id);
				await copyFiles(fileIds, currentId!);
				await copyFolders(folderIds, currentId!);
			} else {
				for (const tgt of targets) {
					if (tgt.id === currentId) continue;
					if (tgt.kind === 'file') await moveFile(tgt.id, currentId!);
					else await moveFolder(tgt.id, currentId!);
				}
			}
		});
		if (ok) {
			// Toast kept for success — a user who just saw the dialog
			// close may not notice the row appeared/disappeared from
			// the listing without this breadcrumb. Only the failure
			// path moved from toast to inline.
			ui.notify(
				mode === 'copy' ? t('files.copied', 'Copied') : t('files.moved', 'Moved'),
				'success'
			);
			open = false;
			onmoved?.();
		}
	}

	const moveTitle = $derived.by(() => {
		if (mode === 'copy') {
			return targets.length > 1
				? t('files.copy_n', { n: targets.length }, 'Copy {{n}} items')
				: t('files.copy_title', { name: targets[0]?.name ?? '' }, 'Copy “{{name}}”');
		}
		return targets.length > 1
			? t('files.move_n', { n: targets.length }, 'Move {{n}} items')
			: t('files.move_title', { name: targets[0]?.name ?? '' }, 'Move “{{name}}”');
	});
</script>

<Modal bind:open title={moveTitle}>
	<div data-testid="move-dialog">
		<FolderBrowser
			drives={writableDrives}
			active={open && targets.length > 0}
			bind:currentId
			testid="move-dialog"
			disabledFolderIds={targetIds}
			busy={action.busy}
			onnavigate={() => action.clearError()}
		/>

		{#if action.error}
			<p class="form-error" id="move-dialog-error" role="alert">{action.error}</p>
		{/if}
	</div>

	{#snippet footer()}
		<button
			class="btn btn-secondary"
			data-testid="move-dialog-cancel-btn"
			disabled={action.busy}
			onclick={() => (open = false)}
		>
			{t('common.cancel', 'Cancel')}
		</button>
		<button
			class="btn btn-primary"
			data-testid="move-dialog-confirm-btn"
			disabled={action.busy || !currentId}
			onclick={confirmMove}
		>
			{action.busy
				? t('common.loading', 'Loading…')
				: mode === 'copy'
					? t('files.copy_here', 'Copy here')
					: t('files.move_here', 'Move here')}
		</button>
	{/snippet}
</Modal>

<style>
	/* `.form-error` lives in `lib/styles/base/forms.css` — one
	   place for every dialog's error state. See
	   `frontend/AGENTS.md § Dialog error UX`. Navigation styles live in
	   FolderBrowser. */
</style>
