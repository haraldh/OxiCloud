<script lang="ts">
	/**
	 * Browse drives and folders inside a dialog: a drive switcher (when more
	 * than one drive is offered), home / up buttons, breadcrumbs, and the
	 * current folder's subfolders — plus its files when `showFiles` is set.
	 * Shared by MoveDialog (pick a target folder) and FilePickerDialog (pick
	 * a file), so both navigate the same way.
	 */
	import { errorToast } from '$lib/utils/errors';
	import { listFolder } from '$lib/api/endpoints/folders';
	import type { Drive, FileItem, FolderItem } from '$lib/api/types';
	import Icon from '$lib/icons/Icon.svelte';
	import { t } from '$lib/i18n/index.svelte';
	import { drives as drivesStore, driveIcon } from '$lib/stores/drives.svelte';

	interface Props {
		/** Drives to offer, in display order. */
		drives: Drive[];
		/** (Re)starts at the default drive's root each time it turns true. */
		active: boolean;
		/** The folder being shown; bind to read it. */
		currentId?: string | null;
		/** Prefix for `data-testid`s (`{prefix}-folder-{id}`, …). */
		testid: string;
		/** Folders that cannot be entered (e.g. the items being moved). */
		disabledFolderIds?: ReadonlySet<string>;
		busy?: boolean;
		/** List files too, each clickable. */
		showFiles?: boolean;
		onpickfile?: (file: FileItem) => void;
		/** Called whenever the shown folder changes. */
		onnavigate?: () => void;
	}

	let {
		drives,
		active,
		currentId = $bindable(null),
		testid,
		disabledFolderIds = new Set<string>(),
		busy = false,
		showFiles = false,
		onpickfile,
		onnavigate
	}: Props = $props();

	let crumbs = $state<Array<{ id: string; name: string }>>([]);
	let folders = $state<FolderItem[]>([]);
	let files = $state<FileItem[]>([]);
	let selectedDriveId = $state<string | null>(null);
	let loading = $state(false);

	async function loadInto(id: string) {
		loading = true;
		onnavigate?.();
		try {
			currentId = id;
			const listing = await listFolder(id);
			folders = listing.folders;
			files = showFiles ? listing.files : [];
		} catch (e) {
			errorToast(e);
		} finally {
			loading = false;
		}
	}

	async function init() {
		await drivesStore.load();
		const home = drivesStore.findDefault();
		// Prefer the user's home drive when it is on offer, else the first.
		const start = home && drives.some((d) => d.id === home.id) ? home : drives[0];
		if (!start) return;
		selectedDriveId = start.id;
		crumbs = [{ id: start.root_folder_id, name: start.name }];
		await loadInto(start.root_folder_id);
	}

	async function switchDrive(d: Drive) {
		if (d.id === selectedDriveId) return;
		selectedDriveId = d.id;
		crumbs = [{ id: d.root_folder_id, name: d.name }];
		await loadInto(d.root_folder_id);
	}

	function enter(f: FolderItem) {
		crumbs = [...crumbs, { id: f.id, name: f.name }];
		void loadInto(f.id);
	}

	function gotoCrumb(index: number) {
		crumbs = crumbs.slice(0, index + 1);
		void loadInto(crumbs[index].id);
	}

	const atHome = $derived(crumbs.length <= 1);

	$effect(() => {
		if (active) void init();
	});
</script>

{#if drives.length > 1}
	<div
		class="fb-drives"
		role="tablist"
		aria-label={t('drive.picker', 'Drives')}
		data-testid={`${testid}-drives`}
	>
		{#each drives as d (d.id)}
			<button
				type="button"
				role="tab"
				aria-selected={d.id === selectedDriveId}
				class="fb-drive"
				class:fb-drive--active={d.id === selectedDriveId}
				data-testid={`${testid}-drive-${d.id}`}
				onclick={() => switchDrive(d)}
			>
				<Icon name={driveIcon(d)} />
				<span>{d.name}</span>
			</button>
		{/each}
	</div>
{/if}

<div class="fb-nav">
	<button
		class="fb-nav-btn"
		data-testid={`${testid}-home-btn`}
		title={t('breadcrumb.home', 'Home')}
		aria-label={t('breadcrumb.home', 'Home')}
		disabled={atHome}
		onclick={() => crumbs.length && gotoCrumb(0)}><Icon name="home" /></button
	>
	<button
		class="fb-nav-btn"
		data-testid={`${testid}-parent-btn`}
		title={t('dialogs.go_to_parent', 'Go to parent')}
		aria-label={t('dialogs.go_to_parent', 'Go to parent')}
		disabled={atHome}
		onclick={() => crumbs.length > 1 && gotoCrumb(crumbs.length - 2)}
		><Icon name="level-up-alt" /></button
	>
	<nav class="fb-crumbs" aria-label="Breadcrumb">
		{#each crumbs as c, i (c.id)}
			{#if i > 0}<span class="fb-sep">/</span>{/if}
			<button
				class="fb-crumb"
				aria-current={c.id === currentId ? 'location' : undefined}
				data-testid={`${testid}-crumb-${c.id}`}
				onclick={() => gotoCrumb(i)}>{c.name}</button
			>
		{/each}
	</nav>
</div>

{#if loading}
	<p class="fb-status">{t('common.loading', 'Loading…')}</p>
{:else if folders.length === 0 && files.length === 0}
	<p class="fb-status">
		{showFiles
			? t('files.empty_folder', 'This folder is empty.')
			: t('files.no_subfolders', 'No subfolders here.')}
	</p>
{:else}
	<ul class="fb-list">
		{#each folders as f (f.id)}
			<li>
				<button
					class="fb-row"
					data-testid={`${testid}-folder-${f.id}`}
					disabled={disabledFolderIds.has(f.id) || busy}
					onclick={() => enter(f)}
				>
					<Icon name="folder" /> <span>{f.name}</span>
					<Icon name="chevron-right" class="fb-enter" />
				</button>
			</li>
		{/each}
		{#each files as f (f.id)}
			<li>
				<button
					class="fb-row"
					data-testid={`${testid}-file-${f.id}`}
					disabled={busy}
					onclick={() => onpickfile?.(f)}
				>
					<Icon name="file" /> <span>{f.name}</span>
				</button>
			</li>
		{/each}
	</ul>
{/if}

<style>
	/* Drive switcher: a chip strip across the top of the dialog. Hidden
	   when only one drive is in scope (single-drive UX). */
	.fb-drives {
		display: flex;
		flex-wrap: wrap;
		gap: 0.375rem;
		margin-bottom: var(--space-3);
		padding-bottom: var(--space-3);
		border-bottom: 1px solid var(--color-border);
	}

	.fb-drive {
		display: inline-flex;
		align-items: center;
		gap: 0.4rem;
		padding: 0.3rem 0.625rem;
		border: 1px solid var(--color-border);
		border-radius: var(--radius-md);
		background: var(--color-bg-input);
		color: var(--color-text);
		font: inherit;
		font-size: 0.85rem;
		cursor: pointer;
		max-width: 14rem;
	}

	.fb-drive:hover:not(.fb-drive--active) {
		background: var(--color-bg-hover);
	}

	.fb-drive--active {
		background: var(--color-accent);
		color: var(--color-on-accent);
		border-color: var(--color-accent);
		cursor: default;
	}

	.fb-drive span {
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.fb-nav {
		display: flex;
		align-items: center;
		gap: var(--space-1);
		margin-bottom: var(--space-3);
	}

	.fb-nav-btn {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		width: 28px;
		height: 28px;
		border: 1px solid var(--color-border);
		border-radius: var(--radius-md);
		background: var(--color-bg-input);
		color: var(--color-text);
		cursor: pointer;
		flex: none;
	}

	.fb-nav-btn:hover:not(:disabled) {
		background: var(--color-bg-hover);
	}

	.fb-nav-btn:disabled {
		opacity: 0.4;
		cursor: not-allowed;
	}

	.fb-crumbs {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: 0.25rem;
		min-width: 0;
	}

	.fb-crumb {
		background: none;
		border: none;
		color: var(--color-accent-text, var(--color-primary));
		cursor: pointer;
		padding: 0.125rem 0.25rem;
	}

	.fb-sep {
		color: var(--color-text-muted);
	}

	.fb-list {
		list-style: none;
		margin: 0;
		padding: 0;
		max-height: 50vh;
		overflow: auto;
	}

	.fb-row {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		width: 100%;
		padding: 0.5rem 0.625rem;
		border: none;
		background: none;
		color: var(--color-text);
		cursor: pointer;
		border-radius: var(--radius-md);
		text-align: left;
	}

	.fb-row:hover:not(:disabled) {
		background: var(--color-bg-hover);
	}

	.fb-row:disabled {
		opacity: 0.4;
		cursor: not-allowed;
	}

	.fb-row span {
		flex: 1;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	:global(.fb-enter) {
		color: var(--color-text-muted);
	}

	.fb-status {
		color: var(--color-text-muted);
		padding: 1rem 0;
		text-align: center;
	}
</style>
