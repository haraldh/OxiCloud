<script lang="ts">
	/**
	 * Pick one file from the user's drives (any drive they can read).
	 * Clicking a file picks it and closes the dialog.
	 */
	import type { FileItem } from '$lib/api/types';
	import FolderBrowser from '$lib/components/FolderBrowser.svelte';
	import Modal from '$lib/components/Modal.svelte';
	import { t } from '$lib/i18n/index.svelte';
	import { compareDrives, drives as drivesStore } from '$lib/stores/drives.svelte';

	interface Props {
		open: boolean;
		title?: string;
		onpick: (file: FileItem) => void;
	}

	let { open = $bindable(false), title, onpick }: Props = $props();

	const readableDrives = $derived(
		[...drivesStore.drives].filter((d) => d.caller_role != null).sort(compareDrives)
	);

	function pick(file: FileItem) {
		open = false;
		onpick(file);
	}
</script>

<Modal bind:open title={title ?? t('files.pick_file', 'Choose a file')}>
	<div data-testid="file-picker">
		<FolderBrowser
			drives={readableDrives}
			active={open}
			testid="file-picker"
			showFiles
			onpickfile={pick}
		/>
	</div>

	{#snippet footer()}
		<button class="btn btn-secondary" onclick={() => (open = false)}>
			{t('common.cancel', 'Cancel')}
		</button>
	{/snippet}
</Modal>
