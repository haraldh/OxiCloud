<script lang="ts">
	/**
	 * One chat attachment. Images show their thumbnail (or the image when it
	 * is small) straight away; video, audio and files load only when asked,
	 * so a long timeline doesn't pull every file. Bytes come from
	 * `ChatClient.mediaUrl`, which also decrypts in encrypted rooms.
	 */
	import Button from '$lib/components/Button.svelte';
	import Icon from '$lib/icons/Icon.svelte';
	import { t } from '$lib/i18n/index.svelte';
	import { formatBytes } from '$lib/utils/format';
	import type { Attachment } from '$lib/chat/attachment';
	import type { ChatClient } from '$lib/chat/matrix.svelte';
	import { saveToChatFolder, CHAT_FOLDER_NAME } from '$lib/chat/saveToFiles';
	import { ui } from '$lib/stores/ui.svelte';
	import { errorMessage } from '$lib/utils/errors';
	import { goto } from '$app/navigation';
	import { resolve } from '$app/paths';

	interface Props {
		attachment: Attachment;
		chat: ChatClient;
	}
	let { attachment, chat }: Props = $props();

	/** Images up to this size load without a thumbnail. */
	const INLINE_IMAGE_MAX = 10 * 1024 * 1024;

	let preview = $state<string | null>(null);
	let full = $state<string | null>(null);
	let busy = $state(false);
	let failed = $state(false);

	const label = $derived(
		attachment.size !== undefined
			? `${attachment.name} (${formatBytes(attachment.size)})`
			: attachment.name
	);

	async function loadFull(): Promise<string | null> {
		if (full) return full;
		busy = true;
		failed = false;
		try {
			full = await chat.mediaUrl(attachment.source, attachment.mimetype);
			return full;
		} catch {
			failed = true;
			return null;
		} finally {
			busy = false;
		}
	}

	async function openImage() {
		const url = await loadFull();
		if (url) window.open(url, '_blank', 'noopener');
	}

	async function download() {
		const url = await loadFull();
		if (!url) return;
		const a = document.createElement('a');
		a.href = url;
		a.download = attachment.name || 'attachment';
		a.click();
	}

	let saving = $state(false);

	/** Keep a copy in the user's files (the `Chat` folder). */
	async function saveToFiles() {
		saving = true;
		try {
			const { blob } = await chat.media(attachment.source, attachment.mimetype);
			const saved = await saveToChatFolder(blob, attachment.name, attachment.mimetype);
			ui.notify(
				t(
					'chat.attachment_saved',
					{ name: `${CHAT_FOLDER_NAME}/${saved.name}` },
					'Saved to {{name}}'
				),
				'info',
				6000,
				true,
				{
					action: {
						label: t('chat.attachment_open_folder', 'Open folder'),
						onClick: () => goto(resolve(`/files/${saved.folderId}`))
					}
				}
			);
		} catch (err) {
			ui.notify(errorMessage(err), 'error');
		} finally {
			saving = false;
		}
	}

	$effect(() => {
		if (attachment.kind !== 'image') return;
		const thumb = attachment.thumbnail;
		const small = attachment.size === undefined || attachment.size <= INLINE_IMAGE_MAX;
		const src = thumb ?? (small ? attachment.source : null);
		if (!src) return;
		chat
			.mediaUrl(src, thumb ? undefined : attachment.mimetype)
			.then((url) => {
				preview = url;
				if (!thumb) full = url;
			})
			.catch(() => (failed = true));
	});
</script>

<div class="att" data-testid="chat-attachment">
	{#if attachment.kind === 'image' && preview}
		<button
			type="button"
			class="att__image-btn"
			onclick={() => void openImage()}
			aria-label={t('chat.attachment_open', { name: attachment.name }, 'Open {{name}}')}
		>
			<img
				class="att__image"
				src={preview}
				alt={attachment.name}
				width={attachment.width}
				height={attachment.height}
			/>
		</button>
	{:else if attachment.kind === 'video' && full}
		<!-- svelte-ignore a11y_media_has_caption -->
		<video class="att__video" src={full} controls></video>
	{:else if attachment.kind === 'audio' && full}
		<audio src={full} controls></audio>
	{:else}
		<div class="att__file">
			<Icon name={attachment.kind === 'image' ? 'image' : 'file'} />
			<span class="att__name">{label}</span>
			{#if attachment.kind === 'video' || attachment.kind === 'audio'}
				<Button small disabled={busy} onclick={() => void loadFull()}>
					{t('chat.attachment_play', 'Play')}
				</Button>
			{:else if attachment.kind === 'image'}
				<Button small disabled={busy} onclick={() => void openImage()}>
					{t('chat.attachment_show', 'Show')}
				</Button>
			{/if}
			<Button small icon="download" disabled={busy} onclick={() => void download()}>
				{t('chat.attachment_download', 'Download')}
			</Button>
		</div>
	{/if}
	<div class="att__actions">
		<Button
			small
			icon="folder-plus"
			disabled={saving}
			onclick={() => void saveToFiles()}
			data-testid="chat-attachment-save"
		>
			{t('chat.attachment_save', 'Save to Files')}
		</Button>
	</div>
	{#if failed}
		<p class="att__error" role="alert">
			{t('chat.attachment_failed', 'Could not load this attachment.')}
		</p>
	{/if}
</div>

<style>
	.att {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
		max-width: 100%;
	}

	.att__image-btn {
		display: block;
		padding: 0;
		border: none;
		background: none;
		cursor: zoom-in;
	}

	.att__image,
	.att__video {
		display: block;
		max-width: min(100%, 20rem);
		max-height: 20rem;
		width: auto;
		height: auto;
		border-radius: var(--radius-md);
	}

	.att__file {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: var(--space-2);
		color: var(--color-text);
	}

	.att__actions {
		display: flex;
		gap: var(--space-2);
	}

	.att__name {
		overflow-wrap: anywhere;
	}

	.att__error {
		margin: 0;
		color: var(--color-danger-text);
		font-size: var(--text-sm);
	}
</style>
