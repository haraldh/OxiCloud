import { describe, expect, it } from 'vitest';
import type { Drive } from '$lib/api/types';
import { compareDrives } from './drives.svelte';

const drive = (name: string, kind: 'personal' | 'shared', home = false) =>
	({ id: name, name, kind, default_for_user: home ? 'me' : null }) as unknown as Drive;

describe('compareDrives', () => {
	it('orders home, then personal, then shared drives, by name within each', () => {
		const sorted = [
			drive('Team B', 'shared'),
			drive('Archive', 'personal'),
			drive('Team A', 'shared'),
			drive('Personal', 'personal', true)
		].sort(compareDrives);
		expect(sorted.map((d) => d.name)).toEqual(['Personal', 'Archive', 'Team A', 'Team B']);
	});
});
