/**
 * A file name not in `taken`: the name itself, else `stem (1).ext`,
 * `stem (2).ext`, … The extension is the part after the last dot, unless
 * the name starts with it (`.env` has no extension). Comparison ignores
 * case, since names that differ only in case collide on many clients.
 */
export function uniqueName(name: string, taken: Iterable<string>): string {
	const used = new Set<string>();
	for (const n of taken) used.add(n.toLowerCase());
	if (!used.has(name.toLowerCase())) return name;
	const dot = name.lastIndexOf('.');
	const [stem, ext] = dot > 0 ? [name.slice(0, dot), name.slice(dot)] : [name, ''];
	for (let i = 1; ; i++) {
		const candidate = `${stem} (${i})${ext}`;
		if (!used.has(candidate.toLowerCase())) return candidate;
	}
}
