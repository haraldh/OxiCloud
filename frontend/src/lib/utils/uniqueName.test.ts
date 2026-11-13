import { describe, expect, it } from 'vitest';
import { uniqueName } from './uniqueName';

describe('uniqueName', () => {
	it('keeps a free name', () => {
		expect(uniqueName('cat.jpg', ['dog.jpg'])).toBe('cat.jpg');
	});

	it('numbers before the extension, skipping taken numbers', () => {
		expect(uniqueName('cat.jpg', ['cat.jpg', 'cat (1).jpg'])).toBe('cat (2).jpg');
	});

	it('treats names differing only in case as taken', () => {
		expect(uniqueName('Cat.JPG', ['cat.jpg'])).toBe('Cat (1).JPG');
	});

	it('handles names without an extension and dotfiles', () => {
		expect(uniqueName('README', ['README'])).toBe('README (1)');
		expect(uniqueName('.env', ['.env'])).toBe('.env (1)');
		expect(uniqueName('archive.tar.gz', ['archive.tar.gz'])).toBe('archive.tar (1).gz');
	});
});
