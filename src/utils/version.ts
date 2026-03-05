import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

let cached: string | null = null;

export function getVersion(): string {
  if (cached) return cached;
  try {
    const __dirname = dirname(fileURLToPath(import.meta.url));
    const pkg = JSON.parse(
      readFileSync(join(__dirname, '..', '..', 'package.json'), 'utf-8'),
    );
    cached = pkg.version as string;
    return cached;
  } catch {
    cached = '0.0.0';
    return cached;
  }
}
