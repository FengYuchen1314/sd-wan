import { execFileSync } from 'node:child_process';

let cachedBundle = null;

export function createCenterBundle(rootDir) {
  if (!cachedBundle) {
    cachedBundle = execFileSync('tar', [
      '-czf', '-',
      'package.json',
      'src',
      'public',
      'scripts/install.sh',
      'scripts/update.sh',
      'scripts/apply-update-request.sh',
      'scripts/uninstall.sh',
    ], { cwd: rootDir, maxBuffer: 32 * 1024 * 1024 });
  }
  return cachedBundle;
}
