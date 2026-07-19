import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';

const windowsBashCandidates = [
  'C:\\Program Files\\Git\\bin\\bash.exe',
  'C:\\Program Files\\Git\\usr\\bin\\bash.exe',
];
const bashPath = process.platform === 'win32'
  ? windowsBashCandidates.find((candidate) => existsSync(candidate))
  : 'bash';

function shellPath(filename) {
  if (process.platform !== 'win32') return filename;
  return filename.replace(/^([A-Za-z]):\\/, (_, drive) => `/${drive.toLowerCase()}/`).replaceAll('\\', '/');
}

test('本机更新器在 GitHub 不可达时自动选择已保存的可达节点', {
  skip: !bashPath,
  timeout: 15_000,
}, async () => {
  const directory = mkdtempSync(join(tmpdir(), 'pathweaver-update-'));
  const stateFile = join(directory, 'state.json');
  const server = createServer((request, response) => {
    if (request.url === '/install.sh') {
      response.writeHead(200, { 'Content-Type': 'text/x-shellscript' });
      return response.end('#!/usr/bin/env bash\nexit 0\n');
    }
    if (request.url === '/artifacts/center/pathweaver-center.tar.gz') {
      response.writeHead(200, { 'Content-Type': 'application/gzip' });
      return response.end('test-bundle');
    }
    response.writeHead(request.url.startsWith('/github-unavailable/') ? 503 : 404);
    response.end('unavailable');
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const source = `http://127.0.0.1:${server.address().port}`;
  writeFileSync(stateFile, JSON.stringify({
    upstream: `${source}/missing-upstream`,
    controlForwarders: { reachablePeer: source },
  }));

  try {
    const child = spawn(bashPath, ['scripts/update.sh'], {
      cwd: resolve('.'),
      env: {
        ...process.env,
        PATHWEAVER_UPDATE_DRY_RUN: '1',
        PATHWEAVER_UPDATE_NODE: shellPath(process.execPath),
        PATHWEAVER_UPDATE_AGENT_STATE: shellPath(stateFile),
        PATHWEAVER_UPDATE_DATABASE: shellPath(join(directory, 'missing.db')),
        PATHWEAVER_UPDATE_GITHUB_SOURCE: `${source}/github-unavailable`,
        PATHWEAVER_UPDATE_GITHUB_BUNDLE_URL: `${source}/github-unavailable/bundle.tar.gz`,
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8').on('data', (chunk) => { stdout += chunk; });
    child.stderr.setEncoding('utf8').on('data', (chunk) => { stderr += chunk; });
    const [code] = await once(child, 'exit');
    assert.equal(code, 0, stderr);
    assert.match(stdout, /更新源不可达，尝试下一台节点/);
    assert.match(stdout, new RegExp(`DRY_RUN_SOURCE=${source.replaceAll('.', '\\.')}`));
  } finally {
    await new Promise((resolveClose) => server.close(resolveClose));
    rmSync(directory, { recursive: true, force: true });
  }
});
