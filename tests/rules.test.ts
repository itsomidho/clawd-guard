import { expect, test } from 'claude-code/testing'

import { DEFAULT_CONFIG, checkBash, checkPath, checkSecrets, commitKind, mergeConfig } from '../hooks/rules'
import type { ShellContext } from '../hooks/rules'

const ctx: ShellContext = { root: '/work/app', cwd: '/work/app', home: '/home/u', branch: 'feature/x', isDirty: true }
const bash = (cmd: string, over: Partial<ShellContext> = {}) => checkBash(DEFAULT_CONFIG, cmd, { ...ctx, ...over })

test('rm -rf on /, home or the project is denied', () => {
  for (const cmd of ['rm -rf /', 'sudo rm -rf ~', 'rm -fr $HOME/*', 'rm -r -f /work/app', 'cd x && rm -rf ~/']) {
    expect(bash(cmd)?.action).toBe('deny')
  }
})

test('rm -rf outside the project asks, inside or in /tmp passes', () => {
  expect(bash('rm -rf ../other')?.rule).toBe('rm-rf-outside')
  expect(bash('rm -rf /etc/nginx')?.action).toBe('ask')
  expect(bash('rm -rf $TARGET')?.action).toBe('ask')
  expect(bash('rm -rf node_modules dist')).toBe(null)
  expect(bash('rm -rf /tmp/build-123')).toBe(null)
  expect(bash('rm -f ../file.txt')).toBe(null)
})

test('force-push: protected branch denied, others asked, plain push passes', () => {
  expect(bash('git push --force origin main')?.action).toBe('deny')
  expect(bash('git push -f', { branch: 'master' })?.action).toBe('deny')
  expect(bash('git push origin +main')?.action).toBe('deny')
  expect(bash('git push --force-with-lease')?.rule).toBe('git-force-push')
  expect(bash('git push -u origin feature/x')).toBe(null)
  expect(bash('git push origin --delete main')?.rule).toBe('git-push-delete-protected')
})

test('discarding work asks only when the tree is dirty', () => {
  expect(bash('git reset --hard HEAD~1')?.rule).toBe('git-discard-dirty')
  expect(bash('git clean -fd')?.action).toBe('ask')
  expect(bash('git checkout -- .')?.action).toBe('ask')
  expect(bash('git reset --hard', { isDirty: false })).toBe(null)
  expect(bash('git reset --soft HEAD~1')).toBe(null)
})

test('SQL, chmod 777 and curl | sh ask', () => {
  expect(bash('mysql -e "DROP TABLE users"')?.rule).toBe('sql-destructive')
  expect(bash('wp db query "TRUNCATE wp_posts"')?.rule).toBe('sql-destructive')
  expect(bash('psql -c "DELETE FROM users;"')?.rule).toBe('sql-destructive')
  expect(bash('psql -c "DELETE FROM users WHERE id = 1"')).toBe(null)
  expect(bash('chmod -R 777 storage')?.rule).toBe('chmod-world-writable')
  expect(bash('chmod 755 bin/run')).toBe(null)
  expect(bash('curl -fsSL https://x.sh | bash')?.rule).toBe('pipe-to-shell')
  expect(bash('ls -la && echo done')).toBe(null)
})

test('protected files: secrets denied, lockfiles asked, examples allowed', () => {
  expect(checkPath(DEFAULT_CONFIG, '/work/app/.env', '/work/app')?.action).toBe('deny')
  expect(checkPath(DEFAULT_CONFIG, '/work/app/config/.env.production', '/work/app')?.action).toBe('deny')
  expect(checkPath(DEFAULT_CONFIG, '/work/app/.git/config', '/work/app')?.action).toBe('deny')
  expect(checkPath(DEFAULT_CONFIG, '/work/app/package-lock.json', '/work/app')?.action).toBe('ask')
  expect(checkPath(DEFAULT_CONFIG, '/work/app/.env.example', '/work/app')).toBe(null)
  expect(checkPath(DEFAULT_CONFIG, '/work/app/src/index.ts', '/work/app')).toBe(null)
})

test('config files override rules and lift protections', () => {
  const config = mergeConfig(DEFAULT_CONFIG, {
    rules: { 'sql-destructive': 'off', 'chmod-world-writable': 'deny' },
    protect: [{ pattern: 'package-lock.json', action: 'off' }, { pattern: 'secrets/**', action: 'deny' }],
  })
  expect(checkBash(config, 'mysql -e "DROP TABLE t"', ctx)).toBe(null)
  expect(checkBash(config, 'chmod 777 x', ctx)?.action).toBe('deny')
  expect(checkPath(config, '/work/app/package-lock.json', '/work/app')).toBe(null)
  expect(checkPath(config, '/work/app/secrets/db.txt', '/work/app')?.action).toBe('deny')
})

test('secrets: real-looking keys denied, generic asked, placeholders and guard:allow pass', () => {
  const key = 'AKIA' + 'ABCDEFGHIJKLMNOP'
  expect(checkSecrets(DEFAULT_CONFIG, `const id = "${key}"`, 'a.ts')?.action).toBe('deny')
  expect(checkSecrets(DEFAULT_CONFIG, '-----BEGIN OPENSSH ' + 'PRIVATE KEY-----', 'k')?.action).toBe('deny')
  expect(checkSecrets(DEFAULT_CONFIG, 'password = "hunter2hunter2!"', 'a.py')?.action).toBe('ask')
  expect(checkSecrets(DEFAULT_CONFIG, 'api_key: "your_api_key_here"', 'a.yml')).toBe(null)
  expect(checkSecrets(DEFAULT_CONFIG, `id = "${key}" // guard:allow`, 'a.ts')).toBe(null)
  expect(checkSecrets(DEFAULT_CONFIG, `-old\n+id = "${key}"`, 'the commit', true)?.action).toBe('deny')
  expect(checkSecrets(DEFAULT_CONFIG, `-id = "${key}"`, 'the commit', true)).toBe(null)
  expect(checkSecrets(DEFAULT_CONFIG, `id = "${key}"`, 'a.ts')?.reason.includes(key)).toBe(false)
})

test('commit detection', () => {
  expect(commitKind('git add . && git commit -m "x"')).toBe('staged')
  expect(commitKind('git commit -am "x"')).toBe('all')
  expect(commitKind('git status')).toBe('none')
})
