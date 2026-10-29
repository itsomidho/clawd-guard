import { expect, test } from 'claude-code/testing'

import { DEFAULT_CONFIG, checkBash, checkPath, checkSecrets, commitKind, displayPath, fitText, mergeConfig, shortenPath } from '../hooks/rules'
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

test('commands hidden inside bash -c, eval, $(…) and backticks are checked', () => {
  expect(bash('bash -c "rm -rf ~"')?.action).toBe('deny')
  expect(bash("sh -lc 'git push -f origin main'")?.action).toBe('deny')
  expect(bash('eval "rm -rf /"')?.action).toBe('deny')
  expect(bash('echo "$(rm -rf ~)"')?.action).toBe('deny')
  expect(bash('echo `rm -rf ~`')?.action).toBe('deny')
  expect(bash('sudo bash -c "rm -rf /etc/nginx"')?.rule).toBe('rm-rf-outside')
  expect(bash('bash -c "npm test && echo ok"')).toBe(null)
  expect(bash('bash scripts/build.sh')).toBe(null)
  expect(bash('echo "$(git rev-parse HEAD)"')).toBe(null)
})

test('find -delete and find -exec rm -r are checked like rm -r on the searched paths', () => {
  expect(bash('find ~ -name "*.log" -delete')?.action).toBe('deny')
  expect(bash('find / -type d -exec rm -rf {} +')?.action).toBe('deny')
  expect(bash('find ../other -delete')?.rule).toBe('rm-rf-outside')
  expect(bash('find . -name "*.tmp" -delete')).toBe(null)
  expect(bash('find -name "*.tmp" -delete')).toBe(null)
  expect(bash('find /tmp/x -delete')).toBe(null)
  expect(bash('find / -name "*.php"')).toBe(null)
})

test('xargs rm -r: targets from find are checked, from elsewhere asked', () => {
  expect(bash('find ~ -name node_modules | xargs rm -rf')?.action).toBe('deny')
  expect(bash('find . -name node_modules -print0 | xargs -0 rm -rf')).toBe(null)
  expect(bash('cat list.txt | xargs -n 1 rm -rf')?.rule).toBe('rm-rf-outside')
  expect(bash('ls | xargs rm -f')).toBe(null)
  expect(bash('echo main | xargs git push -f origin')?.action).toBe('ask')
  expect(bash('git ls-files | xargs wc -l')).toBe(null)
})

test('WP-CLI commands that wipe or rewrite the database ask', () => {
  expect(bash('wp db reset --yes')?.rule).toBe('wp-destructive')
  expect(bash('wp db drop --yes')?.rule).toBe('wp-destructive')
  expect(bash('wp db import dump.sql')?.rule).toBe('wp-destructive')
  expect(bash('wp site empty --yes')?.rule).toBe('wp-destructive')
  expect(bash('wp search-replace https://old.test https://new.test --all-tables')?.rule).toBe('wp-destructive')
  expect(bash('docker compose exec wordpress wp db reset --yes')?.rule).toBe('wp-destructive')
  expect(bash('ddev wp search-replace a b')?.rule).toBe('wp-destructive')
  expect(bash('vendor/bin/wp db clean --yes')?.rule).toBe('wp-destructive')
  expect(bash('wp search-replace a b --dry-run')).toBe(null)
  expect(bash('wp search-replace a b --export=out.sql')).toBe(null)
  expect(bash('wp db export backup.sql')).toBe(null)
  expect(bash('wp post list --format=ids')).toBe(null)
  expect(bash('wp cache flush')).toBe(null)
})

test('deleting docker volumes asks', () => {
  expect(bash('docker compose down -v')?.rule).toBe('docker-data-loss')
  expect(bash('docker compose -f dev.yml down --volumes')?.rule).toBe('docker-data-loss')
  expect(bash('docker-compose down -v')?.rule).toBe('docker-data-loss')
  expect(bash('docker volume rm site_db')?.rule).toBe('docker-data-loss')
  expect(bash('docker volume prune -f')?.rule).toBe('docker-data-loss')
  expect(bash('docker system prune -a --volumes')?.rule).toBe('docker-data-loss')
  expect(bash('ddev delete -O')?.rule).toBe('docker-data-loss')
  expect(bash('lando destroy -y')?.rule).toBe('docker-data-loss')
  expect(bash('docker compose down')).toBe(null)
  expect(bash('docker compose up -d')).toBe(null)
  expect(bash('docker volume ls')).toBe(null)
  expect(bash('docker system prune -f')).toBe(null)
})

test('new rules can be turned off', () => {
  const config = mergeConfig(DEFAULT_CONFIG, { rules: { 'wp-destructive': 'off', 'docker-data-loss': 'deny' } })
  expect(checkBash(config, 'wp db reset --yes', ctx)).toBe(null)
  expect(checkBash(config, 'docker compose down -v', ctx)?.action).toBe('deny')
})

test('messages name the full path, with ~ for home', () => {
  expect(checkPath(DEFAULT_CONFIG, '/work/app/config/.env', '/work/app')?.reason.startsWith('/work/app/config/.env ')).toBe(true)
  expect(checkPath(DEFAULT_CONFIG, '/home/u/site/.env', '/home/u/site', '/home/u')?.reason.startsWith('~/site/.env ')).toBe(true)
  expect(bash('rm -rf ../other')?.reason).toBe('rm -rf on /work/other, outside the project')
  expect(bash('rm -rf ~/old/cache')?.reason).toBe('rm -rf on ~/old/cache, outside the project')
  expect(displayPath('/home/u', '/home/u')).toBe('~')
  expect(displayPath('/home/user2/x', '/home/u')).toBe('/home/user2/x')
})

test('long paths are shortened from the middle, keeping the file name', () => {
  expect(shortenPath('/a/b/c', 20)).toBe('/a/b/c')
  const long = '~/wp-local-dev/academy/web/app/themes/sage/config/.env.production'
  const cut = shortenPath(long, 40)
  expect(cut.length).toBe(40)
  expect(cut.startsWith('~/wp-local-dev')).toBe(true)
  expect(cut.endsWith('/config/.env.production')).toBe(true)
  const line = fitText(`${long} is a protected file (.env.*)`, 60)
  expect(line.length).toBe(60)
  expect(line.endsWith('/.env.production is a protected file (.env.*)')).toBe(true)
  expect(fitText('short text', 60)).toBe('short text')
  expect(fitText('no path here at all, just a long sentence that goes on', 20)).toBe('no path here at all…')
})

test('rm -r on a variable set earlier in the same line is judged by its value', () => {
  // The command from a real session: T is set to a scratch folder in /tmp.
  expect(bash('cd ~/wp-local-dev; T=/tmp/claude-1000/x/scratchpad/badca; rm -rf $T; mkdir -p $T; CAROOT=$T mkcert -install')).toBe(null)
  expect(bash('export T=/tmp/y && rm -rf "${T}/sub"')).toBe(null)
  expect(bash('T=src/gen; rm -rf $T')).toBe(null)
  expect(bash('T=/etc/nginx; rm -rf $T')?.reason).toBe('rm -rf on /etc/nginx (from $T), outside the project')
  expect(bash('T=~; rm -rf $T/')?.rule).toBe('rm-rf-root')
  expect(bash('T=/tmp/a; T=/etc/b; rm -rf $T')?.action).toBe('ask')
})

test('rm -r on a variable guard cannot read says so', () => {
  const unknown = "rm -rf on $T: guard can't tell what $T holds, so it may delete anything"
  expect(bash('rm -rf $T')?.reason).toBe(unknown)
  expect(bash('T=$(mktemp -d); rm -rf $T')?.reason).toBe(unknown)
  expect(bash('T=/tmp/a; T=$X; rm -rf $T')?.reason).toBe(unknown)
  // A prefix assignment lasts only for its own command; $T is expanded before it.
  expect(bash('T=/tmp/a rm -rf $T')?.reason).toBe(unknown)
  expect(bash('rm -rf $HOME/old')?.rule).toBe('rm-rf-outside')
})

test('shell writes to protected files are judged as the Write tool is', () => {
  // Redirections, attached or not, appending or not, any stream.
  for (const cmd of ['echo DEBUG=1 > .env', 'echo DEBUG=1 >.env', 'printf x>.env', 'cat >> .env.local <<EOF', 'some-cmd 2> ~/.netrc', 'echo x &> .git/config']) {
    expect(bash(cmd)?.rule).toBe('protected-file')
    expect(bash(cmd)?.action).toBe('deny')
  }
  // Commands that write files.
  for (const cmd of ['echo x | tee .env', 'tee -a .env < x', 'cp .env.example .env', 'mv tmp.txt .env', 'cp backup/.env .', 'cp a.txt b.txt -t .git', 'touch .env', 'truncate -s 0 .env', 'dd if=/dev/zero of=.env', "sed -i 's/a/b/' .env", "sed -e 's/a/b/' -i .env", "perl -pi -e 's/a/b/' .env"]) {
    expect(bash(cmd)?.rule).toBe('protected-file')
  }
  // A lockfile asks, as it does for the Write tool.
  expect(bash('npm view x > package-lock.json')?.action).toBe('ask')
  // Reading, other files, other streams, and text with > in it pass.
  for (const cmd of ['cat .env', 'grep KEY .env', 'echo hi > notes.txt', 'cmd 2>&1 | tail', 'cmd > /dev/null 2>&1', 'echo "a > .env"', 'cp .env /tmp/env-copy', "sed 's/a/b/' .env > out.txt", 'node -e "x=>1"']) {
    expect(bash(cmd)).toBe(null)
  }
  // A config's allowPaths lifts it here too.
  const allowed = mergeConfig(DEFAULT_CONFIG, { allowPaths: ['.env.testing'] })
  expect(checkBash(allowed, 'echo X=1 > .env.testing', ctx)).toBe(null)
})
