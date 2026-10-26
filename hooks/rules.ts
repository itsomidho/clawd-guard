// Pure rule logic: no engine calls, so every rule is testable on its own.

export type Action = 'deny' | 'ask' | 'off'

export type Verdict = { action: 'deny' | 'ask'; rule: string; reason: string }

export type PathRule = { pattern: string; action: Action }

export type Config = {
  rules: Record<string, Action>
  protectedBranches: string[]
  protect: PathRule[]
  allowPaths: string[]
  rmAllowPaths: string[]
}

// What a shell rule needs to know about where it runs.
export type ShellContext = {
  root: string
  cwd: string
  home: string | undefined
  // The current git branch, or undefined when it could not be read.
  branch: string | undefined
  // Whether the work tree has uncommitted changes; undefined when unknown.
  isDirty: boolean | undefined
}

export const DEFAULT_CONFIG: Config = {
  rules: {
    'rm-rf-root': 'deny',
    'rm-rf-outside': 'ask',
    'git-force-push-protected': 'deny',
    'git-force-push': 'ask',
    'git-push-delete-protected': 'deny',
    'git-discard-dirty': 'ask',
    'sql-destructive': 'ask',
    'chmod-world-writable': 'ask',
    'pipe-to-shell': 'ask',
    'wp-destructive': 'ask',
    'docker-data-loss': 'ask',
    'protected-file': 'deny',
    'secret-high': 'deny',
    'secret-generic': 'ask',
  },
  protectedBranches: ['main', 'master', 'production', 'release'],
  protect: [
    { pattern: '.env', action: 'deny' },
    { pattern: '.env.*', action: 'deny' },
    { pattern: '*.pem', action: 'deny' },
    { pattern: '*.key', action: 'deny' },
    { pattern: '*.p12', action: 'deny' },
    { pattern: '*.pfx', action: 'deny' },
    { pattern: 'id_rsa*', action: 'deny' },
    { pattern: 'id_ed25519*', action: 'deny' },
    { pattern: 'id_ecdsa*', action: 'deny' },
    { pattern: '.netrc', action: 'deny' },
    { pattern: '.git/**', action: 'deny' },
    { pattern: 'package-lock.json', action: 'ask' },
    { pattern: 'yarn.lock', action: 'ask' },
    { pattern: 'pnpm-lock.yaml', action: 'ask' },
    { pattern: 'bun.lockb', action: 'ask' },
    { pattern: 'composer.lock', action: 'ask' },
    { pattern: 'Cargo.lock', action: 'ask' },
    { pattern: 'poetry.lock', action: 'ask' },
    { pattern: 'uv.lock', action: 'ask' },
    { pattern: 'Gemfile.lock', action: 'ask' },
    { pattern: 'go.sum', action: 'ask' },
  ],
  allowPaths: ['.env.example', '.env.sample', '.env.template', '.env.dist'],
  rmAllowPaths: ['/tmp/**', '/var/tmp/**'],
}

// A user's config file, as written: every field optional.
export type ConfigFile = Partial<Config>

// Later files win: rules merge per key, lists add up, a protect entry with the
// same pattern replaces the earlier one (so `"action": "off"` lifts a default).
export function mergeConfig(base: Config, ...files: ConfigFile[]): Config {
  let merged = base
  for (const file of files) {
    const protect = new Map(merged.protect.map(r => [r.pattern, r]))
    for (const rule of file.protect ?? []) protect.set(rule.pattern, rule)
    merged = {
      rules: { ...merged.rules, ...file.rules },
      protectedBranches: file.protectedBranches ?? merged.protectedBranches,
      protect: [...protect.values()],
      allowPaths: [...merged.allowPaths, ...(file.allowPaths ?? [])],
      rmAllowPaths: [...merged.rmAllowPaths, ...(file.rmAllowPaths ?? [])],
    }
  }
  return merged
}

export function parseConfigFile(text: string): ConfigFile {
  const value: unknown = JSON.parse(text)
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error('the config must be a JSON object')
  }
  return value as ConfigFile
}

function verdict(config: Config, rule: string, reason: string, fallback: Action = 'ask'): Verdict | null {
  const action = config.rules[rule] ?? fallback
  return action === 'off' ? null : { action, rule, reason }
}

// The stricter of several verdicts: any deny wins over an ask.
export function strictest(verdicts: readonly (Verdict | null)[]): Verdict | null {
  let found: Verdict | null = null
  for (const v of verdicts) {
    if (v === null) continue
    if (found === null || (v.action === 'deny' && found.action === 'ask')) found = v
  }
  return found
}

// ---------- paths and globs ----------

export function normalize(path: string): string {
  const isAbsolute = path.startsWith('/')
  const parts: string[] = []
  for (const part of path.split('/')) {
    if (part === '' || part === '.') continue
    if (part === '..') {
      if (parts.length > 0 && parts[parts.length - 1] !== '..') parts.pop()
      else if (!isAbsolute) parts.push('..')
      continue
    }
    parts.push(part)
  }
  return (isAbsolute ? '/' : '') + parts.join('/')
}

export function isInside(path: string, dir: string): boolean {
  const p = normalize(path)
  const d = normalize(dir)
  return d === '/' || p === d || p.startsWith(d + '/')
}

// The full path, with ~ for the home folder.
export function displayPath(path: string, home: string | undefined): string {
  const p = normalize(path)
  if (home === undefined || normalize(home) === '/') return p
  const h = normalize(home)
  return p === h ? '~' : p.startsWith(h + '/') ? '~' + p.slice(h.length) : p
}

// A path cut to `max` characters from the middle, so its start and its file
// name both stay.
export function shortenPath(path: string, max: number): string {
  if (path.length <= max) return path
  if (max < 2) return '…'
  const name = path.slice(path.lastIndexOf('/'))
  // The file's folder too when it fits: it says more than the path's start.
  const cut = path.lastIndexOf('/', path.length - name.length - 1)
  const parent = cut < 0 ? name : path.slice(cut)
  const keep = parent.length <= max - 2 ? parent : name
  const tail = Math.min(max - 1, Math.max(keep.length, Math.floor((max - 1) / 2)))
  return path.slice(0, max - 1 - tail) + '…' + path.slice(path.length - tail)
}

// A message cut to `room` characters. The longest path in it is shortened
// from the middle first; only then is the end cut.
export function fitText(text: string, room: number): string {
  if (text.length <= room) return text
  const paths = text.match(/(?:~|\/)[^\s,;()]*\/[^\s,;()]+/g) ?? []
  const path = paths.reduce((a, b) => (b.length > a.length ? b : a), '')
  if (path !== '') {
    const max = path.length - (text.length - room)
    const name = path.slice(path.lastIndexOf('/'))
    if (max >= Math.min(name.length + 2, 12)) {
      const at = text.indexOf(path)
      return text.slice(0, at) + shortenPath(path, max) + text.slice(at + path.length)
    }
  }
  return text.slice(0, Math.max(0, room - 1)) + '…'
}

export function globToRegExp(glob: string): RegExp {
  let source = ''
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i] ?? ''
    if (c === '*' && glob[i + 1] === '*') {
      source += '.*'
      i++
      if (glob[i + 1] === '/') i++
    } else if (c === '*') source += '[^/]*'
    else if (c === '?') source += '[^/]'
    else source += c.replace(/[.+^${}()|[\]\\]/g, '\\$&')
  }
  return new RegExp(`^${source}$`)
}

// A pattern with no slash matches the file's name in any folder; one with a
// slash matches the path from the project root (or an absolute path).
export function matchesGlob(pattern: string, absPath: string, root: string): boolean {
  const re = globToRegExp(pattern.replace(/^\.\//, ''))
  const path = normalize(absPath)
  const name = path.slice(path.lastIndexOf('/') + 1)
  if (!pattern.includes('/')) return re.test(name)
  if (pattern.startsWith('/')) return re.test(path)
  const rel = isInside(path, root) ? path.slice(normalize(root).length + 1) : path
  // `.git/**` also catches a nested repository's `.git` folder.
  return re.test(rel) || (pattern.startsWith('.git/') && /(^|\/)\.git\//.test(path))
}

export function checkPath(config: Config, absPath: string, root: string, home?: string): Verdict | null {
  if (config.allowPaths.some(p => matchesGlob(p, absPath, root))) return null
  const hits = config.protect.filter(r => r.action !== 'off' && matchesGlob(r.pattern, absPath, root))
  if (hits.length === 0) return null
  const rule = hits.find(r => r.action === 'deny') ?? hits[0]
  if (rule === undefined) return null
  const base = verdict(config, 'protected-file', `${displayPath(absPath, home)} is a protected file (${rule.pattern})`, 'deny')
  if (base === null) return null
  // The path rule's own action, but never looser than turning the rule off.
  return { ...base, action: rule.action === 'deny' && base.action === 'deny' ? 'deny' : 'ask' }
}

// ---------- the shell ----------

// Splits a command line into simple commands at ; && || | and newlines,
// each one a list of words with quotes removed. Best effort, not a shell.
export function splitCommands(line: string): string[][] {
  const commands: string[][] = []
  let words: string[] = []
  let word = ''
  let hasWord = false
  let quote: '"' | "'" | null = null
  const endWord = () => {
    if (hasWord) words.push(word)
    word = ''
    hasWord = false
  }
  const endCommand = (op: string) => {
    endWord()
    if (words.length > 0) commands.push(op === '|' ? [...words, '\u0000|'] : words)
    words = []
  }
  for (let i = 0; i < line.length; i++) {
    const c = line[i]
    if (quote !== null) {
      if (c === quote) quote = null
      else if (c === '\\' && quote === '"' && i + 1 < line.length) word += line[++i]
      else word += c
      continue
    }
    if (c === '"' || c === "'") {
      quote = c
      hasWord = true
    } else if (c === '\\' && i + 1 < line.length) {
      word += line[++i]
      hasWord = true
    } else if (c === ' ' || c === '\t') endWord()
    else if (c === '\n' || c === ';') endCommand(';')
    else if (c === '&' && line[i + 1] === '&') {
      endCommand(';')
      i++
    } else if (c === '|' && line[i + 1] === '|') {
      endCommand(';')
      i++
    } else if (c === '|') endCommand('|')
    else if (c === '(' || c === ')' || c === '`') endWord()
    else {
      word += c
      hasWord = true
    }
  }
  endCommand(';')
  return commands
}

const WRAPPERS = new Set(['sudo', 'doas', 'command', 'builtin', 'exec', 'nohup', 'time', 'env'])

// Drops `sudo`, `env X=1` and the like so the command itself comes first.
export function stripWrappers(words: readonly string[]): string[] {
  let i = 0
  while (i < words.length) {
    const w = words[i] ?? ''
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(w)) i++
    else if (WRAPPERS.has(w)) {
      i++
      while (i < words.length && (words[i] ?? '').startsWith('-')) i++
    } else break
  }
  return words.slice(i)
}

function basename(word: string): string {
  return word.slice(word.lastIndexOf('/') + 1)
}

function expandHome(word: string, home: string | undefined): string {
  if (home === undefined) return word
  if (word === '~' || word === '$HOME' || word === '${HOME}') return home
  for (const prefix of ['~/', '$HOME/', '${HOME}/']) {
    if (word.startsWith(prefix)) return home + '/' + word.slice(prefix.length)
  }
  return word
}

type RmArgs = { isRecursive: boolean; isForce: boolean; targets: string[] }

function parseRm(args: readonly string[]): RmArgs {
  let isRecursive = false
  let isForce = false
  const targets: string[] = []
  let isOptionsDone = false
  for (const a of args) {
    if (!isOptionsDone && a === '--') isOptionsDone = true
    else if (!isOptionsDone && a.startsWith('--')) {
      if (a === '--recursive') isRecursive = true
      if (a === '--force') isForce = true
    } else if (!isOptionsDone && a.startsWith('-') && a.length > 1) {
      if (/[rR]/.test(a)) isRecursive = true
      if (a.includes('f')) isForce = true
    } else targets.push(a)
  }
  return { isRecursive, isForce, targets }
}

function checkRm(config: Config, args: string[], ctx: ShellContext): Verdict | null {
  const { isRecursive, isForce, targets } = parseRm(args)
  if (!isRecursive) return null
  return checkTreeTargets(config, targets, ctx, `rm -r${isForce ? 'f' : ''}`)
}

// Whether deleting whole trees at these paths is safe: denied for /, home or
// the project root, asked outside the project or on a variable.
function checkTreeTargets(config: Config, targets: readonly string[], ctx: ShellContext, what: string): Verdict | null {
  const verdicts: (Verdict | null)[] = []
  for (const raw of targets) {
    const expanded = expandHome(raw, ctx.home)
    const isRootish =
      /^(\/|\/\*|~|~\/|~\/\*|\$HOME\/?\*?|\$\{HOME\}\/?\*?)$/.test(raw) ||
      (ctx.home !== undefined && normalize(expanded.replace(/\/\*$/, '')) === normalize(ctx.home)) ||
      (expanded.startsWith('/') && normalize(expanded.replace(/\/\*$/, '')) === normalize(ctx.root))
    if (isRootish) {
      verdicts.push(verdict(config, 'rm-rf-root', `${what} on ${raw} would delete a whole tree (/, home or the project)`, 'deny'))
      continue
    }
    if (raw.includes('$') && !raw.startsWith('$HOME') && !raw.startsWith('${HOME}')) {
      verdicts.push(verdict(config, 'rm-rf-outside', `${what} on ${raw}: a variable that may expand anywhere`))
      continue
    }
    const abs = normalize(expanded.startsWith('/') ? expanded : ctx.cwd + '/' + expanded)
    if (isInside(abs, ctx.root)) continue
    if (config.rmAllowPaths.some(p => matchesGlob(p, abs, ctx.root))) continue
    verdicts.push(verdict(config, 'rm-rf-outside', `${what} on ${displayPath(abs, ctx.home)}, outside the project`))
  }
  return strictest(verdicts)
}

function checkGit(config: Config, args: string[], ctx: ShellContext): Verdict | null {
  // Skip git's own options (-C dir, -c key=value) to reach the subcommand.
  let i = 0
  while (i < args.length && (args[i] ?? '').startsWith('-')) i += args[i] === '-C' || args[i] === '-c' ? 2 : 1
  const sub = args[i]
  const rest = args.slice(i + 1)
  const protectedSet = new Set(config.protectedBranches)

  if (sub === 'push') {
    const flags = rest.filter(a => a.startsWith('-'))
    const positional = rest.filter(a => !a.startsWith('-'))
    const refspecs = positional.slice(1)
    const isDelete = flags.some(f => f === '--delete' || f === '-d') || refspecs.some(r => r.startsWith(':'))
    const isForce =
      flags.some(f => f === '--force' || f === '--force-with-lease' || f.startsWith('--force-with-lease=') || /^-[a-z]*f/.test(f)) ||
      refspecs.some(r => r.startsWith('+'))
    const targets = refspecs.map(r => r.replace(/^[+:]/, '').split(':').pop() ?? '').map(r => r.replace(/^refs\/heads\//, ''))
    const hitsProtected =
      targets.some(t => protectedSet.has(t)) ||
      (targets.length === 0 && (ctx.branch === undefined || protectedSet.has(ctx.branch)))
    if (isDelete && targets.some(t => protectedSet.has(t))) {
      return verdict(config, 'git-push-delete-protected', `git push would delete a protected branch (${targets.join(', ')})`, 'deny')
    }
    if (!isForce) return null
    const isLease = flags.some(f => f.startsWith('--force-with-lease'))
    const branch = targets.length > 0 ? targets.join(', ') : ctx.branch ?? 'the current branch'
    if (hitsProtected && (targets.length > 0 || ctx.branch !== undefined)) {
      return verdict(config, 'git-force-push-protected', `force-push to protected branch ${branch}`, 'deny')
    }
    return verdict(config, 'git-force-push', `force-push${isLease ? ' (with lease)' : ''} to ${branch} rewrites remote history`)
  }

  const discards =
    (sub === 'reset' && rest.includes('--hard')) ||
    (sub === 'clean' && rest.some(a => /^-[a-zA-Z]*f/.test(a) || a === '--force')) ||
    (sub === 'checkout' && rest.includes('--') && rest.slice(rest.indexOf('--') + 1).some(a => a === '.' || a === '*')) ||
    (sub === 'checkout' && rest.some(a => a === '-f' || a === '--force')) ||
    (sub === 'restore' && !rest.includes('--staged') && rest.some(a => a === '.' || a === '*')) ||
    (sub === 'stash' && (rest[0] === 'clear' || rest[0] === 'drop'))
  if (discards && ctx.isDirty !== false) {
    const why = ctx.isDirty === undefined ? 'the work tree state is unknown' : 'there are uncommitted changes'
    return verdict(config, 'git-discard-dirty', `git ${[sub, ...rest].join(' ')} discards work and ${why}`)
  }
  return null
}

// `find <paths> … -delete` or `-exec rm -r …`: the paths it searches are
// what it may delete. Without a path, find searches the current folder.
const FIND_OPTIONS = new Set(['-H', '-L', '-P'])

function findPaths(args: readonly string[]): string[] {
  const paths: string[] = []
  for (const a of args) {
    if (FIND_OPTIONS.has(a) || a.startsWith('-D') || a.startsWith('-O')) continue
    if (a.startsWith('-') || a === '!' || a === '(') break
    paths.push(a)
  }
  return paths.length > 0 ? paths : ['.']
}

function checkFind(config: Config, args: string[], ctx: ShellContext): Verdict | null {
  const execAt = args.findIndex(a => a === '-exec' || a === '-execdir' || a === '-ok' || a === '-okdir')
  const execWords = execAt >= 0 ? stripWrappers(args.slice(execAt + 1)) : []
  const execsRm = basename(execWords[0] ?? '') === 'rm' && parseRm(execWords.slice(1).filter(w => w !== '{}' && w !== '+' && w !== ';')).isRecursive
  if (!args.includes('-delete') && !execsRm) return null
  return checkTreeTargets(config, findPaths(args), ctx, args.includes('-delete') ? 'find -delete' : 'find -exec rm -r')
}

// xargs options that take a value as the next word.
const XARGS_VALUE_OPTIONS = new Set(['-I', '-n', '-P', '-d', '-L', '-s', '-E', '-a', '--max-args', '--max-procs', '--delimiter', '--arg-file'])

function skipXargsOptions(args: readonly string[]): string[] {
  let i = 0
  while (i < args.length && (args[i] ?? '').startsWith('-')) i += XARGS_VALUE_OPTIONS.has(args[i] ?? '') ? 2 : 1
  return args.slice(i)
}

// `… | xargs rm -r`: the targets arrive on stdin. From `find <paths>`, they
// lie under those paths; from anything else, they could be anywhere.
function checkXargsRm(config: Config, rmArgs: string[], before: readonly string[] | undefined, ctx: ShellContext): Verdict | null {
  const rm = parseRm(rmArgs)
  if (!rm.isRecursive) return null
  const fixed = checkTreeTargets(config, rm.targets, ctx, 'xargs rm -r')
  const from = before !== undefined && before[before.length - 1] === '\u0000|' ? stripWrappers(before.slice(0, -1)) : undefined
  if (from !== undefined && basename(from[0] ?? '') === 'find') {
    return strictest([fixed, checkTreeTargets(config, findPaths(from.slice(1)), ctx, 'find | xargs rm -r')])
  }
  return strictest([fixed, verdict(config, 'rm-rf-outside', 'xargs rm -r deletes paths read from input, which could be anywhere')])
}

// WP-CLI commands that wipe or rewrite the database, run directly or through
// docker, ddev, lando or vendor/bin/wp.
function checkWp(config: Config, args: readonly string[]): Verdict | null {
  const [group, sub] = args.filter(a => !a.startsWith('-'))
  const isDry = args.includes('--dry-run') || args.some(a => a === '--export' || a.startsWith('--export='))
  let what: string | null = null
  if (group === 'db' && (sub === 'reset' || sub === 'drop' || sub === 'clean')) what = `wp db ${sub} deletes the database's tables`
  else if (group === 'db' && sub === 'import') what = 'wp db import overwrites the database'
  else if (group === 'site' && (sub === 'empty' || sub === 'delete')) what = `wp site ${sub} deletes the site's content`
  else if (group === 'search-replace' && !isDry) what = 'wp search-replace rewrites the database (no --dry-run or --export)'
  return what === null ? null : verdict(config, 'wp-destructive', what)
}

const WP_RUNNERS = new Set(['docker', 'docker-compose', 'podman', 'ddev', 'lando', 'kubectl'])

function wpArgs(name: string, words: readonly string[]): string[] | null {
  if (name === 'wp') return words.slice(1)
  if (!WP_RUNNERS.has(name)) return null
  const at = words.findIndex((w, i) => i > 0 && basename(w) === 'wp')
  return at > 0 ? words.slice(at + 1) : null
}

// Docker and friends deleting volumes: a local site's database lives there.
function checkDocker(config: Config, name: string, args: readonly string[]): Verdict | null {
  const say = (what: string) => verdict(config, 'docker-data-loss', what)
  const words = args.filter(a => !a.startsWith('-'))
  const hasVolumesFlag = args.some(a => a === '--volumes' || /^-[a-zA-Z]*v[a-zA-Z]*$/.test(a))
  if (name === 'docker' || name === 'podman') {
    if (words[0] === 'compose' && words.includes('down') && hasVolumesFlag) return say(`${name} compose down -v deletes the project's volumes, databases included`)
    if (words[0] === 'volume' && (words[1] === 'rm' || words[1] === 'prune')) return say(`${name} volume ${words[1]} deletes volumes and their data`)
    if (words[0] === 'system' && words[1] === 'prune' && args.includes('--volumes')) return say(`${name} system prune --volumes deletes unused volumes and their data`)
  }
  if (name === 'docker-compose' && words.includes('down') && hasVolumesFlag) return say('docker-compose down -v deletes the project\'s volumes, databases included')
  if (name === 'ddev' && words[0] === 'delete') return say('ddev delete removes the project\'s database')
  if (name === 'lando' && words[0] === 'destroy') return say('lando destroy removes the app and its database')
  return null
}

const SHELLS = new Set(['sh', 'bash', 'zsh', 'fish', 'dash', 'ksh'])
const MAX_DEPTH = 4

// The script a shell runs with -c, e.g. `bash -lc "rm -rf ~"`.
function shellScript(args: readonly string[]): string | null {
  for (let i = 0; i < args.length; i++) {
    const a = args[i] ?? ''
    if (!a.startsWith('-')) return null
    if (/^-[a-zA-Z]*c[a-zA-Z]*$/.test(a)) return args[i + 1] ?? null
  }
  return null
}

// Command substitutions, $(…) and `…`, run even inside double quotes.
function substitutions(line: string): string[] {
  const found: string[] = []
  for (let i = 0; i < line.length; i++) {
    if (line[i] === '$' && line[i + 1] === '(') {
      let depth = 1
      let j = i + 2
      for (; j < line.length && depth > 0; j++) {
        if (line[j] === '(') depth++
        else if (line[j] === ')') depth--
      }
      found.push(line.slice(i + 2, depth === 0 ? j - 1 : j))
      i = j - 1
    } else if (line[i] === '`') {
      const end = line.indexOf('`', i + 1)
      found.push(line.slice(i + 1, end < 0 ? line.length : end))
      i = end < 0 ? line.length : end
    }
  }
  return found
}

const SQL_DESTRUCTIVE = /\b(DROP\s+(TABLE|DATABASE|SCHEMA|INDEX|VIEW)|TRUNCATE(\s+TABLE)?\s+\w|DELETE\s+FROM\s+[\w."`]+\s*(;|$|["'`]))/i
const DROP_COMMANDS = new Set(['dropdb', 'dropuser'])

export function checkBash(config: Config, line: string, ctx: ShellContext, depth = 0): Verdict | null {
  const verdicts: (Verdict | null)[] = []
  const inner = (script: string) => {
    if (depth >= MAX_DEPTH) return verdict(config, 'rm-rf-outside', 'commands nested too deep to check')
    return checkBash(config, script, ctx, depth + 1)
  }
  for (const sub of substitutions(line)) verdicts.push(inner(sub))
  const commands = splitCommands(line)
  for (let n = 0; n < commands.length; n++) {
    const raw = commands[n] ?? []
    const isPiped = raw[raw.length - 1] === '\u0000|'
    const words = stripWrappers(isPiped ? raw.slice(0, -1) : raw)
    if (words.length === 0) continue
    const name = basename(words[0] ?? '')
    const args = words.slice(1)
    const wp = wpArgs(name, words)
    if (wp !== null) verdicts.push(checkWp(config, wp))
    if (name === 'rm') verdicts.push(checkRm(config, args, ctx))
    else if (name === 'find') verdicts.push(checkFind(config, args, ctx))
    else if (name === 'xargs') {
      const run = stripWrappers(skipXargsOptions(args))
      if (basename(run[0] ?? '') === 'rm') verdicts.push(checkXargsRm(config, run.slice(1), commands[n - 1], ctx))
      else if (run.length > 0) verdicts.push(inner(run.map(w => `'${w.replace(/'/g, `'\\''`)}'`).join(' ')))
    } else if (name === 'eval') verdicts.push(inner(args.join(' ')))
    else if (SHELLS.has(name) && shellScript(args) !== null) verdicts.push(inner(shellScript(args) ?? ''))
    else if (name === 'docker' || name === 'podman' || name === 'docker-compose' || name === 'ddev' || name === 'lando') {
      verdicts.push(checkDocker(config, name, args))
    } else if (name === 'git') verdicts.push(checkGit(config, args, ctx))
    else if (name === 'chmod' && args.some(a => /^0?777$/.test(a) || /^(a|ugo|o)\+[rwx]*w/.test(a))) {
      verdicts.push(verdict(config, 'chmod-world-writable', `chmod ${args.join(' ')} makes files writable by everyone`))
    } else if (DROP_COMMANDS.has(name)) {
      verdicts.push(verdict(config, 'sql-destructive', `${name} drops a database object`))
    }
    if (SHELLS.has(name) && n > 0) {
      const before = commands[n - 1] ?? []
      const from = basename(stripWrappers(before)[0] ?? '')
      if (before[before.length - 1] === '\u0000|' && (from === 'curl' || from === 'wget')) {
        verdicts.push(verdict(config, 'pipe-to-shell', `${from} piped into ${name} runs a downloaded script unread`))
      }
    }
  }
  if (SQL_DESTRUCTIVE.test(line)) {
    const what = (line.match(SQL_DESTRUCTIVE)?.[1] ?? 'a destructive statement').replace(/\s+/g, ' ').replace(/[;"'`]$/, '').trim()
    verdicts.push(verdict(config, 'sql-destructive', `SQL ${what}`))
  }
  return strictest(verdicts)
}

// Whether a command commits (so its staged changes should be scanned), and
// whether it stages tracked files itself (`commit -a`).
export function commitKind(line: string): 'none' | 'staged' | 'all' {
  let kind: 'none' | 'staged' | 'all' = 'none'
  for (const raw of splitCommands(line)) {
    const words = stripWrappers(raw.filter(w => w !== '\u0000|'))
    if (basename(words[0] ?? '') !== 'git') continue
    let i = 1
    while (i < words.length && (words[i] ?? '').startsWith('-')) i += words[i] === '-C' || words[i] === '-c' ? 2 : 1
    if (words[i] !== 'commit') continue
    const isAll = words.slice(i + 1).some(a => a === '--all' || /^-[a-zA-Z]*a/.test(a))
    kind = isAll ? 'all' : kind === 'all' ? 'all' : 'staged'
  }
  return kind
}

// ---------- secrets ----------

type SecretPattern = { kind: string; re: RegExp; level: 'high' | 'generic' }

const SECRET_PATTERNS: SecretPattern[] = [
  { kind: 'private key', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/, level: 'high' },
  { kind: 'AWS access key', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/, level: 'high' },
  { kind: 'GitHub token', re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b/, level: 'high' },
  { kind: 'GitLab token', re: /\bglpat-[A-Za-z0-9_-]{20,}\b/, level: 'high' },
  { kind: 'Anthropic API key', re: /\bsk-ant-[A-Za-z0-9_-]{20,}/, level: 'high' },
  { kind: 'OpenAI API key', re: /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}/, level: 'high' },
  { kind: 'Slack token', re: /\bxox[abposr]-[A-Za-z0-9-]{10,}/, level: 'high' },
  { kind: 'Stripe live key', re: /\b[sr]k_live_[0-9a-zA-Z]{20,}/, level: 'high' },
  { kind: 'Google API key', re: /\bAIza[0-9A-Za-z_-]{35}\b/, level: 'high' },
  { kind: 'npm token', re: /\bnpm_[A-Za-z0-9]{36}\b/, level: 'high' },
  {
    kind: 'hard-coded credential',
    re: /\b(?:api[_-]?key|secret[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|password|passwd)\b["']?\s*[:=]\s*["']([^"'\s]{12,})["']/i,
    level: 'generic',
  },
]

const PLACEHOLDER = /^(x+|\*+|\.+|<.*>|\$\{?.*\}?|your[_-].*|changeme|example.*|placeholder.*|dummy.*|test.*|process\.env.*)$/i

export type SecretHit = { kind: string; level: 'high' | 'generic'; line: number }

// Finds secrets in text. A line holding `guard:allow` is skipped. In a diff
// (`isDiff`), only added lines are read. Never returns the secret itself.
export function scanSecrets(text: string, isDiff = false): SecretHit[] {
  const hits: SecretHit[] = []
  const lines = text.split('\n')
  for (let n = 0; n < lines.length; n++) {
    let line = lines[n] ?? ''
    if (isDiff) {
      if (!line.startsWith('+') || line.startsWith('+++')) continue
      line = line.slice(1)
    }
    if (line.includes('guard:allow')) continue
    for (const p of SECRET_PATTERNS) {
      const m = line.match(p.re)
      if (m === null) continue
      if (p.level === 'generic' && PLACEHOLDER.test(m[1] ?? '')) continue
      hits.push({ kind: p.kind, level: p.level, line: n + 1 })
      break
    }
  }
  return hits
}

export function checkSecrets(config: Config, text: string, where: string, isDiff = false): Verdict | null {
  const hits = scanSecrets(text, isDiff)
  if (hits.length === 0) return null
  const high = hits.filter(h => h.level === 'high')
  const shown = (high.length > 0 ? high : hits).slice(0, 3)
  const kinds = [...new Set(shown.map(h => h.kind))].join(', ')
  const lines = isDiff ? '' : ` (line ${shown.map(h => h.line).join(', ')})`
  const reason = `${where} holds what looks like a ${kinds}${lines}; mark a false alarm with a guard:allow comment`
  return strictest([
    high.length > 0 ? verdict(config, 'secret-high', reason, 'deny') : null,
    verdict(config, 'secret-generic', reason),
  ])
}
