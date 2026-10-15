import { atom, read, update } from 'claude-code'
import type { EngineInterface as Engine, Register, ToolCheckResult } from 'claude-code'

import type { GuardHit } from '../types'
import {
  DEFAULT_CONFIG,
  checkBash,
  checkPath,
  checkSecrets,
  commitKind,
  mergeConfig,
  parseConfigFile,
  strictest,
} from './rules'
import type { Config, ConfigFile, ShellContext, Verdict } from './rules'

const PLUGIN = 'clawd-guard'
const CONFIG_NAME = 'clawd-guard.json'

const denied = atom({ plugin: 'clawd-guard', key: 'denied' } as const, 0)
const asked = atom({ plugin: 'clawd-guard', key: 'asked' } as const, 0)
const last = atom({ plugin: 'clawd-guard', key: 'last' } as const, null)
const isBandHidden = atom({ plugin: 'clawd-guard', key: 'isBandHidden' } as const, false)
const isPaused = atom({ plugin: 'clawd-guard', key: 'isPaused' } as const, false)

async function readOptional($: Engine, path: string): Promise<string | undefined> {
  try {
    return (await $.fs.exists(path)) ? String(await $.fs.read(path)) : undefined
  } catch {
    return undefined
  }
}

async function homeDir($: Engine): Promise<string | undefined> {
  try {
    return await $.env.get('HOME')
  } catch {
    return undefined
  }
}

type Loaded = { config: Config; sources: string[]; errors: string[] }

// The defaults, then ~/.claude/clawd-guard.json, then the project's
// .claude/clawd-guard.json: read on every check, so an edit applies at once.
async function loadConfig($: Engine, root: string): Promise<Loaded> {
  const home = await homeDir($)
  const paths = [...(home === undefined ? [] : [`${home}/.claude/${CONFIG_NAME}`]), `${root}/.claude/${CONFIG_NAME}`]
  const files: ConfigFile[] = []
  const sources: string[] = []
  const errors: string[] = []
  for (const path of paths) {
    const text = await readOptional($, path)
    if (text === undefined) continue
    try {
      files.push(parseConfigFile(text))
      sources.push(path)
    } catch (error) {
      errors.push(`${path}: ${error instanceof Error ? error.message : String(error)}`)
    }
  }
  return { config: mergeConfig(DEFAULT_CONFIG, ...files), sources, errors }
}

async function git($: Engine, args: string[]): Promise<string | undefined> {
  try {
    const run = await $.process.run(['git', ...args], { timeoutMs: 5000 })
    return run.exitCode === 0 ? run.stdout : undefined
  } catch {
    return undefined
  }
}

async function shellContext($: Engine, command: string, root: string): Promise<ShellContext> {
  const cwd = await $.session.cwd()
  const home = await homeDir($)
  const usesGit = /\bgit\b/.test(command)
  const branch = usesGit ? (await git($, ['rev-parse', '--abbrev-ref', 'HEAD']))?.trim() : undefined
  const status = usesGit ? await git($, ['status', '--porcelain']) : undefined
  return {
    root,
    cwd,
    home,
    branch: branch === '' || branch === 'HEAD' ? undefined : branch,
    isDirty: status === undefined ? undefined : status.trim() !== '',
  }
}

function field(input: unknown, key: string): string | undefined {
  if (typeof input !== 'object' || input === null) return undefined
  const value = (input as Record<string, unknown>)[key]
  return typeof value === 'string' ? value : undefined
}

async function judge($: Engine, tool: string, input: unknown): Promise<Verdict | null> {
  const root = await $.session.root()
  const { config, errors } = await loadConfig($, root)
  if (errors.length > 0) $.ui.toast(`🛡 ${PLUGIN}: config not read, defaults used: ${errors[0]}`)

  if (tool === 'Bash') {
    const command = field(input, 'command') ?? ''
    const ctx = await shellContext($, command, root)
    const verdicts = [checkBash(config, command, ctx)]
    const commits = commitKind(command)
    if (commits !== 'none') {
      const diff = await git($, commits === 'all' ? ['diff', 'HEAD'] : ['diff', '--cached'])
      if (diff !== undefined) verdicts.push(checkSecrets(config, diff, 'the commit', true))
    }
    return strictest(verdicts)
  }

  const path = field(input, 'file_path') ?? field(input, 'notebook_path')
  if (path === undefined) return null
  const text = field(input, 'content') ?? field(input, 'new_string') ?? field(input, 'new_source') ?? ''
  const name = path.slice(path.lastIndexOf('/') + 1)
  return strictest([checkPath(config, path, root), checkSecrets(config, text, name)])
}

async function record($: Engine, v: Verdict): Promise<void> {
  const hit: GuardHit = { action: v.action, rule: v.rule, summary: v.reason, at: await $.clock.now() }
  if (v.action === 'deny') await update($, denied, n => n + 1)
  else await update($, asked, n => n + 1)
  await update($, last, () => hit)
  await update($, isBandHidden, () => false)
  $.ui.toast(`🛡 ${v.action === 'deny' ? 'Blocked' : 'Needs approval'}: ${v.reason}`)
}

export const register: Register = on => {
  on('session.start', async ($, e, next) => {
    await $.command.register({
      name: 'guard',
      description: 'clawd-guard: status, or "off" / "on" for this session, "reset" the counters',
      argumentHint: '[off|on|reset]',
    })
    return next(e)
  })

  on('tool.check', { tool: ['Bash', 'Write', 'Edit', 'NotebookEdit'] }, async ($, e, next) => {
    if (await read($, isPaused)) return next(e)
    const v = await judge($, e.tool, e.input)
    if (v === null) return next(e)

    const reason = `${PLUGIN}: ${v.reason} [${v.rule}]`
    if (v.action === 'deny') {
      await record($, v)
      return { decision: 'deny', reason } satisfies ToolCheckResult
    }
    // An ask never loosens what the rules beneath already refuse.
    const beneath = await next(e)
    if (beneath.decision === 'deny') return beneath
    await record($, v)
    return { decision: 'ask', reason } satisfies ToolCheckResult
  }).catch(() => ({ decision: 'deny', reason: `${PLUGIN}: its check failed, so the call was refused; /guard off pauses it` }))

  on('command.run', { command: 'guard' }, async ($, e) => {
    const arg = e.args.trim()
    if (arg === 'off' || arg === 'on') {
      await update($, isPaused, () => arg === 'off')
      return { text: arg === 'off' ? '🛡 clawd-guard paused for this session.' : '🛡 clawd-guard is on.' }
    }
    if (arg === 'reset') {
      await update($, denied, () => 0)
      await update($, asked, () => 0)
      await update($, last, () => null)
      return { text: '🛡 clawd-guard counters reset.' }
    }
    const root = await $.session.root()
    const { config, sources, errors } = await loadConfig($, root)
    const rules = Object.entries(config.rules).map(([k, v]) => `  ${k.padEnd(28)} ${v}`)
    const lastHit = await read($, last)
    const lines = [
      `🛡 clawd-guard ${(await read($, isPaused)) ? 'is PAUSED (/guard on to resume)' : 'is on'}`,
      `Blocked ${await read($, denied)}, asked ${await read($, asked)} this session.`,
      ...(lastHit === null ? [] : [`Last: ${lastHit.action} — ${lastHit.summary}`]),
      `Config: ${sources.length > 0 ? sources.join(', ') : `defaults (add ~/.claude/${CONFIG_NAME} or .claude/${CONFIG_NAME})`}`,
      ...errors.map(err => `Config error: ${err}`),
      'Rules:',
      ...rules,
      `Protected branches: ${config.protectedBranches.join(', ')}`,
    ]
    return { text: lines.join('\n') }
  })

  on('ui.render', { component: 'AbovePrompt' }, async ($, e, next) => {
    const hit = await read($, last)
    if (e.props.hasSurvey || hit === null || (await read($, isBandHidden))) return next(e)

    const { Box, Button, Text } = $.ui.resolve(e)
    const nDenied = await read($, denied)
    const nAsked = await read($, asked)
    const room = Math.max(20, e.props.bodyColumns - 44)
    const summary = hit.summary.length > room ? hit.summary.slice(0, room - 1) + '…' : hit.summary

    return (
      <Box>
        <Text color={hit.action === 'deny' ? 'red' : 'yellow'}>🛡 </Text>
        <Text bold>{nDenied}</Text>
        <Text dimColor> blocked · </Text>
        <Text bold>{nAsked}</Text>
        <Text dimColor> asked · </Text>
        <Text>{summary} </Text>
        <Button key="dismiss" label="Dismiss" onPress={() => update($, isBandHidden, () => true)} />
      </Box>
    )
  })
}
