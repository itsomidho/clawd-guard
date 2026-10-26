import { expect, test } from 'claude-code/testing'
import type { On, RenderElement } from 'claude-code'

// The engine beneath the plugin: a project at /work/app on branch main with
// uncommitted changes and no config files.
function world(on: On, files: Record<string, string> = {}) {
  on('session.root', () => ({ value: '/work/app' }))
  on('session.cwd', () => ({ value: '/work/app' }))
  on('env.get', () => ({ value: '/home/u' }))
  on('fs.exists', ($, e) => ({ value: e.path in files }))
  on('fs.read', ($, e) => ({ value: files[e.path] ?? '' }))
  on('process.run', ($, e) => ({ value: {
    exitCode: 0,
    stdout: e.argv.includes('rev-parse') ? 'main\n' : e.argv.includes('status') ? ' M a.ts\n' : '',
    stderr: '',
    isStdoutTruncated: false,
    isStderrTruncated: false,
  } }))
  on('clock.now', () => ({ value: 1_700_000_000_000 }))
  on('ui.toast', () => ({ value: undefined }))
  on('ui.render', ($, e) => h($.ui.resolve(e).Box, {}) as RenderElement)
  on('tool.check', () => ({ decision: 'allow' as const }))
}

test('a force-push to the current main branch is denied', async ($, on) => {
  world(on)
  const verdict = await $.tool.check({ tool: 'Bash', input: { command: 'git push --force' } })
  expect(verdict.decision).toBe('deny')
  expect(verdict.reason?.includes('git-force-push-protected')).toBe(true)
})

test('git reset --hard on a dirty tree asks; harmless commands pass', async ($, on) => {
  world(on)
  expect((await $.tool.check({ tool: 'Bash', input: { command: 'git reset --hard' } })).decision).toBe('ask')
  expect((await $.tool.check({ tool: 'Bash', input: { command: 'npm test' } })).decision).toBe('allow')
})

test('writing .env is denied, a normal file is allowed', async ($, on) => {
  world(on)
  const env = await $.tool.check({ tool: 'Write', input: { file_path: '/work/app/.env', content: 'A=1' } })
  expect(env.decision).toBe('deny')
  const ok = await $.tool.check({ tool: 'Edit', input: { file_path: '/work/app/src/a.ts', old_string: 'a', new_string: 'b' } })
  expect(ok.decision).toBe('allow')
})

test('a project config turns a rule off', async ($, on) => {
  world(on, { '/work/app/.claude/clawd-guard.json': '{ "rules": { "chmod-world-writable": "off" } }' })
  expect((await $.tool.check({ tool: 'Bash', input: { command: 'chmod 777 x' } })).decision).toBe('allow')
})

test('the band counts blocks, shows the last one and hides on Dismiss', async ($, on) => {
  world(on)
  let blocks = 0
  for (const surface of ['terminal', 'desktop'] as const) {
    await $.tool.check({ tool: 'Bash', input: { command: 'rm -rf /' } })
    blocks += 1
    const ui = await $.ui.mount({ plugin: 'clawd-guard', surface, component: 'AbovePrompt', // Only the props the band reads; the rest are the engine's.
      props: { hasSurvey: false, isWorking: false, maxRows: 10, bodyColumns: 120 } as never })
    expect(await ui.find({ type: 'Text', text: /rm -rf? on \// })).toBeDefined()
    expect(await ui.find({ type: 'Text', text: String(blocks) })).toBeDefined()
    // Framed like clawd-statusbar and clawd-logs: a round, dim border.
    const drawn = JSON.stringify(await ui.drawn())
    expect(drawn).toContain('"borderStyle":"round"')
    expect(drawn).toContain('"borderDimColor":true')
    await ui.press({ key: 'dismiss' })
    expect(await ui.find({ key: 'dismiss' })).toBeUndefined()
  }
})

test('the band shows a protected file by its full path, without the pattern', async ($, on) => {
  world(on)
  await $.tool.check({ tool: 'Write', input: { file_path: '/home/u/sites/app/web/app/themes/sage/config/.env.production', content: 'A=1' } })
  for (const [cols, want] of [[160, '~/sites/app/web/app/themes/sage/config/.env.production is a protected file'], [90, '/config/.env.production is a protected file']] as const) {
    const ui = await $.ui.mount({ plugin: 'clawd-guard', surface: 'terminal', component: 'AbovePrompt',
      props: { hasSurvey: false, isWorking: false, maxRows: 10, bodyColumns: cols } as never })
    const text = (await ui.find({ type: 'Text', text: /protected file/ }))?.text ?? ''
    expect(text.trim().endsWith(want)).toBe(true)
    expect(text.includes('(.env')).toBe(false)
  }
  const status = await $.command.run({ command: 'guard', args: '' } as never)
  expect(String((status as { text?: string }).text).includes('is a protected file (.env.*)')).toBe(true)
})
