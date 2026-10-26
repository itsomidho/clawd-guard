export type GuardAction = 'deny' | 'ask'

export type GuardHit = {
  action: GuardAction
  rule: string
  summary: string
  at: number
  // What set it off: the command, or the tool and the file. Missing on hits
  // saved by an older version.
  detail?: string
}

declare module 'claude-code' {
  interface PluginState {
    'clawd-guard': {
      denied: number
      asked: number
      last: GuardHit | null
      isBandHidden: boolean
      isPaused: boolean
    }
  }
}
