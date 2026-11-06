'use client'

// The console's side of step-up (#359): WsClient calls requestStepUp when a command refused with step_up_required;
// the shell mounts the Step-up dialog (features/auth/stepup, loaded on first use), which runs auth.stepup.begin /
// .finish, and the client resends the original request once it resolves true. One dialog at a time: a second refusal
// waits its turn. Kept tiny: it is in every page's first load (the parsing and wording live in models/stepUp.ts).

import { create } from 'zustand'
import type { WsError } from '@/lib/ws/errors'

export interface StepUpPrompt {
  id: number
  error: WsError
  resolve: (granted: boolean) => void
}

export const useStepUp = create<{ prompt: StepUpPrompt | null }>(() => ({ prompt: null }))

let queue: Promise<unknown> = Promise.resolve()
let prompts = 0

export const requestStepUp = (error: WsError): Promise<boolean> => {
  if (typeof window === 'undefined') return Promise.resolve(false)
  const ask = () =>
    new Promise<boolean>(resolve =>
      useStepUp.setState({
        prompt: {
          id: ++prompts,
          error,
          resolve: granted => {
            useStepUp.setState({ prompt: null })
            resolve(granted)
          },
        },
      }),
    )
  const next = queue.then(ask, ask)
  queue = next.catch(() => undefined)
  return next
}

export const resetStepUp = () => useStepUp.getState().prompt?.resolve(false)
