'use client'

import React, { useState } from 'react'
import { Button } from '@/components/ui/Button'
import { Dialog, DialogClose, DialogContent } from '@/components/ui/Dialog'
import { Field, Select, Textarea } from '@/components/ui/Field'
import { InlineError } from '@/components/ui/State'
import { notify } from '@/components/ui/Toast'
import { errorMessage } from '@/lib/ws/errors'
import { FINDINGS_COPY as C } from '@/features/health/findings/copy'
import { NOTE_MAX, SILENCE_CHOICES, noteOf, silencePayload, type SilenceChoice } from '@/features/health/findings/model'
import { useSilence } from '@/features/health/findings/queries'

export interface SilenceTarget {
  class: string
  subject: string
  title: string
}

// Loaded with next/dynamic and mounted only while open.
export default function SilenceDialog({
  target,
  open,
  onOpenChange,
}: {
  target: SilenceTarget
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const [choice, setChoice] = useState<SilenceChoice>('day')
  const [note, setNote] = useState('')
  const silence = useSilence()
  const { length, tooLong } = noteOf(note)

  const submit = () => {
    if (tooLong) return
    silence.mutate(silencePayload(target, choice, note), {
      onSuccess: () => {
        notify.success(C.silencedToast(target.title))
        onOpenChange(false)
      },
    })
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent
        size="sm"
        title={C.silenceTitle(target.title)}
        description={C.silenceBody}
        data-testid="health-silence-dialog"
        footer={
          <>
            <DialogClose asChild>
              <Button variant="ghost">{C.cancel}</Button>
            </DialogClose>
            <Button type="submit" form="health-silence-form" variant="primary" loading={silence.isPending} disabled={tooLong}>
              {C.silenceConfirm}
            </Button>
          </>
        }>
        <form
          id="health-silence-form"
          noValidate
          className="space-y-4"
          onSubmit={event => {
            event.preventDefault()
            submit()
          }}>
          <Field label={C.silenceFor} htmlFor="health-silence-for">
            <Select id="health-silence-for" value={choice} onChange={event => setChoice(event.target.value as SilenceChoice)}>
              {SILENCE_CHOICES.map(c => (
                <option key={c.id} value={c.id}>
                  {c.label}
                </option>
              ))}
            </Select>
          </Field>
          <Field
            label={C.noteLabel}
            htmlFor="health-silence-note"
            hint={C.noteHint(NOTE_MAX)}
            error={tooLong ? C.noteTooLong(NOTE_MAX, length) : undefined}>
            <Textarea
              id="health-silence-note"
              rows={3}
              value={note}
              onChange={event => setNote(event.target.value)}
              aria-invalid={tooLong || undefined}
            />
          </Field>
          <InlineError error={silence.error ? `${C.silenceFailed}: ${errorMessage(silence.error)}` : null} />
        </form>
      </DialogContent>
    </Dialog>
  )
}
