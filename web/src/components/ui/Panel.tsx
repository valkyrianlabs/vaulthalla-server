import React from 'react'
import { cn } from '@/util/cn'

export const Panel = ({
  title,
  description,
  actions,
  children,
  className,
  bodyClassName,
  id,
  padded = true,
}: {
  title?: React.ReactNode
  description?: React.ReactNode
  actions?: React.ReactNode
  children?: React.ReactNode
  className?: string
  bodyClassName?: string
  id?: string
  padded?: boolean
}) => (
  <section id={id} className={cn('panel min-w-0', className)} aria-labelledby={id && title ? `${id}-title` : undefined}>
    {title || actions ? (
      <header className="flex flex-wrap items-start justify-between gap-3 px-5 pt-4">
        <div className="min-w-0">
          {title ? (
            <h2 id={id ? `${id}-title` : undefined} className="text-[15px] font-semibold text-fg">
              {title}
            </h2>
          ) : null}
          {description ? <p className="mt-0.5 text-sm text-fg-subtle">{description}</p> : null}
        </div>
        {/* max-w-full, not shrink-0: on a phone the buttons wrap inside the panel instead of running past its edge. */}
        {actions ? <div className="flex max-w-full flex-wrap items-center gap-2">{actions}</div> : null}
      </header>
    ) : null}
    <div className={cn(padded && 'px-5 pt-3 pb-5', !title && !actions && padded && 'pt-5', bodyClassName)}>{children}</div>
  </section>
)

export const PageHeader = ({
  title,
  description,
  actions,
  eyebrow,
  className,
}: {
  title: React.ReactNode
  description?: React.ReactNode
  actions?: React.ReactNode
  eyebrow?: React.ReactNode
  className?: string
}) => (
  <div className={cn('mb-6 flex flex-wrap items-end justify-between gap-4', className)}>
    <div className="min-w-0">
      {eyebrow ? <div className="mb-1.5 text-xs font-medium tracking-wide text-accent-text/80 uppercase">{eyebrow}</div> : null}
      <h1 className="truncate text-2xl font-semibold tracking-tight text-fg">{title}</h1>
      {description ? <p className="mt-1 max-w-3xl text-sm text-fg-subtle">{description}</p> : null}
    </div>
    {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
  </div>
)

// Key/value list for detail views.
export const DefinitionList = ({ items, className }: { items: [React.ReactNode, React.ReactNode][]; className?: string }) => (
  <dl className={cn('grid grid-cols-[minmax(7rem,max-content)_1fr] gap-x-6 gap-y-2.5 text-sm', className)}>
    {items.map(([term, value], index) => (
      <React.Fragment key={index}>
        <dt className="text-fg-subtle">{term}</dt>
        <dd className="min-w-0 break-words text-fg">{value}</dd>
      </React.Fragment>
    ))}
  </dl>
)
