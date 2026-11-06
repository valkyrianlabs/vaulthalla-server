'use client'

import React, { useEffect, useState } from 'react'
import Link from 'next/link'
import NextImage from 'next/image'
import { usePathname } from 'next/navigation'
import { cn } from '@/util/cn'
import type { NavItem, NavSection } from '@/components/shell/nav'
import { useUiPrefs } from '@/components/shell/uiPrefs'
import { Tooltip } from '@/components/ui/Tooltip'
import { IconButton } from '@/components/ui/IconButton'
import { BarsIcon, ChevronLeftIcon, MagnifyingGlassIcon } from '@/components/ui/icons'
import { Kbd } from '@/components/ui/Badge'
import dynamic from 'next/dynamic'
import { useCommandPalette } from '@/components/shell/commandPaletteStore'
import { useStepUp } from '@/lib/stepUp'
import { useVisibleNav } from '@/components/shell/useVisibleNav'
import { UserMenu } from '@/components/shell/UserMenu'
import { ConnectionIndicator } from '@/components/shell/ConnectionIndicator'
import { TopBarExtras } from '@/components/shell/TopBarExtras'
import { InitialPasswordWarning } from '@/components/shell/InitialPasswordWarning'
import Logo from '@/public/vaulthalla-logo.png'

// cmdk loads the first time the palette opens.
const CommandPalette = dynamic(() => import('@/components/shell/CommandPalette').then(m => m.CommandPalette), { ssr: false })

// The Step-up dialog (#359) loads the first time a command asks for a step-up.
const StepUpDialog = dynamic(() => import('@/features/auth/stepup/StepUpDialog').then(m => m.StepUpDialog), { ssr: false })

const isActive = (pathname: string, href: string) => pathname === href || pathname.startsWith(`${href}/`)

const NavLink = ({ item, collapsed, onNavigate }: { item: NavItem; collapsed: boolean; onNavigate?: () => void }) => {
  const pathname = usePathname() ?? ''
  const active = isActive(pathname, item.href)
  const link = (
    <Link
      href={item.href}
      onClick={onNavigate}
      aria-current={active ? 'page' : undefined}
      className={cn(
        'group relative flex h-9 w-full items-center gap-3 rounded-control px-2.5 text-sm text-fg-muted transition-colors hover:bg-surface-2 hover:text-fg',
        active && 'bg-accent-soft text-fg shadow-[inset_0_0_0_1px_var(--accent-line)]',
        collapsed && 'justify-center px-0',
      )}>
      {active ? <span aria-hidden className="absolute top-2 bottom-2 -left-2 w-[3px] rounded-full bg-accent shadow-[0_0_10px_var(--accent-glow)]" /> : null}
      <item.icon aria-hidden className={cn('size-[18px] shrink-0 text-fg-subtle transition-colors group-hover:text-fg-muted', active && 'text-accent-text group-hover:text-accent-text')} />
      {collapsed ? <span className="sr-only">{item.label}</span> : <span className="truncate">{item.label}</span>}
    </Link>
  )
  return collapsed ? (
    <Tooltip content={item.label} side="right" wrapperClassName="flex">
      {link}
    </Tooltip>
  ) : (
    link
  )
}

export const NavSections = ({ sections, collapsed, onNavigate }: { sections: NavSection[]; collapsed: boolean; onNavigate?: () => void }) => (
  <nav aria-label="Main" className="flex flex-col gap-5">
    {sections.map((section, index) => (
      <div key={section.label ?? index} className="flex flex-col gap-0.5">
        {section.label ? (
          collapsed ? (
            <div aria-hidden className="mx-auto mb-1.5 h-px w-6 bg-line" />
          ) : (
            <div className="mb-1 px-2.5 text-[11px] font-medium tracking-wider text-fg-faint uppercase">{section.label}</div>
          )
        ) : null}
        {section.items.map(item => (
          <NavLink key={item.href} item={item} collapsed={collapsed} onNavigate={onNavigate} />
        ))}
      </div>
    ))}
  </nav>
)

export const Brand = ({ collapsed }: { collapsed: boolean }) => (
  <Link href="/files" className={cn('flex items-center gap-2.5 rounded-control px-1.5 py-1', collapsed && 'justify-center px-0')}>
    <NextImage src={Logo} alt="" width={30} height={30} priority className="size-[30px] drop-shadow-[0_0_10px_rgb(34_211_238/0.25)]" />
    {collapsed ? <span className="sr-only">Vaulthalla</span> : <span className="text-[15px] font-semibold tracking-tight text-fg">Vaulthalla</span>}
  </Link>
)

const Rail = () => {
  const sections = useVisibleNav()
  const collapsed = useUiPrefs(state => state.railCollapsed)
  const setCollapsed = useUiPrefs(state => state.setRailCollapsed)
  return (
    <aside
      className={cn(
        'glass sticky top-0 hidden h-dvh shrink-0 flex-col border-y-0 border-l-0 transition-[width] duration-200 md:flex',
        collapsed ? 'w-[68px]' : 'w-60',
      )}>
      <div className={cn('flex h-14 items-center px-3', collapsed && 'justify-center px-0')}>
        <Brand collapsed={collapsed} />
      </div>
      <div className={cn('min-h-0 flex-1 px-3 py-3 scrollbar-thin', collapsed ? 'overflow-visible' : 'overflow-y-auto')}>
        <NavSections sections={sections} collapsed={collapsed} />
      </div>
      <div className={cn('flex items-center justify-between border-t border-line px-3 py-2.5', collapsed && 'flex-col gap-2 px-0')}>
        <span className="font-mono text-[11px] text-fg-faint" title="Web console version">
          v{process.env.NEXT_PUBLIC_VAULTHALLA_VERSION}
        </span>
        <IconButton
          label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          icon={ChevronLeftIcon}
          size="icon-sm"
          className={cn(collapsed && 'rotate-180')}
          onClick={() => setCollapsed(!collapsed)}
        />
      </div>
    </aside>
  )
}

// The mobile navigation sheet (Radix dialog) loads on first tap.
const MobileNavSheet = dynamic(() => import('@/components/shell/MobileNav').then(m => m.MobileNavSheet), { ssr: false })

const MobileNav = () => {
  const [open, setOpen] = useState(false)
  const [armed, setArmed] = useState(false)
  return (
    <>
      <IconButton
        label="Open navigation"
        icon={BarsIcon}
        className="md:hidden"
        tooltip={false}
        onClick={() => {
          setArmed(true)
          setOpen(true)
        }}
      />
      {armed ? <MobileNavSheet open={open} onOpenChange={setOpen} /> : null}
    </>
  )
}

const SearchTrigger = () => {
  const open = useCommandPalette(state => state.setOpen)
  return (
    <button
      type="button"
      onClick={() => open(true)}
      className="flex h-9 w-full max-w-md items-center gap-2.5 rounded-control border border-line bg-surface-1 px-3 text-sm text-fg-faint transition-colors hover:border-line-strong hover:text-fg-subtle">
      <MagnifyingGlassIcon className="size-4" aria-hidden />
      <span className="flex-1 truncate text-left">Search or jump to…</span>
      <span className="hidden items-center gap-1 sm:flex">
        <Kbd>⌘</Kbd>
        <Kbd>K</Kbd>
      </span>
    </button>
  )
}

const TopBar = () => (
  <header className="sticky top-0 z-40 flex h-14 items-center gap-3 border-b border-line bg-bg/70 px-3 backdrop-blur-xl sm:px-5">
    <MobileNav />
    <div className="min-w-0 flex-1">
      <SearchTrigger />
    </div>
    <div className="flex items-center gap-1.5">
      <ConnectionIndicator />
      <TopBarExtras />
      <UserMenu />
    </div>
  </header>
)

const PaletteMount = () => {
  const open = useCommandPalette(state => state.open)
  const [mounted, setMounted] = useState(false)
  useEffect(() => {
    if (open) setMounted(true)
  }, [open])
  return mounted ? <CommandPalette /> : null
}

const StepUpMount = () => {
  const prompt = useStepUp(state => state.prompt)
  // Keyed by the prompt: each one starts its own ceremony.
  return prompt ? <StepUpDialog key={prompt.id} /> : null
}

export const AppShell = ({ children }: { children: React.ReactNode }) => (
  <div className="flex min-h-dvh">
    <Rail />
    <div className="flex min-w-0 flex-1 flex-col">
      <TopBar />
      <main id="main" className="min-w-0 flex-1 px-4 py-6 sm:px-6 lg:px-8">
        <div className="mx-auto w-full max-w-[1400px]">
          <InitialPasswordWarning />
          {children}
        </div>
      </main>
    </div>
    <PaletteMount />
    <StepUpMount />
  </div>
)
