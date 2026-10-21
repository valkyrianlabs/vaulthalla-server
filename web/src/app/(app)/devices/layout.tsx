import React from 'react'
import { DevicesShell } from '@/features/devices/DevicesShell'

export default function Layout({ children }: { children: React.ReactNode }) {
  return <DevicesShell>{children}</DevicesShell>
}
