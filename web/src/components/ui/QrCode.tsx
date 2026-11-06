'use client'

import React, { useMemo } from 'react'
import { encodeQr } from '@/lib/qr'
import { cn } from '@/util/cn'

// A QR code drawn in the page (lib/qr.ts): dark modules on white with the four-module quiet zone scanners need, in
// both themes. For secrets (the TOTP enrollment URI): nothing is fetched or sent anywhere to draw it.
export const QrCode = ({ value, label, className }: { value: string; label: string; className?: string }) => {
  const { size, path } = useMemo(() => {
    const m = encodeQr(value)
    let d = ''
    m.forEach((row, y) =>
      row.forEach((dark, x) => {
        if (dark) d += `M${x + 4} ${y + 4}h1v1h-1z`
      }),
    )
    return { size: m.length + 8, path: d }
  }, [value])
  return (
    <svg
      role="img"
      aria-label={label}
      viewBox={`0 0 ${size} ${size}`}
      shapeRendering="crispEdges"
      className={cn('block aspect-square rounded-md bg-white', className)}>
      <path d={path} fill="#000" />
    </svg>
  )
}
