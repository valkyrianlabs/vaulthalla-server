import type { NextConfig } from 'next'
import pkg from './package.json'

const isTurbo = process.env.NEXT_TURBO === 'true'

// Icons (FontAwesome SVGs) carry no fill of their own, so an SVG path would paint black: SVGR puts fill="currentColor"
// on the root and marks it data-vh-icon, which globals.css colors with the brand cyan by default (#188). SVGR has no
// `fill` option; it used to be passed here and was silently ignored.
const svgrOptions = { icon: true, svgProps: { fill: 'currentColor', 'data-vh-icon': '' } }

const nextConfig: NextConfig = {
  output: 'standalone',
  devIndicators: false,
  // The console shows its version; inlining just this string keeps package.json (every dependency name) out of
  // first-load JS.
  env: { NEXT_PUBLIC_VAULTHALLA_VERSION: pkg.version },
  allowedDevOrigins: ['vh.home.arpa'],
  images: { localPatterns: [{ pathname: '/preview**' }] },

  // Security headers on every console response, whatever proxy is in front (nginx, Caddy, none in development).
  // No HSTS here: the proxy adds it only with a publicly trusted certificate (#324).
  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          // Share pages carry their token in the path: never leak it through Referer.
          { key: 'Referrer-Policy', value: 'no-referrer' },
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'Content-Security-Policy', value: "frame-ancestors 'none'" },
          { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=(), payment=()' },
        ],
      },
    ]
  },

  // Old console URLs keep working (bookmarks, links in emails and docs).
  async redirects() {
    return [
      { source: '/fs', destination: '/files', permanent: false },
      { source: '/dashboard', destination: '/health', permanent: false },
      { source: '/dashboard/runtime', destination: '/health/runtime', permanent: false },
      { source: '/dashboard/filesystem', destination: '/health/filesystem', permanent: false },
      { source: '/dashboard/storage', destination: '/health/storage', permanent: false },
      { source: '/dashboard/operations', destination: '/health/activity', permanent: false },
      { source: '/dashboard/trends', destination: '/health/activity', permanent: false },
      { source: '/dashboard/:rest*', destination: '/health', permanent: false },
      { source: '/api-keys', destination: '/credentials', permanent: false },
      { source: '/api-keys/add', destination: '/credentials/new', permanent: false },
      { source: '/api-keys/:id', destination: '/credentials/:id', permanent: false },
      { source: '/pricing-budget', destination: '/cost', permanent: false },
      { source: '/operator-email', destination: '/notifications', permanent: false },
      { source: '/users/add', destination: '/users/new', permanent: false },
      { source: '/users/:name/edit', destination: '/users/:name', permanent: false },
      { source: '/users/:name/change-password', destination: '/users/:name', permanent: false },
      { source: '/vaults/add', destination: '/vaults/new', permanent: false },
      { source: '/vaults/:id/edit', destination: '/vaults/:id/settings', permanent: false },
      { source: '/vaults/:id/assign', destination: '/vaults/:id/access', permanent: false },
      { source: '/roles/admin', destination: '/roles?type=admin', permanent: false },
      { source: '/roles/vault', destination: '/roles?type=vault', permanent: false },
      { source: '/roles/admin/add', destination: '/roles/new?type=admin', permanent: false },
      { source: '/roles/vault/add', destination: '/roles/new?type=vault', permanent: false },
    ]
  },
  turbopack: {
    rules: {
      '*.svg': { loaders: [{ loader: '@svgr/webpack', options: svgrOptions }], as: '*.js' },
    },
  },

  webpack(config) {
    if (!isTurbo) {
      config.module.rules.push({
        test: /\.svg$/i,
        issuer: /\.[jt]sx?$/,
        use: [{ loader: '@svgr/webpack', options: svgrOptions }],
      })
    }
    return config
  },
}

export default nextConfig
