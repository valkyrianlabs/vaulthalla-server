---
title: Trust The Vaulthalla CA
navTitle: Client Trust
description: Install the name-constrained Vaulthalla CA on Macs, iPhones and iPads, Linux, Windows, Android and Firefox, verify it, and remove it.
order: 62
status: published
tags:
  - https
  - tls
  - certificates
---

# Trust The Vaulthalla CA

An internal hostname such as `vault.home.arpa` gets its certificate from the CA that [`vh setup caddy`](/https/caddy#internal-names-with-the-vaulthalla-ca) creates. Each device that opens Vaulthalla has to trust that CA once. Until it does, browsers show a certificate warning: do not click through it, because the warning is the only thing telling you that you reached your own server.

:::toc[On this page]{depth="3" theme="compact"}
:::

## Why It Is Safe To Trust

The Vaulthalla CA's certificate carries critical X.509 **name constraints** listing only your Vaulthalla hostnames (or the `--ca-scope` domain). Current operating systems and browsers refuse any certificate it signs for another name. Trusting it lets it vouch for `vault.home.arpa`, not for your bank.

Check what a CA covers before you install it:

```bash
openssl x509 -in vaulthalla-local-ca.crt -noout -subject -fingerprint -sha256
openssl x509 -in vaulthalla-local-ca.crt -noout -text | grep -A3 'Name Constraints'
```

Compare the SHA-256 fingerprint with the one `vh setup caddy` printed on the Mac. Install a certificate only if they match.

## Get The Certificate

On the Mac that runs Vaulthalla, the certificate is at:

```text
/Library/Application Support/Vaulthalla/vaulthalla-local-ca.crt
```

It is a public certificate (no private key), readable by everyone. Copy it to the device by AirDrop, mail, a USB stick or `scp`.

## Install It

:::tabs{default="mac"}

:::tab[Mac]{value="mac"}
On the Mac running Vaulthalla:

```bash
sudo vh setup caddy --trust
```

On any other Mac:

```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain vaulthalla-local-ca.crt
```

macOS asks for confirmation. Safari, Chrome and most apps use the System keychain.
:::

:::tab[iPhone and iPad]{value="ios"}
1. Send the `.crt` to the device (AirDrop or Mail) and open it. iOS says a profile was downloaded.
2. Open **Settings → General → VPN & Device Management**, select the profile and choose **Install**.
3. Open **Settings → General → About → Certificate Trust Settings** and turn on full trust for the Vaulthalla CA.

Step 3 is easy to miss: without it, the certificate is installed but not trusted.
:::

:::tab[Linux]{value="linux"}
Debian, Ubuntu and derivatives:

```bash
sudo cp vaulthalla-local-ca.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates
```

Browsers that keep their own certificate store (Firefox, Chromium snaps) may need the certificate imported there as well.
:::

:::tab[Windows]{value="windows"}
In an Administrator command prompt:

```bash
certutil -addstore -f Root vaulthalla-local-ca.crt
```

Edge and Chrome use the Windows store.
:::

:::tab[Android]{value="android"}
**Settings → Security → More security settings → Encryption & credentials → Install a certificate → CA certificate**, then pick the file. The menu names vary by vendor.

Android trusts user-installed CAs in Chrome, but many apps ignore them by design.
:::

:::tab[Firefox]{value="firefox"}
Firefox on macOS and Windows trusts certificates from the system store when `security.enterprise_roots.enabled` is on (the default there). Otherwise import it: **Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import**, and tick "Trust this CA to identify websites".
:::

:::

## Name Resolution

Trust is only half of it: the device must also resolve `vault.home.arpa` to the Mac. Add a DNS record (A or AAAA) for it on your router or local DNS server. On the Mac itself, `sudo vh setup caddy --hosts-entry` adds a marked `/etc/hosts` line for testing.

## When The CA Changes

`vh setup caddy` creates a new CA when you configure a hostname outside the current one's constraints, and `vh teardown caddy --purge` deletes it. Devices then need the new certificate. Plan names up front with `--ca-scope` (for example `--ca-scope home.arpa`) to avoid this.

## Remove Trust

Remove the CA from devices when you retire the Mac or purge Caddy:

```bash
# macOS (or Keychain Access → System → Certificates): find its SHA-1 hash, then delete by hash
security find-certificate -a -Z -c "Vaulthalla Local CA" /Library/Keychains/System.keychain | grep -E 'SHA-1|"alis"'
sudo security delete-certificate -Z <SHA-1 hash> /Library/Keychains/System.keychain

# Debian/Ubuntu
sudo rm /usr/local/share/ca-certificates/vaulthalla-local-ca.crt
sudo update-ca-certificates --fresh
```

On iPhone and iPad, remove the profile in **Settings → General → VPN & Device Management**. On Windows, use `certmgr.msc` → Trusted Root Certification Authorities. The certificate's common name starts with `Vaulthalla Local CA`, followed by the hostname and the date it was created.
