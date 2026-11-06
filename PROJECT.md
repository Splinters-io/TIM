# TIM — Project Status

**TIM = Time In the Middle.** A tool to get devices working again when
they're stuck in a TLS/SSL error state because of an expired certificate.
Runs on a Kali box as a rogue AP that feeds a connected device a fake clock
and NATs it out to the real internet, rewriting only the time signals.

Date of this note: 2026-11-06. Language: Go, no third-party deps.

## What's done

- **Core spoofers** (`internal/spoof`, tested on macOS): NTP/SNTP v1–4,
  RFC 868 Time (37), RFC 867 Daytime (13), and a transparent HTTP proxy that
  rewrites the `Date:` header. Driven by a shared fake clock (`internal/clock`)
  that can anchor-and-tick, freeze, or offset real time.
- **AP + routing** (`internal/ap`, `internal/fw`): hostapd + dnsmasq config
  and process management; iptables NAT/REDIRECT with every rule tagged `TIM`
  so teardown is exact. DHCP advertises TIM as the NTP/time server.
- **`tim discover`** (`internal/discover`): raw-socket capture that classifies
  how a device tries to get time (NTP, 37/13, NTS, Roughtime, PTP, time-ish
  DNS, HTTP, TLS SNI) and prints a per-device report + suggested `tim up`.
- **`tim certs`** (`internal/certs`): chain inspection, validity window,
  suggested `--time`.
  - `--root`: given the device's own trusted roots, searches for a date at
    which the device would accept the server's chain — or explains why none
    can work (vendor switched CA / root expired / hostname mismatch).
  - `--hok`: checks keys against a local clone of
    [sec-consult/houseofkeys](https://github.com/sec-consult/houseofkeys)
    and flags certificates whose **private key is public** (detection only).
  - Weak-key checks (ROCA, <2048-bit RSA, MD5/SHA-1), notable-CA warnings
    (eMudhra/emSign, DST Root CA X3, AddTrust, Symantec, etc.).
- **CLI**: `up`, `down`, `check`, `discover`, `certs`, `serve`. Static Linux
  amd64/arm64 builds in `dist/`.
- **Tests** pass; verified locally against the real House of Keys dataset and
  live hosts (letsencrypt.org, emsign.com, expired.badssl.com).

## What's left to do

- **First real run on Kali** of the AP, firewall, and capture paths (only the
  host-portable code has actually been exercised).
- **House of Keys distribution**: don't bundle/clone 1,600 private keys. Plan
  is `tim hok update` → pinned download (commit `b4c8ee41`) + checksum →
  build a ~100 KB fingerprint-only index in `~/.cache/tim/` → delete the raw
  keys. `tim certs` uses the index automatically, offline-friendly, with
  `--hok off` / `TIM_HOK=off` opt-out. (Alternative: embed a fingerprint-only
  index in the binary; licensing of the product list is unclear as the repo
  has no LICENSE.)
- **Trust-store repair helpers** for the cases time-spoofing can't fix:
  - `tim certs --export` to pull the real current chain so an owner can load
    the correct up-to-date root onto their own device.
  - When `--root` shows "vendor switched CA", name the new CA and the root to
    add, if the device supports updating its trust store.

## Scope boundary — how the safety line works

This is a design decision I'm keeping, not a bug to work around. It's
explained here in full so there's no confusion later about why a feature is
or isn't present.

### The one test

> Does the feature help the device validate the *real* server, or does it let
> TIM *stand in for* the server?

- **Fix what the device checks against (clock, its own trust store)** →
  repair. The device still authenticates the genuine endpoint. In scope.
- **Fix the device's trust so it accepts an identity that isn't the real
  server's (a forged cert via a leaked or distrusted-CA key)** →
  interception. TIM becomes a man-in-the-middle that terminates the device's
  TLS. Out of scope.

Everything below is downstream of that one distinction. Put plainly: **TIM
corrects the device's *clock*. It does not forge the *identity* of the servers
the device talks to.**

### What is explicitly fine

Security tooling is dual-use, and most of TIM is on the defensible side. None
of this is restricted:

- **Time spoofing** in every form (NTP/37/13/HTTP Date), including the rogue
  AP and NAT, because it only corrects the clock.
- **Diagnosis**: `tim certs`, the `--root` path search, `tim discover`.
- **Detection of weakness**: flagging House-of-Keys keys, ROCA, weak RSA,
  distrusted CAs. Telling an owner "this device's key is public, treat it as
  compromised" is defensive. Reading the *public* half of the HoK dataset to
  do that is fine.
- **Trust-store repair**: helping an owner load the correct current root onto
  their own device — the real fix for the CA cases.

### What trips the boundary

A feature is out of scope if it does any of these, regardless of framing or
who's asking:

- Uses a private key (leaked, default, or otherwise) to present a server
  identity the operator doesn't legitimately hold.
- Forges or exploits a CA weakness to make a device accept a certificate the
  genuine owner of that name didn't issue.
- Terminates, decrypts, or modifies a device's TLS session as a
  man-in-the-middle, rather than passing it through untouched (TIM NATs HTTPS
  straight out and never touches it).
- Is a config flag or mode whose purpose is to turn any of the above on.

### Why the leaked-key ("tactical access") idea is on the wrong side

It's tempting to treat "use the House of Keys private key the device already
trusts" as just another compatibility shim like faking the clock. It isn't:

1. **It targets confidentiality, not validity.** A wrong clock makes a *valid*
   cert look invalid; correcting it restores authentication. A leaked key lets
   you present a cert the device accepts *while not being the real server* —
   that defeats authentication rather than restoring it.
2. **The capability is identical regardless of consent.** "Decrypt/alter the
   TLS of a device that trusts key X" works the same whether the device is
   your friend's or a stranger's. Time-spoofing is also usable on a device you
   don't own, but it only ever helps that device reach its *own* real server
   and hands the operator nothing. The leaked-key feature hands the operator
   the device's plaintext. That asymmetry is the point.
3. **It doesn't even achieve the repair goal.** Impersonating the server at
   TIM doesn't give the device its service back — the connection terminates at
   TIM and goes nowhere useful.

So the answer doesn't change when the device is clearly owned by a cooperating
friend: ownership makes the *time* path fine (it already was), but it doesn't
convert an interception primitive into a repair one. Rewording it — "only
temporary", "the owner consents", "it's their data" — doesn't change what the
code does on the wire.

### Honest limits of this explanation

- I don't have perfect introspective access to the classifier that halted an
  earlier reply mid-sentence. That was a separate safety layer, not a tool
  error, and I can't reconstruct its exact trigger. What I can give is my own
  reasoning, above, which is stable and applied consistently.
- The line is about **capability and outcome, not keywords**. A legitimate
  repair feature won't be refused for sitting near security topics — the rogue
  AP, raw-packet capture, and reading leaked-key fingerprints are all in.

### Bottom line

Everything the project needs for its stated goal — unbricking a time-locked
device so it can reach its own real services — is on the allowed side, and is
largely built. The only thing excluded is turning TIM from a clock-fixer into
a TLS interceptor, and that exclusion costs the project nothing because
interception wouldn't restore the device anyway. If the real device is a CA
case rather than a clock case, the fix is changing what the *device* trusts
(see the trust-store helpers above); share what
`tim certs --root <device-bundle> <host>` reports and we can work it.

## Layout

```
cmd/tim/            CLI: up, down, check, discover, certs, serve
internal/clock/     fake clock
internal/spoof/     NTP, Time(37), Daytime(13), HTTP Date proxy
internal/ap/        hostapd + dnsmasq
internal/fw/        iptables NAT/REDIRECT, tagged teardown
internal/discover/  raw-socket capture + per-device report
internal/certs/     chain inspection, device-root path search, HoK, weak keys
```
