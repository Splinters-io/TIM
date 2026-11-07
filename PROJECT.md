# TIM — Project Status

**TIM = Time In the Middle.** A general-purpose network time-control and
certificate-diagnostics toolkit. Supports standalone protocol services and a
Kali WiFi AP for controlled-clock testing, compatibility experiments,
troubleshooting and device-repair investigations.

Date of this note: 2026-11-07. Language: Go, no third-party deps.

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

## Completion update — 2026-11-07

- Added `tim hok update`: immutable commit and SHA-256 pinned download,
  bounded extraction, temporary dataset removal, atomic fingerprint-only cache.
  `certs` uses the local cache without networking; explicit directories/cache
  files and `--hok off` / `TIM_HOK=off` are supported.
- Added `tim certs --export FILE` for one observed chain, with no overwrite.
  Failed device-root checks now identify the presented issuer and name a root
  candidate only if verification against the current system trust store succeeds.
  Exported server chains are not automatically trusted or installed.
- Fixed the testbed's missing CA mount and HTTP environment wiring, froze its
  fake clock, and disabled transparent destination lookup in standalone serve
  mode so Linux direct HTTP requests use the requested upstream host.
- Added Docker-free integration coverage: actual TLS rejects an expired leaf
  on real time, accepts it after NTP and HTTP Date sync, and still rejects an
  unrelated trust store. Added cache corruption/path traversal/roundtrip and
  certificate export checks. Verified the pinned dataset yields 567 fingerprints.

## Remaining hardware validation

The software work above is complete locally. The first real Kali AP/firewall/
capture run still needs a Linux host and an AP-capable WiFi adapter. Docker is
not installed on this development machine, so Compose itself remains untested;
the protocol/TLS integration test runs without Docker.

On the Kali machine, with your actual interface names:

```bash
sudo ./tim check --ap wlan1 --uplink eth0
sudo ./tim discover --ap wlan1 --uplink eth0
sudo ./tim up --ap wlan1 --uplink eth0 --time <date-from-certs>
# After Ctrl-C, confirm TIM's firewall rules were removed:
sudo iptables-save | grep TIM
```

Also verify the connected device receives its DHCP lease, DNS and ordinary
internet access work, discovery identifies its time traffic, and its own service
recovers after the time correction. After a forced interruption, run `tim down`
and check firewall cleanup and restoration of the original forwarding setting.

## Project scope

TIM diagnoses certificate failures and changes network time signals so a device
can test certificate validation at another date. HTTPS is forwarded unchanged.
It does not install trust anchors, forge certificates, or terminate device TLS.
House of Keys data is used only for public-key fingerprint detection.

Compatibility with specific devices and environments remains unverified. See
[CHANGELOG.md](CHANGELOG.md) for release validation and remaining limitations.

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
