# Changelog

## v0.1.0-beta.2 — 2026-11-07

### Added

- `tim tls-time`: standalone HTTPS Date endpoint using an engineer-supplied
  PEM certificate chain and matching private key.
- GET/HEAD on `/` and `/time`, RFC3339 GET body and cache-disabled responses.
- Shared fixed, ticking and offset scenario clocks; loopback:10443 by default.
- TLS 1.2 minimum by default, TLS 1.3 support and explicit 1.0/1.1 legacy opt-in.
- Network tests for TLS 1.0–1.3, GET/HEAD behavior, wrong hostname, untrusted CA,
  expired certificate, mismatched/missing keys and server shutdown.
- Expanded capability matrix and hardware/software roadmap.

### Compatibility limits

This is an HTTPS Date endpoint, not a transparent TLS proxy or a legacy
ServerHello timestamp generator. Clients still validate the supplied certificate
using their own trust, hostname and clock. Legacy protocol negotiation is tested
with Go clients; no physical legacy-device or tlsdate-binary compatibility is
claimed. Kali AP/hardware and Docker Compose validation remain pending.

Linux amd64/arm64 binaries and SHA256SUMS accompany this pre-release. The
v0.1.0-beta.1 release remains available unchanged.

## v0.1.0-beta.1 — 2026-11-07

First public experimental beta of TIM (Time In the Middle), a general-purpose
network time-control and certificate-diagnostics toolkit.

### Features

- Kali WiFi AP orchestration, DHCP, NAT and targeted time redirection.
- NTP/SNTP, RFC 868 Time, RFC 867 Daytime and HTTP Date time services.
- Fixed, ticking and offset clocks; device targeting by MAC, IP or subnet.
- Discovery of device time traffic, HTTP hosts and TLS SNI.
- Certificate validity analysis, device-root checks and suggested dates.
- Weak-key and known-compromised-key detection with a checksum-pinned,
  fingerprint-only House of Keys cache (`tim hok update`).
- Observed certificate-chain export and system-verified root guidance.
- Preflight checks, cleanup command and a synthetic TLS repair testbed.
- Static Linux amd64 and arm64 binaries; `tim version` identifies this beta.

### Validation and known limits

- Go vet passes for the native platform and Linux; unit and local network
  integration tests pass on macOS.
- Synthetic TLS tests demonstrate failure on real time, successful validation
  after NTP/HTTP time correction, and continued rejection of an unrelated CA.
- Verified the real pinned House of Keys snapshot produces 567 fingerprints.
- Kali WiFi/AP, firewall, DHCP and packet capture need real hardware testing.
- Docker Compose is supplied but has not been executed for this release.
- Compatibility with specific devices and environments is not yet established.
- Time changes cannot fix missing trusted roots, unavailable vendor services,
  or authenticated/non-network clocks. TIM does not decrypt HTTPS traffic.

### Downloads

- `tim-linux-amd64`: Intel/AMD 64-bit Linux.
- `tim-linux-arm64`: ARM64 Linux.
- `SHA256SUMS`: SHA-256 checksums for the two binaries.

Run `chmod +x tim-linux-amd64` (or the arm64 filename), then `./tim-linux-amd64
version`. For AP preflight, install hostapd, dnsmasq, iptables and iw, then run
`sudo ./tim-linux-amd64 check --ap wlan1 --uplink eth0` with your interface names.

Please report beta issues with the TIM version, Kali/kernel version, adapter
and driver, command used, expected/actual result and relevant redacted logs.
