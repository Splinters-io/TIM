# TIM: Time In the Middle

**Experimental beta — v0.1.0-beta.1.** A network time-control and
certificate-diagnostics toolkit for Linux.

[Download the beta](https://github.com/Splinters-io/TIM/releases/tag/v0.1.0-beta.1)
· [Release notes](CHANGELOG.md) · [MIT licence](LICENSE)

TIM lets you observe how network clients obtain time, serve a controlled clock,
and inspect TLS certificate validity and trust paths. Use it for protocol tests,
compatibility experiments, troubleshooting, lab environments, or investigating
whether a different clock restores a device's connection. It is not tied to a
particular device vendor, industry, or mission.

Run time services on their own, or put a client on a WiFi network controlled by
TIM. Choose a fixed date, a ticking clock anchored to a date, or an offset from
real time. TIM changes selected time signals while forwarding other traffic,
including HTTPS, to its original destination.

Local protocol and TLS repair tests pass. Real Kali WiFi/AP testing is still
pending, and the Docker Compose setup has not been exercised for this release.
Device compatibility must be tested for each environment.

```
 [device] ))) wifi ))) [Kali: wlan1  --TIM--  eth0] ---> internet
                             |  DHCP: "your NTP server is me"
                             |  NTP / Time / Daytime / HTTP Date -> fake time
                             |  everything else -> NAT -> real servers
```

## Quick start (Kali)

```bash
# build on any machine with Go 1.22+ (or grab dist/tim-linux-amd64)
make linux            # -> dist/tim-linux-amd64 and dist/tim-linux-arm64
scp dist/tim-linux-amd64 kali:~/tim

# on the Kali box
sudo apt install hostapd dnsmasq iptables iw
sudo ./tim check --ap wlan1 --uplink eth0

# 1. Which cert expired, and what date should we pretend it is?
./tim certs api.the-vendor.com
#    Better: also give it the device's own root/CA bundle (from the firmware)
./tim certs --root device-ca-bundle.pem api.the-vendor.com

# 2. How does the device get the time? Join it to SSID "TIM", power-cycle it, wait, then Ctrl-C.
sudo ./tim discover --ap wlan1 --uplink eth0

# 3. Fake it.
sudo ./tim up --ap wlan1 --uplink eth0 --time 2024-01-01
```

Then connect the device to the `TIM` network. Most devices only sync time at
boot or when they connect, so power-cycle it once it has joined.

## Commands

| Command | What it does |
|---|---|
| `tim check` | Preflight: root, required tools, whether the card supports AP mode, uplink route, port conflicts |
| `tim certs host[:port]\|file...` | Shows each cert in the chain, which ones expired, and the window when the whole chain is valid; suggests a `--time`. Also flags known-bad keys and notable CAs (see below) |
| `tim discover` | Runs the AP with real time and logs every time-related request per device (NTP, RFC 868, Daytime, NTS, Roughtime, PTP, time-ish DNS names, HTTP hosts, TLS SNI). Prints a report and a suggested `tim up` command |
| `tim up` | Runs the AP and spoofs the time |
| `tim down` | Cleans up after a crash: removes the `TIM`-tagged iptables rules, kills leftover hostapd/dnsmasq, restores `ip_forward` |
| `tim hok update` | Downloads a pinned, checksum-verified House of Keys snapshot and caches only public-key fingerprints and product metadata |
| `tim serve` | Spoofers only, no AP and no firewall. For testing, or for when you handle routing yourself |

### `tim up` options

```
--ap wlan1 --uplink eth0     required
--time 2024-01-01            fake time; ticks forward from there   (or)
--offset -400d               real time shifted, e.g. -1y2w, -36h
--freeze                     with --time: never tick
--spoof ntp,time37,daytime,http   default: all
--target aa:bb:cc:dd:ee:ff   only spoof this device (MACs/IPs/CIDRs, comma-separated)
--block-nts                  reject NTS (tcp/4460) so the client may fall back to plain NTP
--http-ports 80,8080         ports to rewrite HTTP Date on
--ssid TIM --pass ...        AP settings (open if --pass is empty; WPA/WPA2 mixed if set)
--channel 6 --country GB     radio settings
--gw 10.77.0.1               AP subnet (/24)
-v                           show hostapd/dnsmasq output and iptables rules
```

## Certificate checks (`tim certs`)

```bash
tim certs api.vendor.com                 # live server (default port 443)
tim certs 10.77.0.23:8443                # the device's own HTTPS admin UI
tim certs chain.pem firmware-cert.der    # files: PEM bundles or DER
tim certs --root ca-bundle.pem --hok ~/houseofkeys api.vendor.com
```

- **`--root FILE`** (repeatable): the device's trusted root(s), e.g. a CA
  bundle pulled from its firmware. TIM tries every date at which a path from
  the server's certificate to one of those roots could be valid, and reports
  either a working `--time` or **why no date can work**:
  - *the server's chain doesn't lead to any of the device's roots*: the vendor
    switched CA (for example away from eMudhra), so faking the time won't help;
  - *no single date is valid for every certificate*: e.g. a certificate
    issued after the device's root expired (the DST Root CA X3 / Let's Encrypt
    problem);
  - *hostname mismatch*: works only if the device doesn't check hostnames.
- **`--hok DIR`** (or `TIM_HOK=DIR`): a clone of
  [sec-consult/houseofkeys](https://github.com/sec-consult/houseofkeys)
  (`git clone --depth 1 https://github.com/sec-consult/houseofkeys`). TIM
  indexes the *public* half of every certificate and private key in the
  dataset (567 distinct keys, including DSA and quirky firmware encodings)
  and flags any certificate whose private key has been published, along with
  the products it shipped in. Detection only: TIM never uses the leaked keys.
- **Notable CAs:** identifies chains involving eMudhra/emSign, DST Root CA X3, AddTrust External CA Root, legacy
  Symantec/VeriSign, WoSign/StartCom, DigiNotar, CNNIC, TrustCor, Camerfirma,
  E-Tugra or Entrust, with what each means for an old device.
- **Weak keys:** ROCA (CVE-2017-15361) moduli, RSA under 2048 bits, and
  MD5/SHA-1 signatures. Certificates Go can't parse (common in firmware)
  still get the House of Keys check.

### Offline key checks and certificate export

```bash
tim hok update                              # explicit download; no automatic network updates
tim certs api.vendor.com                     # uses the cached fingerprints
tim certs --hok off api.vendor.com           # or TIM_HOK=off
tim certs --export observed-chain.pem api.vendor.com
```

The updater pins House of Keys commit
`b4c8ee416f1c494b033ae930d464a37809ed61d8` and verifies the archive's SHA-256
before indexing it. Temporary raw files are removed after indexing; the cache
contains 567 public-key fingerprints, file IDs, and product descriptions.
The cache is in the OS user cache directory: `~/.cache/tim/houseofkeys.json`
on Linux (or `$XDG_CACHE_HOME/tim/houseofkeys.json`) and
`~/Library/Caches/tim/houseofkeys.json` on macOS. Run the updater as the same
user who runs `certs`. A failed update preserves the previous cache.
`--hok` can also select a dataset directory or a copied fingerprint JSON cache.
Without a cache, certificate checks still run and report that key checks are unavailable.

`--export FILE` accepts one target and writes its observed certificates as PEM,
refusing to overwrite an existing file. Inspection deliberately accepts expired
or untrusted chains, so this export is **not an authenticated root bundle**.
Servers generally omit their root. When the device-root check fails, TIM shows
the presented issuer and, if current system verification succeeds, the root
candidate's name and SHA-256 fingerprint. Obtain the matching root from the CA's
official distribution before updating a device's trust store. If verification
fails, TIM reports that it cannot identify a trusted replacement root.

### Expiry versus trust-store changes

A device may fail because a certificate expired, because its trusted roots no
longer match the server's chain, or because validation fails for another reason.
Use `tim certs --root device-ca-bundle.pem host` to distinguish these cases.
A different date cannot add a missing trusted root. CA-name matches are
informational heuristics; they are not proof of compromise or current browser
trust status. OCSP/CRL validation can also fail when a clock is moved backwards.

## What can and can't be spoofed

| Time source | Spoofed? | How |
|---|---|---|
| NTP / SNTP v1-4 (any server, hard-coded or not) | ✅ | DHCP option 42 points at TIM, and all udp/123 is REDIRECTed to TIM |
| RFC 868 Time (37), RFC 867 Daytime (13) | ✅ | DHCP option 4 + REDIRECT |
| HTTP `Date:` header | ✅ | transparent proxy rewrites only the Date header |
| NTS (authenticated NTP) | ❌ | `--block-nts` may force a fallback to plain NTP |
| HTTPS Date, tlsdate, Roughtime | ❌ | cryptographically signed |
| GPS, cellular, battery RTC | ❌ | not network time; a different problem |
| IPv6 time traffic | ➖ | the TIM AP hands out IPv4 only, so devices normally use v4 |

`discover` tells you which of these the device uses.

## Things to know

- **Choosing a date:** it has to be inside the validity window of *every*
  certificate involved: the server's chain (`tim certs` checks this), the
  device's built-in root CA, and any client certificate the device presents.
  Pick a date shortly before the earliest expiry.
- **Devices that refuse to sync:** some clients reject time that jumps
  backwards. If so, power-cycle the device so it boots with no time and takes
  whatever it's given first.
- **Leaving it running:** the clock ticks forward, so a fake date stays good
  for (expiry - fake date). Many devices only need the time at boot, so you can
  sometimes move the device back to its normal WiFi afterwards. If it re-syncs
  with real time, it breaks again. For a long-term fix, run TIM on a Raspberry
  Pi with `--target` set to the device.
- **Firewall rules:** every rule TIM adds is tagged `-m comment --comment TIM`.
  `sudo iptables-save | grep TIM` should be empty after TIM exits.
- Only use TIM on devices and networks you own or have permission to test.

## Development

```bash
make test     # unit tests (macOS or Linux)
make linux    # static Linux binaries in dist/
go test ./testbed/device -v  # real TLS failure, then NTP/HTTP-time repair; no Docker needed
./dist/tim serve --time 2024-01-01        # local spoofers on 127.0.0.1:10123/10037/10013/10080
```

Layout: `cmd/tim` (CLI), `internal/clock` (fake clock), `internal/spoof`
(NTP, Time, Daytime, HTTP Date), `internal/ap` (hostapd + dnsmasq),
`internal/fw` (iptables), `internal/discover` (raw-socket capture + report),
`internal/certs` (chain inspection, device-root path search, House of Keys,
weak-key and notable-CA checks). No third-party dependencies.

To test against the real House of Keys dataset:

```bash
TIM_HOK=~/houseofkeys go test ./internal/certs -run Dataset -v
```

## Licence and third-party data

TIM source code is licensed under the [MIT licence](LICENSE).
The optional House of Keys dataset is maintained by
[SEC Consult](https://github.com/sec-consult/houseofkeys) and is downloaded only
when requested. It is not included in the source or release binaries. TIM's
licence does not relicense that dataset or its product metadata.

## Beta feedback

[Open an issue](https://github.com/Splinters-io/TIM/issues) with `tim version`,
your Kali/kernel version, WiFi adapter and driver, command used, expected versus
actual behavior, and relevant logs. Remove passwords and sensitive device or
network details before posting. Hardware test results are especially welcome.
