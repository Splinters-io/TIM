# TIM: Time In the Middle

Gets devices working again when they're stuck on an expired certificate.

A lot of devices (IoT gadgets, set-top boxes, printers, old tablets) stop
working when a TLS certificate they depend on expires, either on the server or
baked into the device. They check validity against their **own clock**. TIM
puts the device on a WiFi network that you control and tells it the date is
one when the certificate was still valid. Everything else goes through to the
real internet unchanged.

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
- **Notable CAs:** warns when a chain involves eMudhra/emSign (distrusted in
  Oct 2026), DST Root CA X3, AddTrust External CA Root, legacy
  Symantec/VeriSign, WoSign/StartCom, DigiNotar, CNNIC, TrustCor, Camerfirma,
  E-Tugra or Entrust, with what each means for an old device.
- **Weak keys:** ROCA (CVE-2017-15361) moduli, RSA under 2048 bits, and
  MD5/SHA-1 signatures. Certificates Go can't parse (common in firmware)
  still get the House of Keys check.

### eMudhra / emSign

Browsers started distrusting eMudhra in October 2026, and eMudhra is leaving
the TLS business. For an old device that trusts eMudhra:

1. **The server's eMudhra certificate expired:** a normal expiry, so TIM
   works.
2. **The vendor moved the server to another CA:** no fake date helps, and
   `--root` will say so. It needs a firmware or root-store update.
3. **The device checks revocation (OCSP/CRL):** a date in the past can make
   fresh OCSP responses look "not yet valid". Most embedded clients don't
   check or ignore failures; `tim discover` shows OCSP/CRL requests in its
   HTTP list.

A device that still trusts emSign ECC Root CA - G3 can also be fooled by
anyone who works out those keys. Treat that as a reason to update or replace
the device.

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
