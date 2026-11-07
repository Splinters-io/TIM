# TIM testbed

A fully synthetic, self-contained reproduction of the fault TIM fixes: a
server presenting an **expired TLS certificate**, and a simulated
**time-locked device** that rejects it on a correct clock but works once it
gets its time from TIM. Nothing here touches a real server, name or key.

## What's in it

| Service | Role |
|---|---|
| `certgen` | Generates a throwaway CA + a leaf cert valid **2023-01-01 → 2024-01-01** (so it's expired "now"), into a shared volume. Runs once. |
| `server` | nginx presenting that expired leaf on `https://server:8443` (and plain `http://server`), serving some stand-in "account data". |
| `tim` | `tim serve` offering NTP/Time/Daytime/HTTP-Date fixed at **2023-06-01**, inside the cert's window. |
| `device` | The time-locked device, using its **real** clock. |
| `device-fixed` | The same device, getting its clock from `tim` over NTP. |

The device verifies the server's real certificate against the real test CA;
only its clock changes. It does not skip validation — it's the same repair
TIM performs on real hardware (fix the clock, keep authenticating the real
server).

## Run it

```bash
cd testbed
docker compose build

# 1. Broken: real clock -> the cert is expired -> stuck
docker compose run --rm device

# 2. Fixed: time comes from TIM -> clock is 2023 -> the cert is valid -> connects
docker compose run --rm device-fixed

# 3. Diagnose the cert the way you would a real host
docker compose run --rm tim tim certs --hok off server:8443
docker compose run --rm tim tim certs --hok off --root /certs/ca.pem server:8443

docker compose down -v   # stop and delete the certs volume
```

Expected: step 1 prints `DEVICE STUCK: ... certificate has expired`; step 2
prints `DEVICE WORKING: ... accepted the real certificate` and the account
data; step 3 shows the expired window and suggests a `--time`.

## Variations

- **Different fault date:** edit `certgen`'s `-not-before`/`-not-after` in
  `docker-compose.yml`, then `docker compose up certgen --build`.
- **HTTP Date path instead of NTP:** run the device with
  `TIME_SOURCE=http://tim/ HTTP_HOST=server docker compose run --rm device-fixed`
  to pull the clock from the rewritten HTTP `Date:` header (TIM proxies to
  `server:80`; using `device-fixed` starts TIM as a dependency).
- **"Vendor switched CA" case:** generate a second, unrelated CA and pass only
  that to the device via `CA=`; `tim certs --root` will report that no date can
  fix it — the trust-store case from `PROJECT.md`.

> This reproduces the AP's time-spoofing effect by pointing the device
> straight at `tim serve`. It does not run the hostapd/dnsmasq/iptables AP
> path (that needs real WiFi hardware and `NET_ADMIN`); test that on the Kali
> box.

## Without Docker

From the repository root, `go test ./testbed/device -v` starts disposable local
TLS, NTP and HTTP servers on ephemeral ports. It checks an expired certificate
fails against real time, succeeds after each TIM time source, and still fails
with an unrelated trust store. No root access or external services are needed.
This exercises protocol behavior; it does not validate the Compose configuration
or the Linux AP/firewall path.
