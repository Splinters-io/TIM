# Time-source expansion roadmap

Most items below are proposed extensions. v0.1.0-beta.2 implements the
standalone HTTPS Date endpoint with supplied credentials and TLS 1.0–1.3 tests;
legacy handshake-time tlsdate compatibility remains unimplemented. TIM should be
mission-agnostic: a shared scenario clock can drive network, device-local and
hardware-backed time sources. Support must describe the access required and
what was actually tested, rather than label an entire source “unspoofable”.

## Common architecture

Retain the existing fake-clock core and introduce source backends with explicit
capabilities: probe, configure, start, observe and restore. A backend reports
required hardware, privileges, client configuration, achievable precision and
validation status. Read-only discovery must not silently change a device clock.
Device-local backends must distinguish the TIM host from the target device.

Scenarios should support jumps, drift, startup time acquisition, loss/recovery
of a source, and conflicting sources. Record offered time separately from the
time the client actually accepted. Save and restore modified device settings
where the interface supports it; report cases where restoration is impossible.

## Proposed work order

1. **Discovery and compatibility profiles.** Identify likely time protocols,
   explicit client/firmware versions, fallback behavior and source precedence.
   A TLS connection or hostname alone does not prove tlsdate usage.
2. **GNSS receiver-data simulation.** Generate time-bearing NMEA sentences for
   files, pseudo-terminals and serial adapters; integrate a gpsd test harness.
   Add PPS through hardware that can meet measured timing requirements.
   PPS gives second boundaries, not a calendar date by itself. Receiver-protocol
   emulation is distinct from simulating the satellite RF input.
3. **Device-local and RTC adapters.** Start with explicit Linux RTC interfaces
   on a selected test device, then documented service/debug integrations.
   I2C/SPI emulation needs chip-specific register maps and suitable hardware;
   a battery-backed RTC is not necessarily writable without privileged or
   physical access. Secure clocks and rollback checks require separate study.
4. **Controlled TLS time testbed.** Support HTTPS Date with operator-provided
   certificates and explicit client trust. Investigate legacy tlsdate handshake
   time separately, using a compatible TLS stack and client fixture. Ordinary
   modern TLS endpoints must not be assumed to expose a usable timestamp.
   Record certificate/hostname checks, configured trust, pinning, protocol
   version and client bootstrap settings as experimental preconditions.
5. **Cellular test integrations.** Start with modem/OS time observations and
   supported test hooks. Add an adapter for an isolated cellular network or
   network emulator with test SIMs and controlled network time. NITZ is one
   possible source; behavior depends on modem, generation, OS and precedence.
6. **GNSS RF simulator integration.** Control an appropriate laboratory
   simulator through its documented API, with conducted coupling or RF shielding.
   Validate date/epoch behavior and source competition on the specific receiver.
   No assumption that every GNSS receiver accepts an arbitrary simulated time.

## TLS opportunities and their limits

Certificate-validity windows, first-boot time acquisition, configured fallback
and implementation defects are different hypotheses. Test them independently
with reproducible fixtures rather than advertise a generic TLS bypass.
A certificate being within its validity period does not provide its private
key, satisfy a different hostname, or defeat certificate pinning. A correctly
verified TLS session cannot have its time bytes changed in transit without
breaking its authentication. A controlled endpoint, a client-configured test
trust anchor, or a demonstrated implementation-specific weakness changes the
preconditions and must be recorded as such.

The HTTPS Date endpoint and trusted/untrusted certificate tests are implemented.
A tlsdate-specific compatibility probe remains a future deliverable.
Legacy handshake-time support is research until a matching client/server fixture
passes. Future implementation-weakness modules need a concrete affected version,
reproducer and regression test; this roadmap does not claim one exists.

## Hardware prerequisites

| Backend | Starting equipment | Key dependency |
|---|---|---|
| NMEA/receiver data | Pseudo-terminal first; then a voltage-compatible serial adapter | Accessible receiver-data interface |
| PPS | Timed microcontroller/FPGA or supported timing hardware | Verified pulse timing and a matching date source |
| RTC | Target OS/service access, or chip-specific bus adapter/emulator | Permissions, register map and electrical compatibility |
| Cellular | Test modem/SIM and isolated network emulator or lab network | Attachment, time signaling and client source selection |
| GNSS RF | Laboratory GNSS simulator and conducted/shielded fixture | Receiver signal and epoch compatibility |
| TLS time | Compatible software endpoint and test credentials | Client trust and actual time-extraction behavior |

Choose actual hardware only after identifying the target interfaces; these are
architecture options, not a shopping list or verified compatibility claims.

## Technical references

- [gpsfake receiver simulation](https://gpsd.io/gpsfake.html)
- [GPSD time service and PPS](https://www.gpsd.io/gpsd-time-service-howto.html)
- [Linux RTC interfaces](https://www.kernel.org/doc/html/latest/admin-guide/rtc.html)
- [Android time-source priority and NITZ](https://source.android.com/docs/core/connect/time-source)
- [tlsdate upstream README](https://github.com/ioerror/tlsdate/blob/master/README)
- [Legacy TLS Random structure, RFC 5246](https://www.rfc-editor.org/rfc/rfc5246#section-7.4.1.2)
